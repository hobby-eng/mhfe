// Writes where the shadow stack of a bound WebAssembly ends into its custom section "mhfe-stack",
// so that the worker can zero the dead stack between calls (AUD-024-SEC003; web/worker-runtime.js
// reads it). The Rust linker lays the stack out first: global 0, the stack pointer, starts at the
// stack's top, and the data begins right there. The script reads that start from global 0's
// initializer and refuses a module laid out otherwise: one that imports globals, whose global 0
// is not a mutable i32 set by a constant, or whose lowest data segment does not start at it.
//
//   node scripts/mark-wasm-stack.mjs <file.wasm>   marks the file, as scripts/bind-wasm.sh does
//   node scripts/mark-wasm-stack.mjs --self-test   the reader against modules it must decide

import { readFileSync, writeFileSync } from "node:fs";
import { runGate } from "./gate-command-line.mjs";

/** The custom section that holds the stack's top as decimal text; web/worker-runtime.js reads it. */
const STACK_SECTION = "mhfe-stack";
const USAGE = "usage: node scripts/mark-wasm-stack.mjs <file.wasm> | --self-test";

/** Section ids of the WebAssembly specification, section 5.5. */
const IMPORT_SECTION = 2;
const GLOBAL_SECTION = 6;
const DATA_SECTION = 11;
const I32 = 0x7f;
const I32_CONST = 0x41;
const END = 0x0b;
const GLOBAL_IMPORT = 3;

/** A reader of `bytes` from `at`, with the encodings a section uses. */
function reader(bytes, at = 0) {
  const self = {
    at,
    byte: () => {
      if (self.at >= bytes.length) throw new Error("the module ends inside a section");
      return bytes[self.at++];
    },
    unsigned() {
      let value = 0;
      for (let shift = 0; ; shift += 7) {
        const byte = self.byte();
        value += (byte & 0x7f) * 2 ** shift;
        if ((byte & 0x80) === 0) return value;
      }
    },
    signed() {
      let value = 0;
      let shift = 0;
      let byte;
      do {
        byte = self.byte();
        value += (byte & 0x7f) * 2 ** shift;
        shift += 7;
      } while ((byte & 0x80) !== 0);
      return (byte & 0x40) === 0 ? value : value - 2 ** shift;
    },
    name: () => {
      const length = self.unsigned();
      self.at += length;
      return bytes.subarray(self.at - length, self.at).toString("utf8");
    },
    /** Skips a vector of bytes: its length, then that many bytes. */
    skip: () => {
      const length = self.unsigned();
      self.at += length;
    },
    /** A constant expression that must be `i32.const n; end`: n. */
    constant: () => {
      if (self.byte() !== I32_CONST) throw new Error("an initializer is not an i32 constant");
      const value = self.signed();
      if (self.byte() !== END) throw new Error("an initializer holds more than one constant");
      return value;
    },
  };
  return self;
}

/** The sections of a module: id and body, after the 8-byte header. */
function sections(bytes) {
  const found = [];
  const read = reader(bytes, 8);
  while (read.at < bytes.length) {
    const id = read.byte();
    const size = read.unsigned();
    found.push({ id, body: bytes.subarray(read.at, read.at + size) });
    read.at += size;
  }
  return found;
}

/** Whether an import section imports a global, whose index would come before global 0's. */
function importsAGlobal(body) {
  const read = reader(body);
  for (let count = read.unsigned(); count > 0; count -= 1) {
    read.name();
    read.name();
    const kind = read.byte();
    if (kind === GLOBAL_IMPORT) return true;
    if (kind === 0) read.unsigned();
    else if (kind === 1) {
      read.byte();
      limits(read);
    } else if (kind === 2) limits(read);
    else throw new Error(`an import of unknown kind ${kind}`);
  }
  return false;
}

/** Skips memory or table limits. */
function limits(read) {
  const flags = read.byte();
  read.unsigned();
  if ((flags & 1) !== 0) read.unsigned();
}

/** The initial value of global 0, which must be a mutable i32. */
function firstGlobal(body) {
  const read = reader(body);
  if (read.unsigned() === 0) throw new Error("the module has no global");
  const [type, mutable] = [read.byte(), read.byte()];
  if (type !== I32 || mutable !== 1) throw new Error("global 0 is not a mutable i32");
  return read.constant();
}

/** The lowest offset of an active data segment of memory 0, or null without one. */
function lowestData(body) {
  const read = reader(body);
  let lowest = null;
  for (let count = read.unsigned(); count > 0; count -= 1) {
    const flags = read.unsigned();
    if (flags === 1) {
      read.skip();
      continue;
    }
    if (flags === 2 && read.unsigned() !== 0) throw new Error("data for another memory");
    if (flags > 2) throw new Error(`a data segment of unknown kind ${flags}`);
    const offset = read.constant();
    read.skip();
    lowest = lowest === null ? offset : Math.min(lowest, offset);
  }
  return lowest;
}

/** The top of the module's shadow stack, where its data begins. */
export function stackTop(bytes) {
  const all = sections(bytes);
  const body = (id) => all.find((section) => section.id === id)?.body;
  const imports = body(IMPORT_SECTION);
  if (imports !== undefined && importsAGlobal(imports)) {
    throw new Error("the module imports a global, so global 0 is not its stack pointer");
  }
  const globals = body(GLOBAL_SECTION);
  const data = body(DATA_SECTION);
  if (globals === undefined || data === undefined) throw new Error("no globals or no data");
  const top = firstGlobal(globals);
  if (top <= 0 || lowestData(data) !== top) {
    throw new Error(`the stack does not end where the data begins (global 0 starts at ${top})`);
  }
  return top;
}

/** A custom section (section 5.5.3): id 0, its size, its name, then `content`. */
function customSection(name, content) {
  const named = Buffer.concat([unsignedBytes(Buffer.byteLength(name)), Buffer.from(name)]);
  const body = Buffer.concat([named, Buffer.from(content)]);
  return Buffer.concat([Buffer.from([0]), unsignedBytes(body.length), body]);
}

/** An unsigned LEB128 number. */
function unsignedBytes(value) {
  const bytes = [];
  let rest = value;
  do {
    const low = rest % 128;
    rest = Math.floor(rest / 128);
    bytes.push(rest === 0 ? low : low | 0x80);
  } while (rest !== 0);
  return Buffer.from(bytes);
}

/** A module of the given sections, after the header. */
function moduleOf(...parts) {
  const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  return Buffer.concat([
    header,
    ...parts.map(([id, body]) =>
      Buffer.concat([Buffer.from([id]), unsignedBytes(body.length), body]),
    ),
  ]);
}

/** The reader against modules it must decide right, and a refused command line. */
function selfTest() {
  const top = [0x80, 0x80, 0xc0, 0x00]; // 1,048,576 as a signed LEB128 number
  const global = (mutable, value) => Buffer.from([1, I32, mutable, I32_CONST, ...value, END]);
  const data = (value) => Buffer.from([1, 0, I32_CONST, ...value, END, 1, 7]);
  // A passive segment, then two active ones above the top and at it.
  const segments = Buffer.from([3, 1, 2, 7, 7, 0, I32_CONST, 0x80, 0x88, 0xc0, 0x00, END, 1, 7]);
  const three = Buffer.concat([segments, Buffer.from([0, I32_CONST, ...top, END, 2, 7, 7])]);
  const controls = [
    [moduleOf([GLOBAL_SECTION, global(1, top)], [DATA_SECTION, data(top)]), 1_048_576],
    [moduleOf([GLOBAL_SECTION, global(1, top)], [DATA_SECTION, three]), 1_048_576],
    [moduleOf([GLOBAL_SECTION, global(0, top)], [DATA_SECTION, data(top)]), null],
    [moduleOf([GLOBAL_SECTION, global(1, top)], [DATA_SECTION, data([0x80, 0x08])]), null],
    [
      moduleOf(
        [IMPORT_SECTION, Buffer.from([1, 1, 0x65, 1, 0x67, GLOBAL_IMPORT, I32, 1])],
        [GLOBAL_SECTION, global(1, top)],
        [DATA_SECTION, data(top)],
      ),
      null,
    ],
  ];
  for (const [index, [bytes, expected]] of controls.entries()) {
    let found;
    try {
      found = stackTop(bytes);
    } catch {
      found = null;
    }
    if (found !== expected) throw new Error(`self-test: control ${index + 1} gives ${found}`);
  }
  console.log(`The stack reader decides all ${controls.length} of its controls right.`);
}

/** Marks `file` with its stack's top; a file marked already is refused. */
function mark(file) {
  const bytes = readFileSync(file);
  if (WebAssembly.Module.customSections(new WebAssembly.Module(bytes), STACK_SECTION).length > 0) {
    throw new Error(`${file} is marked already; bind it again.`);
  }
  const top = stackTop(bytes);
  writeFileSync(file, Buffer.concat([bytes, customSection(STACK_SECTION, String(top))]));
  console.log(`${file}: the stack ends at ${top}.`);
}

runGate(USAGE, {
  selfTest,
  operand: (file) => {
    mark(file);
    return true;
  },
});
