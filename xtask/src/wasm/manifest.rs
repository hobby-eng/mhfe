//! `cargo xtask wasm package-manifest DIR`: writes DIR/modules.json and DIR/README.md for the
//! browser package that scripts/build-wasm.sh built: the package version, its build (`cargo xtask
//! wasm stamp-build-id`), and for the runtime and each module its files with their SHA-256, so
//! that a page that takes some modules can check exactly the files it takes. The README is
//! docs/BROWSER-PACKAGE.md with the SHA-256 of the files after it.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};

use super::stamp::WASM_FILE;
use super::{BUILD_SECTION, custom_sections, read, sha256_hex, text, write};
use crate::{Failure, at};

/// The modules of the package, in the order of modules.json and of the README's list.
pub(super) const MODULES: [&str; 4] = ["core", "repair", "passwords", "wallet"];

/// modules.json, with its keys in this order, which JSON keeps.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    version: String,
    build_id: String,
    runtime: Folder,
    modules: Modules,
}

/// The runtime: its files.
#[derive(Serialize)]
struct Folder {
    files: Files,
}

/// A module: its files, and the folder it needs besides.
#[derive(Serialize)]
struct Module {
    files: Files,
    requires: [&'static str; 1],
}

/// The files of a folder by name, in byte order, with their SHA-256.
type Files = BTreeMap<String, String>;

/// The modules in the order of MODULES, which a map would sort.
struct Modules(Vec<(&'static str, Module)>);

impl Serialize for Modules {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, module) in &self.0 {
            map.serialize_entry(name, module)?;
        }
        map.end()
    }
}

/// Writes the manifest and the README of the package in `folder`.
pub(super) fn run(root: &Path, folder: &Path) -> Result<(), Failure> {
    let (json, readme) = render(root, folder)?;
    write(&folder.join("modules.json"), json)?;
    write(&folder.join("README.md"), readme)
}

/// The build stamped into the WebAssembly of the package in `folder`.
pub(super) fn build_of(folder: &Path) -> Result<String, Failure> {
    let wasm_path = folder.join(WASM_FILE);
    let wasm = read(&wasm_path)?;
    let sections = custom_sections(&wasm, BUILD_SECTION, &wasm_path)?;
    let build = sections
        .first()
        .ok_or_else(|| Failure(format!("{WASM_FILE} is not stamped with its build.")))?;
    Ok(String::from_utf8_lossy(build).into_owned())
}

/// The text of `modules.json` and of `README.md` for the package in `folder`.
pub(super) fn render(root: &Path, folder: &Path) -> Result<(String, String), Failure> {
    let cargo = text(&root.join("Cargo.toml"))?;
    let version = cargo
        .lines()
        .find_map(|line| {
            let (version, _) = line.strip_prefix("version = \"")?.split_once('"')?;
            (!version.is_empty()).then_some(version)
        })
        .ok_or_else(|| Failure("Cargo.toml names no version.".to_owned()))?;
    let build_id = build_of(folder)?;
    let runtime = files_of(&folder.join("runtime"))?;
    let mut modules = Vec::with_capacity(MODULES.len());
    for name in MODULES {
        let files = files_of(&folder.join(name))?;
        modules.push((
            name,
            Module {
                files,
                requires: ["runtime"],
            },
        ));
    }
    let folders = [("runtime", &runtime)].into_iter();
    let sums: Vec<String> = folders
        .chain(modules.iter().map(|(name, module)| (*name, &module.files)))
        .flat_map(|(folder, files)| {
            files
                .iter()
                .map(move |(name, hash)| format!("{hash}  {folder}/{name}"))
        })
        .collect();
    let readme = format!(
        "{}\n## SHA-256 of this build\n\nVersion {version}, build {build_id}.\n\n\
         ```text\n{}\n```\n",
        text(&root.join("docs/BROWSER-PACKAGE.md"))?,
        sums.join("\n")
    );
    let manifest = Manifest {
        version: version.to_owned(),
        build_id,
        runtime: Folder { files: runtime },
        modules: Modules(modules),
    };
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|error| Failure(format!("modules.json: {error}")))?;
    Ok((json + "\n", readme))
}

/// The files of `folder`, by name, with their SHA-256.
pub(super) fn files_of(folder: &Path) -> Result<Files, Failure> {
    let failed = |error: std::io::Error| at(folder, error);
    let mut files = Files::new();
    for entry in std::fs::read_dir(folder).map_err(failed)? {
        let entry = entry.map_err(failed)?;
        let Ok(name) = entry.file_name().into_string() else {
            return Err(at(folder, "a file name is not UTF-8"));
        };
        files.insert(name, sha256_hex(&read(&entry.path())?));
    }
    Ok(files)
}
