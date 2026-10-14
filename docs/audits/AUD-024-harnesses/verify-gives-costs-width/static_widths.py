"""AUD-024 verifier (verify-gives-costs-width): the rendered width of every style::gives and
style::costs line at b6fca69, and the absence of wrap() in gives, costs and fact_before_work.
Constants are substituted with their values from src/wallet_check.rs and src/packing.rs.
Exit 1 when a rendered line is wider than style::TEXT_WIDTH (78)."""
import re, sys
root = sys.argv[1]
style = open(f"{root}/src/bin/mhfe/style.rs").read().splitlines()
def body(name):
    start = next(i for i, l in enumerate(style) if re.match(rf"pub fn {name}\(", l))
    end = next(i for i in range(start, len(style)) if style[i] == "}")
    return start + 1, end + 1, "\n".join(style[start:end + 1])
for name in ("gives", "costs", "fact_before_work", "ok", "fact_as"):
    s, e, text = body(name)
    print(f"style.rs:{s}-{e} {name}: calls wrap/fact_lines/ok_lines: "
          f"{bool(re.search(r'wrap\(|fact_lines\(|ok_lines\(', text))}")
values = {"odds": "65,536", "WALLET_CHECK_BITS": "16", "NEW_ENTROPY_BITS": "256",
          "BITS_LEFT_WITH_CHECK": "240"}
widest = 0
for path in ("src/bin/mhfe/length_choice.rs", "src/bin/mhfe/new_wallet.rs"):
    src = open(f"{root}/{path}").read()
    for m in re.finditer(r"style::(gives|costs)\((&format!\()?\s*\"((?:[^\"\\]|\\.)*)\"", src, re.S):
        line_no = src[:m.start()].count("\n") + 1
        text = re.sub(r"\\\n\s*", "", m.group(3))
        text = re.sub(r"\{(\w+)\}", lambda k: values.get(k.group(1), "{" + k.group(1) + "}"), text)
        # caught(choice) for the widest case: 24 words "255 times in 256", same length "15 times in 16" (12 words) up to "255 times in 256"
        text = text.replace("{}", "255 times in 256" if "caught" in text else "21")
        mark = "✓" if m.group(1) == "gives" else "!"
        rendered = f"  {mark} {text}"
        width = len(rendered)
        widest = max(widest, width)
        print(f"{width:3} {path}:{line_no} {rendered}")
print(f"widest gives/costs line: {widest} columns (TEXT_WIDTH 78)")
sys.exit(1 if widest > 78 else 0)
