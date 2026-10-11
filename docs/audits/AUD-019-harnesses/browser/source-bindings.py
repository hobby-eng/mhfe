#!/usr/bin/env python3
"""Apply the retained byte-comparison helper to AUD-019 without replacing old evidence."""
import importlib.util
from pathlib import Path

root = Path(__file__).resolve().parents[4]
source = root / "docs/audits/AUD-018-harnesses/browser/loader-source-bindings.py"
spec = importlib.util.spec_from_file_location("retained_loader_binding_helper", source)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
helper.OUTPUT = root / "docs/audits/AUD-019-evidence/browser-loader-source-bindings.json"
raise SystemExit(helper.main())
