#!/usr/bin/env python3
"""Run the historical integrity implementation against current audit inputs."""

import importlib.util
import json
import sys
from pathlib import Path


class CurrentIntegrity:
    def run(self):
        root = Path(__file__).resolve().parents[3]
        retained = root / "docs/audits/AUD-018-harnesses/supply-chain.py"
        spec = importlib.util.spec_from_file_location("retained_integrity", retained)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        review = module.SupplyChainReview()
        review._evidence = root / "docs/audits/AUD-019-evidence"
        result = review.run()
        record = review._evidence / "supply-chain.json"
        data = json.loads(record.read_text())
        # Preserve the implementation's original label and explicitly record the new invocation.
        data["currentAuditId"] = "AUD-019"
        data["harnessOrigin"] = "AUD-018-harnesses/supply-chain.py (unmodified)"
        record.write_text(json.dumps(data, indent=2) + "\n")
        return result


if __name__ == "__main__":
    sys.exit(CurrentIntegrity().run())
