#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

EXPECTED = (
    "const _ = uint(maxControlPlaneMaxInFlight - defaultControlPlaneMaxInFlight)",
    "const _ = uint(defaultControlPlanePollTimeout - 1)",
    "const _ = uint(defaultControlPlaneInitialPollTimeout - 1)",
    "const _ = uint(maxControlPlanePollDeadline - defaultControlPlanePollTimeout - defaultControlPlanePollDeadlineGuardrail)",
    "const _ = uint(defaultControlPlanePollDeadlineGuardrail - 1)",
    "const _ = uint(maxControlPlanePollDeadlineGuardrail - defaultControlPlanePollDeadlineGuardrail - 1)",
)


def patch(checkout: Path) -> Path:
    target = checkout / "pkg" / "runtimeconfig" / "config.go"
    data = target.read_text(encoding="utf-8")
    for line in EXPECTED:
        count = data.count(line)
        if count != 1:
            raise SystemExit(f"expected exact source line once, found {count}: {line}")
    if data.count("const _ = uint(") != len(EXPECTED):
        raise SystemExit("unexpected additional machine-word uint compile assertion")
    patched = data
    for line in EXPECTED:
        patched = patched.replace(line, line.replace("uint(", "uint64(", 1))
    if patched == data:
        raise SystemExit("portability patch made no change")
    if patched.count("const _ = uint64(") < len(EXPECTED):
        raise SystemExit("not all portability assertions converted")
    target.write_text(patched, encoding="utf-8")
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("checkout")
    args = parser.parse_args()
    target = patch(Path(args.checkout).resolve())
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
