#!/usr/bin/env python3
"""Palette-quantises the screenshots, because they live in git forever.

A UI screenshot is flat colour and antialiased text — a few hundred distinct
values in an image the encoder is storing as 24-bit truecolour. Quantising to a
256-colour palette is visually indistinguishable here (checked side by side at
2x) and takes the set from ~2.4 MB to ~900 KB. That matters because these are
regenerated on purpose: every refresh adds its full weight to history.

Skipped with a note if Pillow is missing. A smaller PNG is worth having and not
worth making anyone install something for.

    python3 shrink.py <dir>
"""

import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("shrink: no Pillow, leaving the shots at full size", file=sys.stderr)
    sys.exit(0)

directory = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/ui/shots")
before = after = 0

for path in sorted(directory.glob("*.png")):
    before += path.stat().st_size
    image = Image.open(path).convert("RGB")
    image.quantize(colors=256, method=Image.Quantize.MEDIANCUT).save(
        path, optimize=True
    )
    after += path.stat().st_size

if before:
    print(f"shrink: {before // 1024} KiB -> {after // 1024} KiB")
