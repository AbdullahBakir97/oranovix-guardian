"""
Icon generator for Oranovix Guardian.

Source: ``assets/icon.png`` (1536x1024, the logo tile centred on a white
background). It is never changed. From it this script writes:

- ``assets/icon_square.png``: the tile with the white background removed,
  cropped and padded to a transparent square. Used by the UI and for the
  large icon sizes.
- ``assets/icon_shield.png``: the shield part only, with rounded corners.
  Used for the small icon sizes, where the text would be noise.
- ``assets/icon.ico``: 16, 20, 24, 32, 48, 64, 128 and 256 px, each a
  square 32-bit PNG entry.

Run from the project root: ``python assets/icon_generator.py``
"""
from __future__ import annotations

import io
import struct
from collections import deque
from pathlib import Path
from typing import Any, Dict, List

from PIL import Image, ImageDraw, ImageFilter

ASSETS_DIR = Path(__file__).parent
SOURCE = ASSETS_DIR / "icon.png"
SQUARE = ASSETS_DIR / "icon_square.png"
SHIELD = ASSETS_DIR / "icon_shield.png"
ICO = ASSETS_DIR / "icon.ico"

LARGE_SIZES = (256, 128, 64)
SMALL_SIZES = (48, 32, 24, 20, 16)
ICO_SIZES = (16, 20, 24, 32, 48, 64, 128, 256)

WHITE_THRESHOLD = 225
ALPHA_THRESHOLD = 8                        # the source has alpha 1..3 noise around the tile
SHIELD_BOX = (0.20, 0.02, 0.80, 0.66)     # fractions of the square side
CORNER_RADIUS = 0.18                       # fraction of the side


def _pad_to_square(img: Image.Image) -> Image.Image:
    side = max(img.size)
    square = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    square.paste(img, ((side - img.width) // 2, (side - img.height) // 2))
    return square


def remove_outside_background(img: Image.Image) -> Image.Image:
    """Make the near-white or (nearly) transparent area connected to the border transparent.

    White highlights inside the logo are kept: only background reachable
    from the image border counts as outside.
    """
    img = img.convert("RGBA")
    width, height = img.size
    pixels: Any = img.load()

    def is_background(x: int, y: int) -> bool:
        r, g, b, a = pixels[x, y]
        return a < ALPHA_THRESHOLD or (r > WHITE_THRESHOLD and g > WHITE_THRESHOLD and b > WHITE_THRESHOLD)

    outside = bytearray(width * height)
    queue: deque = deque()
    for x in range(width):
        queue.append((x, 0))
        queue.append((x, height - 1))
    for y in range(height):
        queue.append((0, y))
        queue.append((width - 1, y))
    while queue:
        x, y = queue.popleft()
        index = y * width + x
        if outside[index] or not is_background(x, y):
            continue
        outside[index] = 1
        if x > 0:
            queue.append((x - 1, y))
        if x < width - 1:
            queue.append((x + 1, y))
        if y > 0:
            queue.append((x, y - 1))
        if y < height - 1:
            queue.append((x, y + 1))

    result = img.copy()
    out: Any = result.load()
    for y in range(height):
        row = y * width
        for x in range(width):
            if outside[row + x]:
                out[x, y] = (0, 0, 0, 0)
    return result


def make_square(source: Image.Image) -> Image.Image:
    """The logo tile alone, centred on a transparent square."""
    cleared = remove_outside_background(source)
    bbox = cleared.getchannel("A").getbbox()
    if bbox is None:
        raise ValueError("the source image is all background")
    return _pad_to_square(cleared.crop(bbox))


def make_shield(square: Image.Image) -> Image.Image:
    """The shield region of the square, padded to square, with rounded corners."""
    side = square.width
    left, top, right, bottom = (round(f * side) for f in SHIELD_BOX)
    shield = _pad_to_square(square.crop((left, top, right, bottom)))
    mask = Image.new("L", shield.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, shield.width - 1, shield.height - 1),
        radius=round(CORNER_RADIUS * shield.width), fill=255,
    )
    alpha = Image.composite(shield.getchannel("A"), mask, mask)
    shield.putalpha(alpha)
    return shield


def render_sizes(square: Image.Image, shield: Image.Image) -> Dict[int, Image.Image]:
    images: Dict[int, Image.Image] = {}
    for size in LARGE_SIZES:
        images[size] = square.resize((size, size), Image.Resampling.LANCZOS)
    for size in SMALL_SIZES:
        small = shield.resize((size, size), Image.Resampling.LANCZOS)
        images[size] = small.filter(ImageFilter.UnsharpMask(radius=1, percent=80, threshold=2))
    return images


def write_ico(images: Dict[int, Image.Image], path: Path) -> None:
    """Write a .ico of PNG entries by hand (Pillow re-scales one source image)."""
    sizes: List[int] = list(ICO_SIZES)
    blobs: List[bytes] = []
    for size in sizes:
        img = images[size]
        assert img.size == (size, size)
        buf = io.BytesIO()
        img.convert("RGBA").save(buf, format="PNG")
        blobs.append(buf.getvalue())

    out = io.BytesIO()
    out.write(struct.pack("<HHH", 0, 1, len(sizes)))
    offset = 6 + 16 * len(sizes)
    for size, blob in zip(sizes, blobs):
        dim = 0 if size == 256 else size          # 0 means 256 in the ICO directory
        out.write(struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset))
        offset += len(blob)
    for blob in blobs:
        out.write(blob)
    path.write_bytes(out.getvalue())


def build_icons() -> None:
    source = Image.open(SOURCE)
    square = make_square(source)
    shield = make_shield(square)
    square.save(SQUARE, optimize=True)
    shield.save(SHIELD, optimize=True)
    write_ico(render_sizes(square, shield), ICO)
    print(f"{SQUARE.name}: {square.width}x{square.height}")
    print(f"{SHIELD.name}: {shield.width}x{shield.height}")
    print(f"{ICO.name}: {', '.join(str(s) for s in ICO_SIZES)} px ({ICO.stat().st_size:,} bytes)")


if __name__ == "__main__":
    build_icons()
