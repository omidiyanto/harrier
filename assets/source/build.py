"""Regenerate every Harrier brand asset from the pixel grids in harrier.py.

    python3 assets/source/build.py        # needs Pillow; writes into assets/

Icons are scaled by whole pixels only: 16/32 px from the 16 px tile, 48 px
and up from the 20 px tile (2 px margin), so every size stays crisp.
"""
import os
import struct
import sys

from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harrier as H  # noqa: E402

OUT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PNG = os.path.join(OUT, "png")
os.makedirs(PNG, exist_ok=True)

i20, i16, logo = H.icon(20), H.icon(16), H.lockup()
m = H.rows(H.MARK)
mark = H.blank(len(m[0]) + 2, len(m) + 2)
H.place(mark, m, 1, 1)


def write(name, text):
    with open(os.path.join(OUT, name), "w") as f:
        f.write(text)


write("harrier-icon.svg", H.svg(i20, scale=16))
write("harrier-icon-16.svg", H.svg(i16, scale=16))
write("harrier-logo.svg", H.svg(logo, scale=8))
write("harrier-logo-transparent.svg", H.svg(logo, scale=8, tile=False))
write("harrier-mark.svg", H.svg(mark, scale=16, tile=False))


def icon_png(size):
    if size <= 32:
        return H.png(i16, size // 16)
    k = size // 20
    img = Image.new("RGBA", (size, size), H.png(i20, 1).getpixel((0, 0)))
    tile = H.png(i20, k)
    img.paste(tile, ((size - tile.width) // 2, (size - tile.height) // 2))
    return img


icons = {s: icon_png(s) for s in (16, 32, 48, 64, 128, 256, 512, 1024)}
for s, img in icons.items():
    img.save(os.path.join(PNG, f"harrier-icon-{s}.png"))
H.png(logo, 8).save(os.path.join(PNG, "harrier-logo.png"))
H.png(logo, 8, tile=False).save(os.path.join(PNG, "harrier-logo-transparent.png"))

# GitHub social preview, 1280 x 640.
scale = 10
canvas = H.blank(1280 // scale, 640 // scale)
H.place(canvas, ["".join(r) for r in logo], (128 - len(logo[0])) // 2, (64 - len(logo)) // 2)
H.png(canvas, scale).save(os.path.join(OUT, "harrier-social.png"))


def bmp_frame(img):
    """32-bit BMP icon image (BITMAPINFOHEADER, bottom-up BGRA, empty AND mask):
    the format every Windows version reads for sizes below 256."""
    w, h = img.size
    px = img.convert("RGBA").load()
    pixels = b"".join(
        bytes((px[x, y][2], px[x, y][1], px[x, y][0], px[x, y][3]))
        for y in reversed(range(h)) for x in range(w)
    )
    mask = bytes(((w + 31) // 32) * 4 * h)
    header = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, len(pixels) + len(mask), 0, 0, 0, 0)
    return header + pixels + mask


def png_frame(img):
    from io import BytesIO
    buf = BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


# Windows .ico (also embedded into harrier.exe by build.rs): BMP frames for
# 16-128 px, PNG for 256 px, as Windows itself does.
sizes = (16, 32, 48, 64, 128, 256)
frames = [png_frame(icons[s]) if s == 256 else bmp_frame(icons[s]) for s in sizes]
offset = 6 + 16 * len(sizes)
ico = struct.pack("<HHH", 0, 1, len(sizes))
for s, data in zip(sizes, frames):
    ico += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), offset)
    offset += len(data)
with open(os.path.join(OUT, "harrier.ico"), "wb") as f:
    f.write(ico + b"".join(frames))
print("assets written to", OUT)
