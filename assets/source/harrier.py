"""Harrier brand pixel art: single source of truth for every asset."""

# Harrier mascot (primary icon): chunky pixel bird in profile, facing right,
# yellow hooked beak, tail down-left, two little feet. 16 x 14 pixels.
MARK = """
.......######...
......########..
.....####kk###yy
.....####kk###.y
......########..
.....#########..
....##########..
...###########..
..############..
.############...
##..########....
#....######.....
......#..#......
.....##.##......
"""

FONT = {
    "H": ["##...##", "##...##", "##...##", "##...##", "#######", "##...##", "##...##", "##...##", "##...##"],
    "A": [".#####.", "##...##", "##...##", "##...##", "#######", "##...##", "##...##", "##...##", "##...##"],
    "R": ["######.", "##...##", "##...##", "##...##", "######.", "##.##..", "##..##.", "##...##", "##...##"],
    "I": ["##"] * 9,
    "E": ["#######", "##.....", "##.....", "##.....", "#####..", "##.....", "##.....", "##.....", "#######"],
    "_": ["....."] * 7 + ["#####"] * 2,  # terminal cursor
}

# Amber CRT palette.
COLORS = {
    "#": "#FF7A1A",  # orange
    "d": "#C85A0E",  # shade
    "k": "#1A0F08",  # eyes
    "y": "#FFD23F",  # beak
    "g": "#3A1C06",  # glow halo
}
BG = "#120D0A"
SCAN = "#18110D"


def rows(art):
    lines = art.strip("\n").split("\n")
    w = max(map(len, lines))
    return [l.ljust(w, ".") for l in lines]


def word(text, gap=3):
    out = [""] * 9
    for i, ch in enumerate(text):
        for r in range(9):
            out[r] += FONT[ch][r] + ("." * gap if i < len(text) - 1 else "")
    return out


def place(canvas, art, x0, y0):
    for y, line in enumerate(art):
        for x, ch in enumerate(line):
            if ch != ".":
                canvas[y0 + y][x0 + x] = ch


def blank(w, h):
    return [["."] * w for _ in range(h)]


def glow(canvas):
    """1-pixel dim halo around every lit pixel (CRT bloom, still pixel-exact)."""
    h, w = len(canvas), len(canvas[0])
    out = [r[:] for r in canvas]
    for y in range(h):
        for x in range(w):
            if canvas[y][x] == ".":
                near = any(
                    0 <= y + dy < h and 0 <= x + dx < w and canvas[y + dy][x + dx] not in ".g"
                    for dy in (-1, 0, 1) for dx in (-1, 0, 1)
                )
                if near:
                    out[y][x] = "g"
    return out


def icon(size=20):
    """App icon tile: 16 (the mascot edge to edge) or 20 (2 px margin)."""
    m = rows(MARK)
    c = blank(size, size)
    place(c, m, (size - len(m[0])) // 2, (size - len(m)) // 2)
    return glow(c)


def lockup(text="HARRIER_", pad=3):
    m = rows(MARK)
    w = word(text)
    width = pad + len(m[0]) + 6 + len(w[0]) + pad
    height = pad + len(m) + pad
    c = blank(width, height)
    place(c, m, pad, pad)
    place(c, w, pad + len(m[0]) + 6, pad + (len(m) - 9) // 2 + 1)
    return glow(c)


def svg(canvas, scale=1, tile=True, scanlines=True, rounded=False, colors=COLORS):
    """Crisp SVG: one rect per horizontal run of equal colour."""
    h, w = len(canvas), len(canvas[0])
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        f'width="{w * scale}" height="{h * scale}" shape-rendering="crispEdges">'
    ]
    if tile:
        r = ' rx="3"' if rounded else ""
        parts.append(f'<rect width="{w}" height="{h}" fill="{BG}"{r}/>')
        if scanlines:
            parts += [f'<rect y="{y}" width="{w}" height="1" fill="{SCAN}"/>' for y in range(1, h - 1, 2)]
    for y, line in enumerate(canvas):
        x = 0
        while x < w:
            ch = line[x]
            run = 1
            while x + run < w and line[x + run] == ch:
                run += 1
            if ch != "." and (tile or ch != "g"):
                parts.append(f'<rect x="{x}" y="{y}" width="{run}" height="1" fill="{colors[ch]}"/>')
            x += run
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def png(canvas, scale, tile=True, scanlines=True, colors=COLORS):
    from PIL import Image

    h, w = len(canvas), len(canvas[0])
    hexrgb = lambda s: tuple(int(s[i:i + 2], 16) for i in (1, 3, 5))
    img = Image.new("RGBA", (w, h), hexrgb(BG) + (255,) if tile else (0, 0, 0, 0))
    px = img.load()
    for y in range(h):
        if tile and scanlines and y % 2 and 0 < y < h - 1:
            for x in range(w):
                px[x, y] = hexrgb(SCAN) + (255,)
        for x in range(w):
            ch = canvas[y][x]
            if ch != "." and (tile or ch != "g"):
                px[x, y] = hexrgb(colors[ch]) + (255,)
    return img.resize((w * scale, h * scale), Image.NEAREST)
