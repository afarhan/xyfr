#!/usr/bin/env python3
"""gen_gfx.py — generate the non-ASCII glyph table for the 6x12 terminal font.

    ./tools/gen_gfx.py > gfx6x12.c

These are GENERATED rather than taken from a font for two reasons:
  * box/block characters must TILE -- a horizontal has to span all 6 columns and
    a vertical all 12 rows, or a frame comes out dashed and a filled block comes
    out striped. Generating guarantees it.
  * at 6x12 there is no room for a faithful reduction of an outline glyph; a
    hand-drawn 6x12 tick reads better than any downscale.

They occupy a private transmitted range starting at 0x80 (the DEC Special Graphics
trick), so the protocol still carries ONE BYTE per cell rather than UTF-8.

Art is written as 6-wide x 12-tall ASCII; '#' is ink. Row 0 is the top.
Keep the order in sync with box_cps[] in secserver/vterm_glue.c.
"""

import sys
# Args:  [W H [symbol]]   default = the original 6x12 -> font6x12_box.
#   ./gen_gfx.py            > gfx6x12.c
#   ./gen_gfx.py 8 16 font8x16_box > gfx8x16.c
W   = int(sys.argv[1]) if len(sys.argv) > 1 else 6
H   = int(sys.argv[2]) if len(sys.argv) > 2 else 12
SYM = sys.argv[3] if len(sys.argv) > 3 else "font6x12_box"
HROW, VCOL = H // 2 - 1, W // 2 - 1   # the joining row / column for box drawing


def art(*rows):
    """ASCII art -> 12 bytes, MSB = leftmost pixel."""
    out = []
    for r in range(H):
        line = rows[r] if r < len(rows) else ""
        b = 0
        for c in range(W):
            if c < len(line) and line[c] == '#':
                b |= 1 << (7 - c)
        out.append(b)
    return out


def line_glyph(parts):
    """Box-drawing pieces, built so adjacent cells always join."""
    g = [0] * H
    if "hl" in parts:
        for c in range(0, VCOL + 1): g[HROW] |= 1 << (7 - c)
    if "hr" in parts:
        for c in range(VCOL, W):     g[HROW] |= 1 << (7 - c)
    if "vu" in parts:
        for r in range(0, HROW + 1): g[r] |= 1 << (7 - VCOL)
    if "vd" in parts:
        for r in range(HROW, H):     g[r] |= 1 << (7 - VCOL)
    return g


def block(rows=range(H), cols=range(W), mask=None):
    """Solid / dithered block elements. mask(r,c) -> bool for shades."""
    g = [0] * H
    for r in rows:
        for c in cols:
            if mask and not mask(r, c):
                continue
            g[r] |= 1 << (7 - c)
    return g


GLYPHS = [
    # ---- box drawing (must tile) ------------------------------------------
    ("U+2500", "HLINE",  line_glyph(["hl", "hr"])),
    ("U+2502", "VLINE",  line_glyph(["vu", "vd"])),
    ("U+250C", "TLCORN", line_glyph(["hr", "vd"])),
    ("U+2510", "TRCORN", line_glyph(["hl", "vd"])),
    ("U+2514", "BLCORN", line_glyph(["hr", "vu"])),
    ("U+2518", "BRCORN", line_glyph(["hl", "vu"])),
    ("U+251C", "TEE_R",  line_glyph(["vu", "vd", "hr"])),
    ("U+2524", "TEE_L",  line_glyph(["vu", "vd", "hl"])),
    ("U+252C", "TEE_D",  line_glyph(["hl", "hr", "vd"])),
    ("U+2534", "TEE_U",  line_glyph(["hl", "hr", "vu"])),
    ("U+253C", "CROSS",  line_glyph(["hl", "hr", "vu", "vd"])),
    ("U+256D", "RND_TL", line_glyph(["hr", "vd"])),
    ("U+256E", "RND_TR", line_glyph(["hl", "vd"])),
    ("U+256F", "RND_BR", line_glyph(["hl", "vu"])),
    ("U+2570", "RND_BL", line_glyph(["hr", "vu"])),

    # ---- block elements (must tile) ---------------------------------------
    ("U+2588", "BLK_FULL",  block()),
    ("U+2580", "BLK_UPPER", block(rows=range(0, H // 2))),
    ("U+2584", "BLK_LOWER", block(rows=range(H // 2, H))),
    ("U+258C", "BLK_LEFT",  block(cols=range(0, W // 2))),
    ("U+2590", "BLK_RIGHT", block(cols=range(W // 2, W))),
    ("U+2591", "SHADE_LT",  block(mask=lambda r, c: (r + c) % 3 == 0)),
    ("U+2592", "SHADE_MED", block(mask=lambda r, c: (r + c) % 2 == 0)),
    ("U+2593", "SHADE_DK",  block(mask=lambda r, c: (r + c) % 3 != 0)),

    # ---- arrows ------------------------------------------------------------
    ("U+2190", "ARROW_L", art("", "", "", "",
                              "  #   ",
                              " #    ",
                              "######",
                              " #    ",
                              "  #   ")),
    ("U+2192", "ARROW_R", art("", "", "", "",
                              "   #  ",
                              "    # ",
                              "######",
                              "    # ",
                              "   #  ")),
    ("U+2191", "ARROW_U", art("", "  #   ",
                              " ###  ",
                              "# # # ",
                              "  #   ",
                              "  #   ",
                              "  #   ",
                              "  #   ",
                              "  #   ")),
    ("U+2193", "ARROW_D", art("", "  #   ",
                              "  #   ",
                              "  #   ",
                              "  #   ",
                              "  #   ",
                              "# # # ",
                              " ###  ",
                              "  #   ")),

    # ---- marks -------------------------------------------------------------
    ("U+2713", "TICK",   art("", "", "",
                             "     #",
                             "    # ",
                             "#  #  ",
                             " # #  ",
                             "  #   ")),
    ("U+2717", "CROSSM", art("", "", "",
                             "#    #",
                             " #  # ",
                             "  ##  ",
                             "  ##  ",
                             " #  # ",
                             "#    #")),
    ("U+2022", "BULLET", art("", "", "", "",
                             "  ##  ",
                             "  ##  ")),
    ("U+25CF", "DOT_F",  art("", "", "",
                             "  ##  ",
                             " #### ",
                             " #### ",
                             "  ##  ")),
    ("U+25CB", "DOT_O",  art("", "", "",
                             "  ##  ",
                             " #  # ",
                             " #  # ",
                             "  ##  ")),
    ("U+276F", "CHEVR",  art("", "",
                             " #    ",
                             "  #   ",
                             "   #  ",
                             "    # ",
                             "   #  ",
                             "  #   ",
                             " #    ")),
    ("U+00B7", "MIDDOT", art("", "", "", "", "",
                             "  ##  ",
                             "  ##  ")),
]


def main():
    print("// Generated by tools/gen_gfx.py -- do not edit by hand.")
    print("//")
    print("// Non-ASCII glyphs for the 6x12 terminal font, transmitted in a")
    print("// PRIVATE range starting at TG_BOX_BASE (0x80) so a cell stays ONE byte.")
    print("// Box and block characters are generated so they TILE: a horizontal spans")
    print("// all 6 columns, a vertical all 12 rows, a full block every pixel --")
    print("// otherwise frames come out dashed and fills come out striped.")
    print("//")
    print("// Order MUST match box_cps[] in secserver/vterm_glue.c.")
    print("")
    print("#include <stdint.h>")
    print("")
    print("const uint8_t %s[%d][%d] = {" % (SYM, len(GLYPHS), H))
    for cp, name, bits in GLYPHS:
        body = ", ".join("0x%02X" % b for b in bits)
        print("\t/* %-7s %-9s */ { %s }," % (cp, name, body))
    print("};")
    print("")


if __name__ == "__main__":
    main()
