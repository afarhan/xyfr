#!/usr/bin/env python3
"""lvfont2tfont.py — LVGL generated font (.c) -> the text engine's flat font table.

    ./tools/lvfont2tfont.py lv_font_montserrat_14.c mont14 > mont14.c
    ./tools/lvfont2tfont.py --bpp 1 lv_font_montserrat_14.c mont14 > mont14.c

WHY convert rather than rasterise a TTF: the LVGL .c files are already on disk
(the lvgl library ships every Montserrat size) and converting them reproduces the
glyphs currently on screen PIXEL FOR PIXEL. No download, no freetype, no visual
change when the engine replaces LVGL.

WHAT CHANGES. LVGL stores each glyph as a TIGHT box (box_w x box_h) plus offsets,
bit-packed at 1/2/4/8 bpp, with a 4-bit-fractional advance. The text engine wants
what text_engine.txt specifies: every glyph the SAME height, a rectangular block,
rows padded to a byte boundary so no row needs cross-row bit shifting. So each
glyph is expanded into a uniform line_height cell, positioned by ofs_y against
the baseline, and re-packed with byte-aligned rows.

BPP. Default 4 (keep LVGL's anti-aliasing — Montserrat is a fine-stroked
geometric sans and thresholding it to 1bpp breaks the thin strokes). --bpp 1
thresholds at 50% coverage for a smaller table. Rows stay byte-aligned either
way, so "byte-aligned bitmap" holds for both; only the depth differs.

Advance is rounded to whole pixels: the engine sums integer widths (spec: "we
calculate a string's rendered length by adding up the widths of each character").
"""

import re, sys

def die(m):
    sys.stderr.write("lvfont2tfont: %s\n" % m); sys.exit(1)

def strip_comments(s):
    """LVGL interleaves /* U+0020 " " */ markers through the bitmap array; those
    contain digits and would be parsed as data."""
    s = re.sub(r'/\*.*?\*/', ' ', s, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', s)

def parse_uint_array(src, name):
    """Pull `static const uint8_t NAME[] = { ... };` out as a list of ints."""
    m = re.search(r'\b' + name + r'\s*\[\s*\]\s*=\s*\{(.*?)\}\s*;', src, re.S)
    if not m: die("array %s not found" % name)
    return [int(t, 0) for t in re.findall(r'0x[0-9a-fA-F]+|\b\d+\b', strip_comments(m.group(1)))]

def parse_glyph_dsc(src):
    """Pull the glyph descriptor table: bitmap_index, adv_w, box_w, box_h, ofs_x, ofs_y."""
    m = re.search(r'glyph_dsc\s*\[\s*\]\s*=\s*\{(.*?)\n\}\s*;', src, re.S)
    if not m: die("glyph_dsc not found")
    out = []
    for rec in re.finditer(
            r'\{\s*\.bitmap_index\s*=\s*(-?\d+)\s*,\s*\.adv_w\s*=\s*(-?\d+)\s*,'
            r'\s*\.box_w\s*=\s*(-?\d+)\s*,\s*\.box_h\s*=\s*(-?\d+)\s*,'
            r'\s*\.ofs_x\s*=\s*(-?\d+)\s*,\s*\.ofs_y\s*=\s*(-?\d+)\s*\}', m.group(1)):
        out.append(tuple(int(g) for g in rec.groups()))
    if not out: die("glyph_dsc parsed empty")
    return out

def scalar(src, name, default=None):
    m = re.search(r'\.' + name + r'\s*=\s*(-?\d+)', src)
    if m: return int(m.group(1))
    if default is not None: return default
    die("scalar %s not found" % name)

def unpack_glyph(bitmap, index, w, h, bpp):
    """Decode one tight glyph box into a w*h list of 0..15 coverage values.

    LVGL packs rows CONTIGUOUSLY — a row does NOT restart on a byte boundary, so
    the bit cursor runs straight on from one row to the next. That is exactly the
    property we are removing."""
    px, bit = [], index * 8
    maxv = (1 << bpp) - 1
    for _ in range(h):
        row = []
        for _ in range(w):
            byte = bitmap[bit >> 3]
            shift = 8 - bpp - (bit & 7)
            v = (byte >> shift) & maxv
            row.append(v * 15 // maxv if bpp != 4 else v)   # normalise to 0..15
            bit += bpp
        px.append(row)
    return px

def main():
    args = sys.argv[1:]
    out_bpp = 4
    if '--bpp' in args:
        i = args.index('--bpp'); out_bpp = int(args[i+1]); del args[i:i+2]
    if out_bpp not in (1, 4): die("--bpp must be 1 or 4")
    if len(args) != 2: die("usage: lvfont2tfont.py [--bpp 1|4] <lv_font_x.c> <name>")
    path, name = args

    src = open(path).read()
    bitmap = parse_uint_array(src, 'glyph_bitmap')
    dsc    = parse_glyph_dsc(src)
    in_bpp = scalar(src, 'bpp', 4)
    line_h = scalar(src, 'line_height')
    base   = scalar(src, 'base_line')

    # The ASCII cmap: range_start=32, range_length=95, glyph_id_start=1 (verified
    # for montserrat). Anything outside becomes .notdef and is not emitted.
    FIRST, COUNT = 32, 95

    bytes_per_row = lambda w: (w * out_bpp + 7) // 8

    blob, offsets, widths = bytearray(), [], []
    for i in range(COUNT):
        gid = 1 + i
        if gid >= len(dsc): die("glyph id %d past the descriptor table" % gid)
        bidx, adv_w, bw, bh, ofx, ofy = dsc[gid]
        adv = (adv_w + 8) // 16                       # 1/16 px -> whole px, rounded
        cell_w = max(adv, bw + max(ofx, 0))           # never clip the ink
        offsets.append(len(blob))
        widths.append(cell_w)

        cov = unpack_glyph(bitmap, bidx, bw, bh, in_bpp) if bw and bh else []
        # Vertical placement: LVGL sits the box's BOTTOM at (baseline - ofs_y),
        # and baseline is base_line up from the cell bottom.
        top = line_h - base - bh - ofy

        for y in range(line_h):
            row = bytearray(bytes_per_row(cell_w))
            sy = y - top
            if 0 <= sy < bh:
                for x in range(cell_w):
                    sx = x - max(ofx, 0)
                    if not (0 <= sx < bw): continue
                    v = cov[sy][sx]
                    if out_bpp == 1:
                        if v >= 8: row[x >> 3] |= 0x80 >> (x & 7)
                    else:
                        if x & 1: row[x >> 1] |= v          # low nibble  = odd x
                        else:     row[x >> 1] |= v << 4     # high nibble = even x
            blob += row

    w = sys.stdout.write
    w("// Generated by tools/lvfont2tfont.py from %s\n" % path.split('/')[-1])
    w("// Uniform-height, byte-aligned-row glyph table for the text engine.\n")
    w("// height=%d bpp=%d  ASCII %d..%d\n\n" % (line_h, out_bpp, FIRST, FIRST + COUNT - 1))
    w('#include "tfont.h"\n\n')

    w("static const uint8_t %s_bitmap[] = {" % name)
    for i, b in enumerate(blob):
        if i % 16 == 0: w("\n    ")
        w("0x%02X," % b)
    w("\n};\n\n")

    w("static const uint16_t %s_offset[] = {" % name)
    for i, o in enumerate(offsets):
        if i % 12 == 0: w("\n    ")
        w("%d," % o)
    w("\n};\n\n")

    w("static const uint8_t %s_width[] = {" % name)
    for i, x in enumerate(widths):
        if i % 16 == 0: w("\n    ")
        w("%d," % x)
    w("\n};\n\n")

    w("const tfont_t %s = {\n" % name)
    w("    .height = %d,\n"    % line_h)
    w("    .bpp    = %d,\n"    % out_bpp)
    w("    .first  = %d,\n"    % FIRST)
    w("    .count  = %d,\n"    % COUNT)
    w("    .bitmap = %s_bitmap,\n" % name)
    w("    .offset = %s_offset,\n" % name)
    w("    .width  = %s_width,\n"  % name)
    w("};\n")

    sys.stderr.write("lvfont2tfont: %s  height=%d bpp=%d  %d glyphs  %d bytes\n"
                     % (name, line_h, out_bpp, COUNT, len(blob)))

main()
