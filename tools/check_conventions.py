#!/usr/bin/env python3
"""check_conventions.py — enforce the house rules that a machine can check.

Usage:
    tools/check_conventions.py FILE [FILE...]     check the named files
    tools/check_conventions.py --hook             read a Claude Code hook event
                                                  on stdin and check the file it
                                                  names
    tools/check_conventions.py --all              check every source file in the
                                                  tree

Prints one line per violation as  path:line: RULE: what is wrong.
Exits 2 when anything was found, 0 when clean, 1 on a usage error. Exit 2 is
what makes a PostToolUse hook feed the report back to the model.

WHAT THIS CANNOT CHECK, and still needs a person: whether a comment is TRUE,
whether a name says what the thing does, whether a comment buries the code, and
whether history was left behind in prose. Those four are the rules most often
broken; this script only removes the excuse for the mechanical seven.
"""

import json
import os
import re
import sys

# Verified, security-critical, or copied verbatim from an upstream repo that a
# build check diffs against — editing any of these is a separate mistake, so do
# not add noise about them.
EXEMPT = {
    "wg.c", "wg.h", "crypto.c",
    "ili9488.cpp", "ili9488.h", "text_engine.cpp", "text_engine.h",
    "text_edit.cpp", "text_edit.h", "tfont.h",
    "mont14.c", "mont10.c", "tamzen_tfont.c",
    # generated glyph tables: machine output, not written by hand
    "font6x12.c", "font8x16.c", "gfx6x12.c", "gfx8x16.c", "bip39_wordlist.c",
    "check_conventions.py",
}

SOURCE_SUFFIXES = (".c", ".h", ".cpp", ".ino")

# `tag` means the AEAD authentication tag throughout the storage and transport
# code, which is correct usage. Only flag it away from that context.
TAG_OK = re.compile(
    r"AEAD|auth|Poly1305|AUTHTAG|_TAG\b|tag_bytes|TAG_BYTES|authentication",
    re.I,
)

# A string on one of these lines goes to the serial log, never to the panel, so
# the display font's missing glyphs do not apply to it.
LOG_CALL = re.compile(r"hal_debug\s*\(|Debug\s*\.|Serial\s*\.|\bprintf\s*\(|\bfprintf\s*\(")


def strip_comments_and_strings(text):
    """Blank out comments and string/char literals, keeping line structure.

    Every removed character becomes a space and every newline is kept, so a
    line number in the result still matches the source.
    """
    out = []
    i = 0
    n = len(text)
    state = "code"
    while i < n:
        c = text[i]
        nxt = ""
        if i + 1 < n:
            nxt = text[i + 1]

        if state == "code":
            if c == "/" and nxt == "/":
                state = "line_comment"
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block_comment"
                out.append("  ")
                i += 2
                continue
            if c == '"':
                state = "string"
                out.append(" ")
                i += 1
                continue
            if c == "'":
                state = "char"
                out.append(" ")
                i += 1
                continue
            out.append(c)
            i += 1
            continue

        if state == "line_comment":
            if c == "\n":
                state = "code"
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue

        if state == "block_comment":
            if c == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 2
                continue
            if c == "\n":
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue

        # inside a string or char literal
        if c == "\\":
            out.append("  ")
            i += 2
            continue
        if (state == "string" and c == '"') or (state == "char" and c == "'"):
            state = "code"
            out.append(" ")
            i += 1
            continue
        if c == "\n":
            out.append("\n")   # an unterminated literal must not eat the file
            state = "code"
        else:
            out.append(" ")
        i += 1

    return "".join(out)


def string_literals(text):
    """Yield (line_number, literal_text) for every double-quoted literal."""
    line = 1
    i = 0
    n = len(text)
    state = "code"
    start_line = 0
    buf = []
    while i < n:
        c = text[i]
        nxt = ""
        if i + 1 < n:
            nxt = text[i + 1]
        if c == "\n":
            line += 1

        if state == "code":
            if c == "/" and nxt == "/":
                state = "line_comment"
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if c == '"':
                state = "string"
                start_line = line
                buf = []
                i += 1
                continue
            i += 1
            continue

        if state == "line_comment":
            if c == "\n":
                state = "code"
            i += 1
            continue

        if state == "block_comment":
            if c == "*" and nxt == "/":
                state = "code"
                i += 2
                continue
            i += 1
            continue

        # in a string
        if c == "\\":
            buf.append(text[i:i + 2])
            i += 2
            continue
        if c == '"':
            state = "code"
            yield start_line, "".join(buf)
            i += 1
            continue
        buf.append(c)
        i += 1


def check_file(path):
    """Return a list of 'path:line: RULE: message' strings."""
    try:
        raw = open(path, "r", encoding="utf-8", errors="surrogateescape").read()
    except OSError as exc:
        return ["%s: could not read: %s" % (path, exc)]

    found = []
    code = strip_comments_and_strings(raw)
    code_lines = code.split("\n")
    raw_lines = raw.split("\n")

    def note(lineno, rule, message):
        found.append("%s:%d: %s: %s" % (path, lineno, rule, message))

    # ---- rule: no ?: ternary -------------------------------------------
    # With comments and literals blanked, a '?' left in C source is a ternary.
    for i, line in enumerate(code_lines, 1):
        if "?" in line:
            note(i, "ternary",
                 "`?:` is banned — write an if, body on the next line, indented")

    # ---- rule: an if body never shares the if's line --------------------
    # The condition's parentheses have to be matched by counting, not by a
    # regex: `if (!f(a, b))` ends in two closes, and a greedy `.*\)` stops at
    # the first of them and reports the second as a body.
    if_head = re.compile(r"^\s*(?:\}\s*)?(?:else\s+)?if\s*\(")
    for i, line in enumerate(code_lines, 1):
        m = if_head.match(line)
        if not m:
            continue
        depth = 0
        end = -1
        for pos in range(m.end() - 1, len(line)):
            if line[pos] == "(":
                depth += 1
            elif line[pos] == ")":
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        if end < 0:
            continue                      # condition continues on the next line
        tail = line[end + 1:].strip()
        if tail == "" or tail.startswith("{"):
            continue
        note(i, "if-body",
             "the body must go on the next line, indented, not on the if line")

    # ---- rule: one statement per line ------------------------------------
    # A `for` header carries two semicolons of its own, and a `do { … } while(0)
    # ` macro cannot be split across lines without continuations, so neither is
    # the thing this rule is about.
    in_macro = False
    for i, line in enumerate(code_lines, 1):
        stripped = line.strip()
        was_macro = in_macro
        if stripped.startswith("#"):
            in_macro = True
        if in_macro and not line.rstrip().endswith("\\"):
            in_macro = False               # the macro's last line
        if was_macro or stripped.startswith("#"):
            continue                       # a macro body, however many lines
        if stripped.startswith("for") or stripped.startswith("}"):
            continue
        if line.count(";") > 1:
            note(i, "one-statement",
                 "two statements on one line — put them on separate lines")

    # ---- rule: a struct is never crammed onto one line --------------------
    # The rule is about a struct BURIED ON A SINGLE LINE, not about anonymity.
    # An anonymous struct that declares one object at its point of use —
    #     static struct { uint8_t a; uint32_t b; } thing[N];
    # spread over several lines — is the shape the tree wants, so it passes.
    # What fails is every field squeezed onto the same line as the brace, which
    # is how a struct stops being readable as a list of fields.
    # The characters excluded before the brace are what separate a DEFINITION
    # from two things that merely mention a struct: `=` means an initializer
    # (`struct msg_meta m = { … };`) and `()` means a function signature whose
    # parameter or return type is one (`void f(enum phone_state s){ … }`).
    definition = re.compile(r"\b(?:struct|enum)\b[^;{=()]*\{")
    for i, line in enumerate(code_lines, 1):
        m = definition.search(line)
        if not m:
            continue
        if "}" not in line[m.end() - 1:]:
            continue                       # body continues on later lines: fine
        note(i, "one-line-struct",
             "struct/enum crammed onto one line — one field per line")

    # ---- rule: banned words -----------------------------------------------
    for i, line in enumerate(raw_lines, 1):
        for word in ("wire", "codec"):
            if re.search(r"\b%s\b" % word, line, re.I):
                note(i, "banned-word",
                     "`%s` already means something else here — say "
                     "transmission format / voice compression" % word)
        if re.search(r"\btag\b", line, re.I) and not TAG_OK.search(line):
            note(i, "banned-word",
                 "`tag` means the AEAD authentication tag in this tree — "
                 "say label, field, or marker")

    # ---- rule: a code reference carries its filename ----------------------
    for i, line in enumerate(raw_lines, 1):
        if re.search(r"(?:^|\s)lines?\s+\d+", line, re.I):
            if not re.search(r"\w+\.(?:c|h|cpp|ino|md):\d+", line):
                note(i, "bare-line-ref",
                     "cite file.c:465, never a bare line number")

    # ---- rule: user-visible strings are plain ASCII -----------------------
    # The display font has no em-dash, curly quote or ellipsis glyph; each
    # renders as a missing-glyph box. This is about what reaches the PANEL, so
    # comments are free to use them and so is anything going to the serial log.
    for lineno, literal in string_literals(raw):
        if lineno <= len(raw_lines) and LOG_CALL.search(raw_lines[lineno - 1]):
            continue
        bad = sorted({ch for ch in literal if ord(ch) > 0x7F})
        if bad:
            note(lineno, "non-ascii",
                 "string literal contains %s — the panel font has no glyph"
                 % " ".join("U+%04X %s" % (ord(c), c) for c in bad))

    return found


def collect_all(root):
    paths = []
    skip_dirs = {".git", "build", "node_modules", "fsroot", "packaging"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            if name.endswith(SOURCE_SUFFIXES):
                paths.append(os.path.join(dirpath, name))
    return sorted(paths)


def main(argv):
    args = argv[1:]
    paths = []

    if args and args[0] == "--hook":
        try:
            event = json.load(sys.stdin)
        except (ValueError, OSError):
            return 0                      # not our business to fail the tool
        path = event.get("tool_input", {}).get("file_path")
        if not path:
            return 0
        paths = [path]
    elif args and args[0] == "--all":
        root = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
        paths = collect_all(root)
    elif args:
        paths = args
    else:
        sys.stderr.write(__doc__)
        return 1

    violations = []
    for path in paths:
        if not path.endswith(SOURCE_SUFFIXES):
            continue
        if os.path.basename(path) in EXEMPT:
            continue
        if not os.path.isfile(path):
            continue
        violations.extend(check_file(path))

    if not violations:
        return 0

    sys.stderr.write("house conventions — %d violation(s):\n" % len(violations))
    for line in violations:
        sys.stderr.write("  %s\n" % line)
    sys.stderr.write(
        "\nRules a script cannot check, and that still need a pass by hand:\n"
        "  is the comment TRUE of the code, does the name say what it does,\n"
        "  does the comment bury the code, is there history left in prose.\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
