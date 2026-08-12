#!/usr/bin/env python3
"""Flag a CSS comment that closes on prose instead of on its terminator.

The pages inject their styles as <style> blocks inside Lua long strings, so a
comment written as `(do not use an editor-*/ wildcard here)` closes at that
`*/`; everything from there to the next `*/` is then parsed as prose and the
rules in between are silently dropped. That is how `.small-btn` stopped
applying -- nothing errors, the styling just goes missing.

Only <style> ... </style> regions are examined: elsewhere in a Lua file `*/` is
ordinarily part of a character class such as `[%d%*/,%-]`.

Legitimate terminators here are preceded by whitespace or another star, so a
`*/` glued to a word is the signal.

  usage: lint-css-comments.py <directory>
"""
import re
import sys
import pathlib

STYLE = re.compile(r"<style\b.*?</style>", re.S | re.I)
MARKER = re.compile(r"/\*|\*/")


def main(root):
    problems = []
    for path in sorted(pathlib.Path(root).rglob("*.lua")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for block in STYLE.finditer(text):
            depth = 0
            for m in MARKER.finditer(block.group(0)):
                if m.group(0) == "/*":
                    depth += 1
                    continue
                if depth == 0:
                    continue
                depth -= 1
                at = block.start() + m.start()
                before = text[at - 1] if at else " "
                if before not in " \t\n*":
                    line = text.count("\n", 0, at) + 1
                    problems.append(
                        "%s:%d: CSS comment closes on '%s*/' -- every rule up to "
                        "the next close is parsed as prose and dropped"
                        % (path, line, before))
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
