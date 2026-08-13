#!/usr/bin/env python3
"""A shipped template must not name a placeholder in a comment.

Substitution is literal, so a token mentioned in prose is replaced too: the
Mihomo batch template documented its own placeholders and every run pasted the
listeners block into the middle of that sentence, producing invalid YAML. Mihomo
started without proxies and all 53 links were reported dead.

Same failure mode as a CSS comment closing early -- prose that the machine reads.
"""
import re
import sys
from pathlib import Path

COMMENT = re.compile(r"^\s*(#|//)")
TOKEN = re.compile(r"__[A-Z][A-Z0-9_]*__")

def main(paths):
    bad = []
    for path in paths:
        for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
            if COMMENT.match(line):
                for token in TOKEN.findall(line):
                    bad.append((path, n, token, line.strip()))
    for path, n, token, line in bad:
        print(f"{path}:{n}: {token} named in a comment -- it will be substituted here too")
        print(f"    {line}")
    if bad:
        print(f"\n{len(bad)} placeholder mention(s) in comments; describe them without the token")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
