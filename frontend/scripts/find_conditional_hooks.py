"""Find React hooks called after an early return inside a component.

A hook after a conditional return changes the hook count between renders and crashes the
component with "Rendered more hooks than during the previous render" — but only once the
data takes the other branch, which is why this class of bug survives demo data and appears
the first time a real tenant is loaded.

Usage: python scripts/find_conditional_hooks.py <dir> [<dir> ...]
"""
from __future__ import annotations

import pathlib
import re
import sys

COMPONENT = re.compile(r"^(export\s+)?function\s+[A-Z]\w*\s*\(")
HOOK = re.compile(r"^  (const|let|var)?\s*.*\b(useMemo|useState|useEffect|useRef|useCallback"
                  r"|useQuery|useMutation|usePersistedState)\s*\(")
# Only a return at the COMPONENT's own indentation (two spaces) ends the hook-safe region.
# A `return` nested inside a useEffect callback is at four or more and is irrelevant.
EARLY_RETURN = re.compile(r"^  (if\s*\(.*\)\s*return\b|return\s+<|return\s*\()")

problems: list[str] = []

for root in (sys.argv[1:] or ["."]):
    for path in pathlib.Path(root).rglob("*.tsx"):
        lines = path.read_text(encoding="utf-8").splitlines()
        first_return = -1
        for i, line in enumerate(lines):
            # ANY top-level (unindented, non-blank) line starts a new declaration, which
            # ends the previous component's body. Without this the detector carries a
            # `return (` from one component into the next and reports the whole file.
            if line and not line[0].isspace():
                first_return = -1
                continue
            if first_return < 0 and EARLY_RETURN.match(line):
                first_return = i
                continue
            if first_return >= 0 and HOOK.search(line):
                problems.append(
                    f"{path}:{i + 1}: hook after early return on line {first_return + 1}\n"
                    f"    {lines[first_return].strip()[:90]}\n"
                    f"    {line.strip()[:90]}"
                )

if problems:
    print(f"{len(problems)} conditional hook(s):\n")
    print("\n\n".join(problems))
    sys.exit(1)
print("no conditional hooks found")
