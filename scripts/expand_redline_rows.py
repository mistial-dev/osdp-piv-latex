"""Expose table cells to latexdiff so changed wire fields are not hidden."""

import re
import sys
from pathlib import Path


def braced(text, pos):
    while text[pos].isspace():
        pos += 1
    if text[pos] != "{":
        raise ValueError("Expected braced argument")
    start, depth = pos + 1, 1
    pos += 1
    while depth:
        if text[pos] == "\\":
            pos += 2
            continue
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
        pos += 1
    return start, pos


def clean_column_specs(text):
    """Keep diff markup in table cells, where LaTeX permits it."""
    edits = []
    for match in re.finditer(r"\\begin\{SimpleTable\}", text):
        pos = match.end()
        for _ in range(3):
            start, pos = braced(text, pos)
        spec = text[start:pos - 1]
        while (marker := re.search(r"\\DIF(add|del)\{", spec)):
            body, end = braced(spec, marker.end() - 1)
            replacement = spec[body:end - 1] if marker[1] == "add" else ""
            spec = spec[:marker.start()] + replacement + spec[end:]
        spec = re.sub(r"\\DIF(?:add|del)(?:begin|end)\s*", "", spec)
        edits.append((start, pos - 1, spec))
    for start, end, spec in reversed(edits):
        text = text[:start] + spec + text[end:]
    return text


def expand(text):
    pattern = re.compile(r"\\(PacketRow|ValueDescriptionRow)\b")
    output = []
    cursor = 0
    for match in pattern.finditer(text):
        if match.start() < cursor:
            continue
        output.append(text[cursor:match.start()])
        pos = match.end()
        cells = []
        for _ in range(4 if match[1] == "PacketRow" else 2):
            while text[pos].isspace():
                pos += 1
            if text[pos] != "{":
                raise ValueError("Expected braced table cell")
            start = pos + 1
            depth = 1
            pos += 1
            while depth:
                if text[pos] == "\\":
                    pos += 2
                    continue
                if text[pos] == "{":
                    depth += 1
                elif text[pos] == "}":
                    depth -= 1
                pos += 1
            cells.append(text[start:pos - 1])
        output.append(" & ".join(cells) + r" \\\hline")
        cursor = pos
    output.append(text[cursor:])
    return "".join(output)


if __name__ == "__main__":
    clean = sys.argv[1:2] == ["--clean-column-specs"]
    for name in sys.argv[2:] if clean else sys.argv[1:]:
        path = Path(name)
        path.write_text((clean_column_specs if clean else expand)(path.read_text()))
