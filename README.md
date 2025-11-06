# OSDP Document Template (Normie-Friendly)

This folder contains a simple structure for building the OSDP document without touching LaTeX styling.

- `main.tex` – minimal driver, do not edit.
- `tex/` – styling files (fonts, colors, table layouts). Leave these alone unless you know LaTeX.
- `sections/` – plain text `.tex` files for each chapter/section. Edit these to change the prose.
- `tables/` – Simple `.tex` snippets with one `\PacketRow{...}` per line. Open them in any text editor and edit the text between braces (use `\\` to force a line break within a cell).
- `Makefile` – run `make pdf` to build `osdp-document.pdf`.

## Editing Workflow

1. Edit the prose in `sections/01-introduction.tex`, etc. Use simple LaTeX: paragraphs, `\section`, `\subsection`, lists.
2. For tables, edit the matching `.tex` file (e.g., `tables/packet-format.tex`). Each row uses `\PacketRow{size}{name}{meaning}{value}`. Use `\\` for a forced line break inside a cell and `\textsuperscript{n}` for note markers.
3. Run `make pdf` (or `latexmk -xelatex -outdir=build main.tex`) to regenerate the PDF.
If LaTeX complains, check for unmatched braces or missing `%` line endings in the table rows.
