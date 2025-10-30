# OSDP Document Template (Normie-Friendly)

This folder contains a simple structure for building the OSDP document without touching LaTeX styling.

- `main.tex` – minimal driver, do not edit.
- `tex/` – styling files (fonts, colors, table layouts). Leave these alone unless you know LaTeX.
- `sections/` – plain text `.tex` files for each chapter/section. Edit these to change the prose.
- `tables/` – Simple `.tex` snippets with one `\PacketRow{...}` per line. Open them in any text editor, change the text between braces, and save.
- `Makefile` – run `make pdf` to build `osdp-document.pdf`.

## Editing Workflow

1. Edit the prose in `sections/01-introduction.tex`, etc. Use simple LaTeX: paragraphs, `\section`, `\subsection`, lists.
2. For tables, edit the matching `.tex` file (e.g., `tables/packet-format.tex`). Each line is a `\PacketRow{size}{name}{meaning}{value}`—just change the words.
3. Run `make pdf` (or `latexmk -xelatex main.tex`) to regenerate the PDF.

If LaTeX complains, check the CSV for stray commas or unmatched braces in text fields.
