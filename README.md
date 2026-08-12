# OSDP PIV LaTeX Workspace

This folder builds the OSDP PIV proposal PDF. Most edits should be made in `sections/` for prose and `tables/` for reusable table snippets.

- `main.tex` - document driver.
- `sections/` - chapter and section prose.
- `tables/` - command tables and small reference tables.
- `tex/` - shared template, table, color, and font helpers.
- `scripts/` - vector and demo utilities.
- `Makefile` - run `make` to rebuild `osdp-piv-proposal.pdf`.

## Editing Workflow

1. Edit prose in `sections/*.tex` or table snippets in `tables/*.tex`.
2. Use the supported table helpers below; do not hand-code table layout.
3. Use `\code{...}` for long command names, OIDs, customization strings, and other literals that may need to break across lines.
4. Run `make`.
5. Check the generated `osdp-piv-proposal.pdf`.

## Review Redline

Generate a track-changes-style PDF against an explicit Git revision:

```sh
make redline BASE=<git-ref>
```

The command compares the chosen committed baseline with the current working
tree, including uncommitted and untracked LaTeX inputs. It expands all
`\input` and `\include` files before applying `latexdiff`, then writes
`build/redline/osdp-piv-proposal-redline.pdf`. The first page identifies the
baseline commit and current working-tree commit.

The redline requires the TeX Live `latexdiff` and `latexpand` packages. If
they are missing, install them with:

```sh
tlmgr install latexdiff latexpand
```

## Tables

All tables should use the helpers in `tex/tables.sty`. They are full-width and breakable. The table title is part of the table header, so it stays with the top of the table. If a table continues onto another page, the helper emits a continued header automatically.

Do not use `center`, `samepage`, `captionof{table}`, raw `tabularx`, manual `\Needspace`, or manual page breaks for tables.

### Packet Tables

Use `PacketTable` for OSDP command and reply layouts with `Size (bytes)`, `Name`, `Meaning`, and `Value` columns.

```tex
\begin{PacketTable}{Example Command (osdp_EXAMPLE)}
  \PacketRow{1}{CMND}{Command identifier.}{0xA0}
  \PacketRow{2}{Length}{Payload length, least-significant byte first.}{0x0000-0xFFFF}
  \PacketRow{0-n}{Data}{Payload bytes.}{0x00-0xFF}
\end{PacketTable}
```

### Value/Description Tables

Use `ValueDescriptionTable` for result codes, flags, modes, masks, type lists, and other two-column references. The third argument names the first column.

```tex
\begin{ValueDescriptionTable}{Example Result Codes}{Value}
  \label{tab:example-results}
  \ValueDescriptionRow{0x00}{Success.}
  \ValueDescriptionRow{0x01}{Timeout.}
  \ValueDescriptionRow{0x02-0x7F}{Reserved for future use.}
\end{ValueDescriptionTable}
```

For mask tables, change the first-column header:

```tex
\begin{ValueDescriptionTable}{Example Flags}{Mask}
  \ValueDescriptionRow{0x01}{Enable the feature.}
  \ValueDescriptionRow{0x02-0x80}{Reserved and transmitted as zero.}
\end{ValueDescriptionTable}
```

### Custom Tables

Use `SimpleTable` only when a table does not fit the packet or value/description shapes. The arguments are title, column count, column specification, and header row. Use `\SimpleUsableWidth` to keep custom columns full width.

```tex
\begin{SimpleTable}{Example Custom Table}{3}
  {|L{0.20\SimpleUsableWidth}|L{0.30\SimpleUsableWidth}|L{0.50\SimpleUsableWidth}|}
  {\TableHeaderCell{Tag} & \TableHeaderCell{Name} & \TableHeaderCell{Meaning}}
  \code{0x80} & Profile & Record profile identifier. \\\hline
  \code{0x81} & Data & Variable-length record data. \\\hline
\end{SimpleTable}
```

Use `\TableHeaderCell{...}` for every custom header cell. Do not use `\textcolor`, `\bfseries`, or local header styling directly in a table.

## Long Literals

Use `\code{...}` instead of `\texttt{...}` for long literals that can otherwise run into the margins.

```tex
The customization string is \code{OSDP-PIV-AUTO-CHALLENGE-v1}.

The certificate includes EKU OID \code{2.16.840.1.101.3.6.7}.
```

Short literals such as `\code{0x00}` may continue to use `\texttt`.

## Build Outputs

The only PDF intended to be kept in the repository is `osdp-piv-proposal.pdf`. The `build/` directory contains generated intermediate output, including `build/main.pdf`, and is ignored.

## Troubleshooting

- If LaTeX reports unmatched braces, check table rows for unbalanced `{...}` arguments.
- If a table title separates from the table body, the table is probably using unsupported raw LaTeX instead of the helpers above.
- If a table needs unusual columns, use `SimpleTable` rather than adding `center`, `samepage`, or manual page breaks.
