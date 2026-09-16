import unittest

from expand_redline_rows import clean_column_specs, expand


class RedlineRowsTests(unittest.TestCase):
    def test_column_specs_cleaned_but_cells_keep_markup(self):
        source = (r"\begin{SimpleTable}{Title}{2}"
                  r"{\DIFadd{|L}{\DIFadd{0.35}\SimpleUsableWidth}\DIFadd{|}}"
                  r"{Header} \DIFadd{Cell}")
        self.assertEqual(clean_column_specs(source),
                         r"\begin{SimpleTable}{Title}{2}{|L{0.35\SimpleUsableWidth}|}"
                         r"{Header} \DIFadd{Cell}")

    def test_packet_cells_preserve_nested_commands(self):
        source = r"\PacketRow{2}{Length}{A \textbf{nested} cell.}{0xFFFF}"
        self.assertEqual(
            expand(source),
            r"2 & Length & A \textbf{nested} cell. & 0xFFFF \\\hline",
        )

    def test_value_cells_preserve_escaped_braces(self):
        self.assertEqual(
            expand(r"Before \ValueDescriptionRow{1}{Literal \{value\}} after"),
            r"Before 1 & Literal \{value\} \\\hline after",
        )

    def test_unrelated_text_unchanged(self):
        self.assertEqual(expand(r"\section{Title}"), r"\section{Title}")
