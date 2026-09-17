"""HTML parsing that tolerates malformed marked declarations in hostile email."""

from html.parser import HTMLParser


class EmailHTMLParser(HTMLParser):
    def parse_marked_section(self, i: int, report: bool = True) -> int:
        try:
            return super().parse_marked_section(i, report)
        except AssertionError:
            # Browsers ignore bogus declarations. Continue with subsequent tags
            # so a broken declaration cannot hide links or password fields.
            end = self.rawdata.find(">", i + 3)
            return end + 1 if end >= 0 else -1
