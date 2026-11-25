"""Sigma regexes and case-folded host names rewritten for Elasticsearch match what Sigma matches.

    python3 -m unittest discover -s tests/elastic -p 'test_*.py'

A Lucene regex must match the whole value, so each rewrite is checked with Python's fullmatch against the original
regex's search. The rewrites use only syntax that means the same in both.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from elastic_values import folded_regex, lucene_regex  # noqa: E402
from sigma.types import SigmaString  # noqa: E402

CASES = [
    (r"^/(api/)?nx-[0-9a-f]{16}$", ["/nx-0123456789abcdef", "/api/nx-0123456789abcdef"],
     ["/x/nx-0123456789abcdef", "/nx-0123456789abcdef/", "/nx-0123"]),
    (r"/(artex[-_](i\d|probe)|ptx-i\d|hermes-h\d)", ["/v2/artex-i3/manifests/x", "/v2/x/ptx-i9", "/hermes-h1"],
     ["/v2/artex-ix", "/v2/ptx-i", "artex-i3"]),
    (r"(^|[/\\\s])hermes(\.exe)?(\s|$)|hermes_cli|run_agent\.py|/\.hermes/",
     ["hermes", "/usr/bin/hermes --yolo", "C:\\x\\hermes.exe run", "python run_agent.py", "cat ~/.hermes/x"],
     ["xhermes", "hermesx", "/usr/bin/hermes.exe2", "run_agentxpy"]),
    (r"((pip|pipx)\s+install|uvx)\s(.*\s)?[\"']?strix-agent", ["pip install strix-agent", "uvx --from x 'strix-agent"],
     ["pip installstrix-agent", "pip show strix-agent"]),
    (r"a.*?b+?c", ["xxaxxbbcxx"], ["acb"]),
]


class LuceneRegex(unittest.TestCase):
    def test_same_matches(self):
        for regex, hits, misses in CASES:
            lucene = lucene_regex(regex)
            for value in hits + misses:
                with self.subTest(regex=regex, value=value):
                    self.assertEqual(bool(re.search(regex, value)), bool(re.fullmatch(lucene, value)), lucene)
            for value in hits:
                self.assertTrue(re.search(regex, value), f"case {value!r} should match {regex!r}")
            for value in misses:
                self.assertFalse(re.search(regex, value), f"case {value!r} should not match {regex!r}")

    def test_ignorecase(self):
        lucene = lucene_regex(r"^ab[c-e]\d$", ignorecase=True)
        for value in ("abc1", "ABD2", "aBe3"):
            self.assertTrue(re.fullmatch(lucene, value), lucene)
        self.assertFalse(re.fullmatch(lucene, "abf1"))

    def test_lucene_operators_escaped(self):
        self.assertEqual(lucene_regex(r'^a"b#c@d&e<f>g~h$'), r'a\"b\#c\@d\&e\<f\>g\~h')

    def test_unsupported(self):
        for regex in (r"\bword", r"a(?=b)", r"a^b", r"(?i)abc"):
            with self.subTest(regex=regex), self.assertRaises(ValueError):
                lucene_regex(regex)


class FoldedHostNames(unittest.TestCase):
    def test_folded(self):
        lucene = folded_regex(SigmaString("*.Artex.lol"))
        for value in ("a.artex.lol", "X.ARTEX.LOL"):
            self.assertTrue(re.fullmatch(lucene, value), lucene)
        for value in ("artex.lol", "a.artexalol", "a.artex.lol.example"):
            self.assertFalse(re.fullmatch(lucene, value), lucene)


if __name__ == "__main__":
    unittest.main()
