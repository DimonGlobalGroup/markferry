import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent
TOOL = HERE / "markferry.py"

CANARY_URL = "https://canary-secret.example/hidden-path?token=canarytoken"
CANARY_TITLE = "Canary Secret Title"
CANARY_FOLDER = "Canary Folder Name"


def doc(body):
    return ("<!DOCTYPE NETSCAPE-Bookmark-file-1>\n"
            "<TITLE>Bookmarks</TITLE>\n<H1>Bookmarks</H1>\n<DL><p>\n"
            + body + "\n</DL><p>\n")


def bm(url, title="Example", add_date="1700000000", extra=""):
    return f'<DT><A HREF="{url}" ADD_DATE="{add_date}"{extra}>{title}</A>'


def run(*args):
    return subprocess.run([sys.executable, str(TOOL), *args],
                          capture_output=True, text=True)


class MarkFerryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, content, binary=False):
        p = self.dir / name
        if binary or isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
        return str(p)

    def check(self, content, name="b.html", *extra):
        return run("check", self.write(name, content), *extra)

    def test_clean_file_exit0(self):
        r = self.check(doc(bm("https://example.org/page", "Example Page")))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("markferry: 1 bookmarks, 1 folders, 0 errors, 0 warnings", r.stdout)

    def test_missing_href(self):
        r = self.check(doc('<DT><A ADD_DATE="1">No Link</A>'))
        self.assertEqual(r.returncode, 1)
        self.assertIn("missing-href", r.stdout)

    def test_empty_href(self):
        r = self.check(doc('<DT><A HREF="">Empty</A>'))
        self.assertEqual(r.returncode, 1)
        self.assertIn("missing-href", r.stdout)

    def test_dangerous_schemes(self):
        for scheme in ("javascript:alert(1)", "data:text/html,hi", "vbscript:x"):
            r = self.check(doc(bm(scheme, "X")))
            self.assertEqual(r.returncode, 1, scheme)
            self.assertIn("dangerous-scheme", r.stdout)

    def test_credential_in_url(self):
        r = self.check(doc(bm("https://user:passw0rd@example.org/x", "X")))
        self.assertEqual(r.returncode, 1)
        self.assertIn("credential-in-url", r.stdout)
        self.assertNotIn("passw0rd", r.stdout)

    def test_malformed_url(self):
        r = self.check(doc(bm("https:///nohost", "X")))
        self.assertEqual(r.returncode, 1)
        self.assertIn("malformed-url", r.stdout)

    def test_insecure_and_private(self):
        r = self.check(doc(bm("http://192.168.1.10/admin", "Router")))
        self.assertEqual(r.returncode, 0)
        self.assertIn("insecure-http", r.stdout)
        self.assertIn("private-host", r.stdout)
        self.assertNotIn("192.168.1.10", r.stdout)

    def test_localhost_private(self):
        r = self.check(doc(bm("https://localhost:8080/x", "Local")))
        self.assertIn("private-host", r.stdout)
        self.assertNotIn("localhost", r.stdout.split("schemes:")[0].replace("private-host", ""))

    def test_missing_title_and_bad_date(self):
        r = self.check(doc(bm("https://example.org/", "", add_date="soon")))
        self.assertIn("missing-title", r.stdout)
        self.assertIn("bad-add-date", r.stdout)
        self.assertEqual(r.returncode, 0)

    def test_long_url(self):
        r = self.check(doc(bm("https://example.org/" + "a" * 2100, "Long")))
        self.assertIn("long-url", r.stdout)

    def test_exact_duplicate_across_files(self):
        a = self.write("a.html", doc(bm("https://example.org/Page#one", "One")))
        b = self.write("b.html", doc(bm("https://EXAMPLE.org/Page#two", "Two")))
        r = run("check", a, b)
        self.assertEqual(r.returncode, 1)
        self.assertIn("exact-duplicate", r.stdout)

    def test_exact_duplicate_default_port(self):
        body = bm("https://example.org:443/x", "A") + bm("https://example.org/x", "B")
        r = self.check(doc(body))
        self.assertIn("exact-duplicate", r.stdout)

    def test_near_duplicate_tracking_params(self):
        body = (bm("http://www.example.org/page/?utm_source=news&id=7", "A")
                + bm("https://example.org/page?id=7", "B"))
        r = self.check(doc(body))
        self.assertIn("near-duplicate", r.stdout)
        self.assertNotIn("exact-duplicate", r.stdout)

    def test_near_not_raised_for_exact_group(self):
        body = bm("https://example.org/x", "A") + bm("https://example.org/x", "B")
        r = self.check(doc(body))
        self.assertIn("exact-duplicate", r.stdout)
        self.assertNotIn("near-duplicate", r.stdout)

    def test_distinct_urls_clean(self):
        body = bm("https://example.org/a", "A") + bm("https://example.org/b", "B")
        r = self.check(doc(body))
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_empty_folder(self):
        body = ('<DT><H3>Empty One</H3>\n<DL><p>\n</DL><p>\n'
                + bm("https://example.org/", "X"))
        r = self.check(doc(body))
        self.assertIn("empty-folder", r.stdout)
        self.assertNotIn("Empty One", r.stdout)

    def test_nonempty_folder_quiet(self):
        body = ('<DT><H3>Stuff</H3>\n<DL><p>\n'
                + bm("https://example.org/", "X") + "\n</DL><p>")
        r = self.check(doc(body))
        self.assertNotIn("empty-folder", r.stdout)

    def test_no_bookmarks_error(self):
        r = self.check(doc(""))
        self.assertEqual(r.returncode, 1)
        self.assertIn("no-bookmarks", r.stdout)

    def test_structure_unclosed(self):
        r = self.check("<DL><p>\n" + bm("https://example.org/", "X"))
        self.assertIn("structure", r.stdout)

    def test_privacy_canary_text_and_json(self):
        body = (f'<DT><H3>{CANARY_FOLDER}</H3>\n<DL><p>\n'
                + bm(CANARY_URL, CANARY_TITLE)
                + bm(CANARY_URL, CANARY_TITLE)
                + "\n</DL><p>")
        for extra in ((), ("--json",)):
            r = self.check(doc(body), *extra)
            self.assertNotIn("canary-secret", r.stdout)
            self.assertNotIn("canarytoken", r.stdout)
            self.assertNotIn(CANARY_TITLE, r.stdout)
            self.assertNotIn(CANARY_FOLDER, r.stdout)
            self.assertNotIn("hidden-path", r.stdout)

    def test_json_shape_and_determinism(self):
        body = bm("https://example.org/x", "A") + bm("https://example.org/x", "B")
        f = self.write("b.html", doc(body))
        r1 = run("check", f, "--json")
        r2 = run("check", f, "--json")
        self.assertEqual(r1.stdout, r2.stdout)
        data = json.loads(r1.stdout)
        self.assertEqual(data["bookmarks"], 2)
        self.assertEqual(data["counts"]["exact-duplicate"], 1)

    def test_max_examples_cap(self):
        body = "".join('<DT><A>No href %d</A>' % i for i in range(5))
        f = self.write("cap.html", doc(body))
        r = run("check", f, "--max-examples", "2")
        self.assertEqual(r.stdout.count("missing-href"), 3)  # 2 examples + suppressed note
        self.assertIn("total 5", r.stdout)

    def test_missing_file_exit2(self):
        r = run("check", str(self.dir / "nope.html"))
        self.assertEqual(r.returncode, 2)

    def test_invalid_utf8_exit2(self):
        f = self.write("bad.html", b"\xff\xfe<DL>", binary=True)
        r = run("check", f)
        self.assertEqual(r.returncode, 2)

    def test_bom_tolerated(self):
        f = self.write("bom.html", b"\xef\xbb\xbf" + doc(bm("https://example.org/", "X")).encode())
        r = run("check", f)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_version(self):
        r = run("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn("1.0.0", r.stdout)

    def test_entities_in_title_do_not_break_parse(self):
        r = self.check(doc(bm("https://example.org/?a=1&amp;b=2", "Fish &amp; Chips")))
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_relative_href_quiet(self):
        r = self.check(doc(bm("docs/local.html", "Local Doc")))
        self.assertNotIn("malformed-url", r.stdout)
        self.assertNotIn("dangerous-scheme", r.stdout)

    def test_public_ip_not_private(self):
        r = self.check(doc(bm("https://8.8.8.8/x", "DNS")))
        self.assertNotIn("private-host", r.stdout)


if __name__ == "__main__":
    unittest.main()
