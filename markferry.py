#!/usr/bin/env python3
"""MarkFerry - a read-only preflight gate for Netscape bookmark exports.

Audits one or more bookmark HTML files as one set before import.
Findings identify bookmarks only by position and SHA-256 fingerprint:
no URL, title, or folder name ever appears in the output.
Standard library only. No network. Never modifies any file.
"""
import argparse
import hashlib
import ipaddress
import json
import sys
from collections import Counter, OrderedDict
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urlsplit

VERSION = "1.0.0"
TRACKING_EXACT = {"fbclid", "gclid", "dclid", "mc_cid", "mc_eid", "igshid"}
DANGEROUS = {"javascript", "data", "vbscript"}


def fp(text):
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:12]


class Bookmark:
    __slots__ = ("num", "file", "href", "title", "add_date", "folder_path")

    def __init__(self, num, file, href, title, add_date, folder_path):
        self.num = num
        self.file = file
        self.href = href
        self.title = title
        self.add_date = add_date
        self.folder_path = folder_path


class Folder:
    __slots__ = ("num", "file", "name", "path", "count")

    def __init__(self, num, file, name, path):
        self.num = num
        self.file = file
        self.name = name
        self.path = path
        self.count = 0


class Parser(HTMLParser):
    def __init__(self, label, state):
        super().__init__(convert_charrefs=True)
        self.label = label
        self.state = state
        self.stack = []          # Folder objects currently open
        self.pending_folder = None
        self.capture = None      # "a" or "h3"
        self.a_attrs = None
        self.buf = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        ad = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if tag == "a":
            self.capture = "a"
            self.a_attrs = ad
            self.buf = []
        elif tag == "h3":
            self.capture = "h3"
            self.buf = []
        elif tag == "dl":
            name = self.pending_folder if self.pending_folder is not None else ""
            self.pending_folder = None
            path = "/".join([f.name for f in self.stack] + [name]) if (self.stack or name) else name
            folder = Folder(len(self.state["folders"]) + 1, self.label, name, path)
            self.state["folders"].append(folder)
            self.stack.append(folder)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "a" and self.capture == "a":
            title = "".join(self.buf)
            href = self.a_attrs.get("href")
            href = href.strip() if href is not None else None
            bm = Bookmark(
                len(self.state["bookmarks"]) + 1,
                self.label,
                href,
                title,
                self.a_attrs.get("add_date"),
                "/".join(f.name for f in self.stack),
            )
            self.state["bookmarks"].append(bm)
            for f in self.stack:
                f.count += 1
            self.capture = None
            self.a_attrs = None
            self.buf = []
        elif tag == "h3" and self.capture == "h3":
            self.pending_folder = "".join(self.buf).strip()
            self.capture = None
            self.buf = []
        elif tag == "dl":
            if self.stack:
                self.stack.pop()
            else:
                self.state["findings"].append({
                    "severity": "warning", "code": "structure",
                    "file": self.label,
                    "detail": "unmatched closing folder tag",
                })

    def handle_data(self, data):
        if self.capture:
            self.buf.append(data)

    def close(self):
        super().close()
        if self.stack:
            self.state["findings"].append({
                "severity": "warning", "code": "structure",
                "file": self.label,
                "detail": "unclosed folder at end of file",
            })
            self.stack = []


def scheme_of(href):
    if not href:
        return ""
    i = href.find(":")
    if i <= 0:
        return ""
    s = href[:i].lower()
    return s if all(c.isalnum() or c in "+-." for c in s) else ""


def split_http(href):
    try:
        return urlsplit(href)
    except ValueError:
        return None


def exact_key(bm):
    href = bm.href or ""
    sch = scheme_of(href)
    if sch in ("http", "https"):
        parts = split_http(href)
        if parts is None:
            return "raw:" + href.casefold()
        host = (parts.hostname or "").lower()
        try:
            port = parts.port
        except ValueError:
            port = -1
        if port == (80 if sch == "http" else 443):
            port = None
        auth = host if port is None else f"{host}:{port}"
        path = parts.path or "/"
        q = f"?{parts.query}" if parts.query else ""
        return f"{sch}://{auth}{path}{q}"
    return "raw:" + href.casefold()


def near_key(bm):
    href = bm.href or ""
    sch = scheme_of(href)
    if sch not in ("http", "https"):
        return None
    parts = split_http(href)
    if parts is None:
        return None
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    try:
        port = parts.port
    except ValueError:
        port = -1
    if port in (80, 443):
        port = None
    auth = host if port is None else f"{host}:{port}"
    path = parts.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    if path == "/":
        path = ""
    params = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
              if k.lower() not in TRACKING_EXACT and not k.lower().startswith("utm_")]
    params.sort()
    q = f"?{urlencode(params)}" if params else ""
    return f"web://{auth}{path}{q}"


def check_bookmark(bm, findings):
    def add(sev, code, detail=""):
        f = {"severity": sev, "code": code, "bookmark": bm.num, "file": bm.file,
             "fingerprint": fp(bm.href or "")}
        if detail:
            f["detail"] = detail
        findings.append(f)

    href = bm.href
    if href is None or href == "":
        add("error", "missing-href")
        return
    sch = scheme_of(href)
    if sch in DANGEROUS:
        add("error", "dangerous-scheme", f"scheme {sch}")
    if sch in ("http", "https"):
        parts = split_http(href)
        if parts is None or not parts.hostname:
            add("error", "malformed-url")
        else:
            netloc = parts.netloc
            if "@" in netloc:
                add("error", "credential-in-url")
            host = parts.hostname.lower()
            if host == "localhost":
                add("warning", "private-host")
            else:
                try:
                    ip = ipaddress.ip_address(host)
                    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
                        add("warning", "private-host")
                except ValueError:
                    pass
        if sch == "http":
            add("warning", "insecure-http")
    if not bm.title or not bm.title.strip():
        add("warning", "missing-title")
    if bm.add_date is not None and bm.add_date.strip() != "" and not bm.add_date.strip().isdigit():
        add("warning", "bad-add-date")
    if len(href) > 2000:
        add("warning", "long-url")


def audit(labels_and_texts):
    state = {"bookmarks": [], "folders": [], "findings": []}
    per_file_counts = []
    for label, text in labels_and_texts:
        before = len(state["bookmarks"])
        p = Parser(label, state)
        p.feed(text)
        p.close()
        n = len(state["bookmarks"]) - before
        per_file_counts.append(n)
        if n == 0:
            state["findings"].append({
                "severity": "error", "code": "no-bookmarks", "file": label,
                "detail": "no bookmarks found in file",
            })
    bookmarks = state["bookmarks"]
    folders = state["folders"]
    findings = state["findings"]

    per_bm = []
    for bm in bookmarks:
        check_bookmark(bm, per_bm)
    findings_all = list(findings) + per_bm

    for folder in folders:
        if folder.count == 0:
            norm_path = " ".join(folder.path.casefold().split())
            findings_all.append({
                "severity": "warning", "code": "empty-folder",
                "folder": folder.num, "file": folder.file,
                "fingerprint": fp(norm_path),
            })

    # cross-bookmark groups
    def groups(keyfn, skip_none=True):
        m = OrderedDict()
        for bm in bookmarks:
            if bm.href is None or bm.href == "":
                continue
            k = keyfn(bm)
            if k is None and skip_none:
                continue
            m.setdefault(k, []).append(bm)
        return [(k, v) for k, v in m.items() if len(v) > 1]

    cross = []
    exact_groups = groups(exact_key)
    exact_member_sets = [set(b.num for b in v) for _, v in exact_groups]
    for k, members in exact_groups:
        cross.append({
            "severity": "error", "code": "exact-duplicate",
            "bookmarks": [b.num for b in members],
            "file": members[0].file,
            "fingerprint": fp(k),
            "_first": members[0].num,
        })
    for k, members in groups(near_key):
        nums = set(b.num for b in members)
        if any(nums == s for s in exact_member_sets):
            continue
        cross.append({
            "severity": "warning", "code": "near-duplicate",
            "bookmarks": [b.num for b in members],
            "file": members[0].file,
            "fingerprint": fp(k),
            "_first": members[0].num,
        })
    cross.sort(key=lambda f: (f["_first"], f["code"]))
    for c in cross:
        del c["_first"]
    findings_all += cross

    schemes = Counter()
    for bm in bookmarks:
        schemes[scheme_of(bm.href or "") or "(none)"] += 1
    errors = sum(1 for f in findings_all if f["severity"] == "error")
    warnings = sum(1 for f in findings_all if f["severity"] == "warning")
    return {
        "bookmarks": bookmarks, "folders": folders, "findings": findings_all,
        "schemes": dict(sorted(schemes.items())),
        "errors": errors, "warnings": warnings,
    }


def cap_findings(findings, max_examples):
    counts = Counter(f["code"] for f in findings)
    seen = Counter()
    kept = []
    for f in findings:
        seen[f["code"]] += 1
        if seen[f["code"]] <= max_examples:
            kept.append(f)
    suppressed = {c: counts[c] - min(counts[c], max_examples) for c in counts
                  if counts[c] > max_examples}
    return kept, counts, suppressed


def render_text(result, max_examples):
    kept, counts, suppressed = cap_findings(result["findings"], max_examples)
    lines = []
    for f in kept:
        where = f.get("file", "")
        if "bookmark" in f:
            where = f"bookmark #{f['bookmark']} in {f['file']}"
        elif "folder" in f:
            where = f"folder #{f['folder']} in {f['file']}"
        elif "bookmarks" in f:
            where = "bookmarks " + ", ".join(f"#{n}" for n in f["bookmarks"]) + f" in {f['file']}"
        detail = f" ({f['detail']})" if f.get("detail") else ""
        fpr = f" [{f['fingerprint']}]" if f.get("fingerprint") else ""
        lines.append(f"{f['severity']}: {f['code']}: {where}{fpr}{detail}")
    for code in sorted(suppressed):
        lines.append(f"note: {code}: {suppressed[code]} further example(s) suppressed "
                     f"(total {counts[code]})")
    if result["schemes"]:
        sch = ", ".join(f"{k}={v}" for k, v in result["schemes"].items())
        lines.append(f"schemes: {sch}")
    lines.append(f"markferry: {len(result['bookmarks'])} bookmarks, "
                 f"{len(result['folders'])} folders, {result['errors']} errors, "
                 f"{result['warnings']} warnings")
    return "\n".join(lines) + "\n"


def render_json(result, max_examples):
    kept, counts, suppressed = cap_findings(result["findings"], max_examples)
    out = {
        "tool": "markferry", "version": VERSION,
        "bookmarks": len(result["bookmarks"]), "folders": len(result["folders"]),
        "errors": result["errors"], "warnings": result["warnings"],
        "schemes": result["schemes"],
        "counts": dict(sorted(counts.items())),
        "suppressed": suppressed,
        "findings": kept,
    }
    return json.dumps(out, indent=2, sort_keys=True) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="markferry")
    ap.add_argument("--version", action="version", version=f"markferry {VERSION}")
    sub = ap.add_subparsers(dest="cmd")
    chk = sub.add_parser("check")
    chk.add_argument("files", nargs="+")
    chk.add_argument("--json", action="store_true")
    chk.add_argument("--max-examples", type=int, default=10)
    args = ap.parse_args(argv)
    if args.cmd != "check":
        ap.print_usage(sys.stderr)
        return 2
    if args.max_examples < 0:
        print("markferry: --max-examples must be >= 0", file=sys.stderr)
        return 2
    inputs = []
    for label in args.files:
        try:
            with open(label, "rb") as fh:
                raw = fh.read()
        except OSError as e:
            print(f"markferry: cannot read {label}: {e.strerror or e}", file=sys.stderr)
            return 2
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            print(f"markferry: {label}: invalid UTF-8", file=sys.stderr)
            return 2
        inputs.append((label, text))
    result = audit(inputs)
    sys.stdout.write(render_json(result, args.max_examples) if args.json
                     else render_text(result, args.max_examples))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
