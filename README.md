# MarkFerry

**Audit a set of browser bookmark exports before you import them — without ever printing a single URL or title.**

MarkFerry is a single-file, standard-library-only Python tool that
preflights one or more Netscape bookmark files (the HTML format every
browser exports) *as one set*. It finds broken, risky, and duplicated
bookmarks before the import — and its report is safe to paste anywhere,
because no bookmark URL, title, or folder name ever appears in it.

```console
$ python3 markferry.py check demo.html
warning: insecure-http: bookmark #3 in demo.html [c8c711e430a5]
error: exact-duplicate: bookmarks #1, #2 in demo.html [b5b10dd0429e]
warning: near-duplicate: bookmarks #3, #4 in demo.html [2d98ecfcc926]
schemes: http=1, https=3
markferry: 4 bookmarks, 1 folders, 1 errors, 2 warnings
```

(That demo file holds four bookmarks: the same page saved twice, and
the same page again under an `http://` address carrying a
`utm_source` tracking parameter and under a clean `https://`
address.)

Every finding identifies a bookmark only by its position in the set and
the first 12 hex characters of the SHA-256 of its URL. You find the
bookmark in your export by position; the report itself leaks nothing
about where you browse.

## Why this exists

Moving bookmarks between browsers, phones, and backups is normally done
by importing first and cleaning up afterwards: the doubled entries, the
same page saved under an `http://` and an `https://` address, the link
with a password embedded in it, the `javascript:` bookmarklet you did
not mean to carry over. The tools that help live inside a browser, edit
the live bookmark tree directly, print your URLs into their reports, or
check dead links by visiting every site.

MarkFerry is the opposite shape:

- **Read-only.** It never modifies, merges, or deletes anything, and it
  never opens the network. Dead-link checking is deliberately out of
  scope — a preflight gate should work offline, in an air-gapped room.
- **Whole-set.** Files are audited together, with bookmarks numbered
  across the whole set, because the duplicates that matter live
  *between* an old export and a new one.
- **Private by construction.** The report carries positions and
  fingerprints only — no URLs, no titles, no folder names, no hosts —
  in text and JSON output alike. This is enforced by tests with canary
  values, not just promised here.
- **Honest matching.** Exact duplicates and near-duplicates are
  separate findings with the normalization rules stated below. A
  near-match is reported as a warning, never silently merged.

## Install

Nothing to install. Python 3.10 or newer, standard library only:

```console
$ python3 markferry.py --version
markferry 1.0.0
```

## Usage

```console
python3 markferry.py check FILE [FILE ...] [--json] [--max-examples N]
```

- `--json` — machine-readable output (deterministic: the same input
  set always produces byte-identical output).
- `--max-examples N` — cap the examples printed per finding code
  (default 10). Totals are always exact; suppressed examples are
  counted in a closing note.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No error findings (warnings may be present) |
| 1 | Error findings present |
| 2 | Usage or I/O error (missing file, invalid UTF-8, bad options) |

### What it checks

Per bookmark (errors): `missing-href`, `dangerous-scheme`
(`javascript:`, `data:`, `vbscript:`), `credential-in-url` (userinfo in
an http(s) authority), `malformed-url` (http(s) with no host).
Warnings: `insecure-http`, `private-host` (`localhost` or a
loopback/private/link-local/reserved IP literal), `missing-title`,
`bad-add-date`, `long-url` (over 2000 characters).

Per folder: `empty-folder`. Per file: `no-bookmarks`, plus `structure`
warnings for unmatched or unclosed folder tags.

Across the set:

- `exact-duplicate` (error) — same *exact key*: scheme and host
  lowercased, default port removed, empty path read as `/`, fragment
  removed; path and query otherwise unchanged.
- `near-duplicate` (warning) — same *near key* but not one exact
  group: `http`/`https` unified, a leading `www.` stripped, a trailing
  slash stripped, the fragment removed, and tracking parameters
  (`utm_*`, `fbclid`, `gclid`, `dclid`, `mc_cid`, `mc_eid`, `igshid`)
  removed with the rest sorted.

## Limitations, stated plainly

- Only the Netscape HTML export format is parsed. Browser-native JSON
  bookmark stores are not read.
- Non-http(s) bookmarks (for example `ftp:` or relative hrefs) receive
  no scheme-specific checks beyond a missing href.
- MarkFerry does not check whether links are alive, and never will —
  that requires the network, and this tool's promise is that it works
  with the network cable pulled.
- URL parsing follows the standard library's `urlsplit`; a URL exotic
  enough to defeat it falls back to whole-string matching for
  duplicate purposes.

## License

MIT — see `LICENSE`. Copyright (c) 2026 Dimon Global Group.
