# Wayback OSINT

A small Python CLI for researching public captures in the Internet Archive's Wayback Machine CDX index. It accepts ordinary URLs and bare Instagram usernames, exports capture metadata, builds replay links, and can optionally save selected raw archived responses for local inspection.

> **Scope and privacy:** This queries only the Internet Archive. It does not log into Instagram, use Instagram's private APIs, defeat access controls, or make a currently private profile public. Use it only for accounts and material you own or are authorized to research. An archived public snapshot may expose information that was publicly accessible at the time it was captured; do not redistribute other people's personal information.

## Install

Python 3.10+ is recommended.

```bash
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
```

## Check an Instagram profile you own

Use your current or former handle. For handles containing dots, keep the leading `@` so the program recognizes it as an Instagram username:

```bash
python wayback_osint.py YOUR_INSTAGRAM_USERNAME
# Dotted username example:
python wayback_osint.py @first.last
```

Or supply the profile URL:

```bash
python wayback_osint.py https://www.instagram.com/YOUR_INSTAGRAM_USERNAME/
```

The default `prefix` scope searches the profile URL and URL paths beneath it. It does **not** search all of Instagram. Results are written to a target-specific folder under `output/`:

- `captures.json` — complete structured result set returned by the query
- `captures.csv` — spreadsheet-friendly capture list
- `report.md` — summary and clickable Wayback replay links

## Useful options

```bash
# Exact URL only
python wayback_osint.py YOUR_USERNAME --scope exact

# Only captures in a date window
python wayback_osint.py YOUR_USERNAME --from-date 20180101 --to-date 20231231

# Only captures that returned HTTP 200 at capture time
python wayback_osint.py YOUR_USERNAME --status 200

# Download up to 3 latest distinct archived responses as raw files
python wayback_osint.py YOUR_USERNAME --recover-latest 3

# Increase/decrease the total pagination ceiling
python wayback_osint.py YOUR_USERNAME --max-pages 10 --page-limit 3000

# Custom output folder
python wayback_osint.py YOUR_USERNAME --out ./case-files
```

`--recover-latest N` uses the CDX raw replay form (`id_`) and writes files into `recovered/`. It does not execute or render them. Review downloaded HTML as untrusted content; do not open it with scripts enabled or enter credentials on archived pages. Individual downloads are size-limited (10 MB by default; configurable with `--max-file-mb`).

For general websites, broader scopes are available:

```bash
python wayback_osint.py example.com --scope domain
python wayback_osint.py https://example.com/docs/ --scope prefix
```

Host/domain-wide Instagram queries are blocked by default to avoid accidentally querying the entire platform. `--allow-broad` explicitly overrides that guardrail; it is not needed for your profile.

## What a result means (and does not mean)

- A CDX result means the archive has an indexed capture for that URL and timestamp.
- It does not guarantee that the entire page, images, videos, comments, or all profile posts were preserved.
- Instagram pages are highly dynamic. The Wayback Machine may have captured only a login wall, a redirect, a shell page, or incomplete metadata.
- The profile URL's captures will not necessarily reveal post permalinks. Instagram post URLs (`/p/...`, `/reel/...`) are separate URLs and must themselves have been archived to be replayable.
- No results do not prove that nothing was archived. URL variants, trailing slashes, redirects, robots exclusions, or archive limitations can affect matches.
- `statuscode=200` refers to the archived HTTP response at capture time, not the current live page.

## Tests

```bash
python -m unittest discover -s tests -v
```

## API reference

The tool uses the public Wayback CDX endpoint documented by Internet Archive:

- https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md

The CDX API supports URL match scopes (`exact`, `prefix`, `host`, `domain`), JSON output, date filters, and resumption keys for paginating large result sets.
