#!/usr/bin/env python3
# Wayback OSINT-Framework: inspect public Internet Archive captures for a URL/profile

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

CDX_API = "https://web.archive.org/cdx/search/cdx"
USER_AGENT = "Wayback OSINT-Framework/v_1.0"
FIELDS = ["timestamp", "original", "mimetype", "statuscode", "digest", "length"]
ALLOWED_MATCH_TYPES = {"exact", "prefix", "host", "domain"}


@dataclass
class Capture:
    timestamp: str
    original: str
    mimetype: str
    statuscode: str
    digest: str
    length: str

    @property
    def replay_url(self) -> str:
        return f"https://web.archive.org/web/{self.timestamp}/{self.original}"

    @property
    def raw_url(self) -> str:
        return f"https://web.archive.org/web/{self.timestamp}id_/{self.original}"

    @property
    def captured_at(self) -> str:
        try:
            return datetime.strptime(self.timestamp, "%Y%m%d%H%M%S").isoformat(sep=" ")
        except ValueError:
            return self.timestamp


def normalize_target(value: str) -> str:

    # Accept a URL, an Instagram profile URL, or a bare Instagram username.
    value = value.strip()
    if not value:
        raise ValueError("Target can't be empty!")

    explicit_instagram_handle = value.startswith("@")
    if explicit_instagram_handle:  # disambiguates handles containing dots
        value = value[1:]

    # A bare handle is treated as an Instagram username. A dotted handle should
    # be supplied with @ because it otherwise resembles a hostname.
    if explicit_instagram_handle or (not re.search(r"[/:.\s]", value) and not value.startswith("http")):
        if not re.fullmatch(r"[A-Za-z0-9._]{1,30}", value):
            raise ValueError("Invalig Instagram-Username.")
        return f"https://www.instagram.com/{value}/"

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Please provide a valid URL or Instagram-Username.")
    if parsed.username or parsed.password:
        raise ValueError("URLs with credential-parameters are not accepted.")

    # Keep the path and query as supplied; CDX performs URL matching.
    return value.rstrip("#")


def validate_date(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.replace("-", "")
    if not re.fullmatch(r"\d{8}", normalized):
        raise argparse.ArgumentTypeError("Select date as YYYYMMDD or YYYY-MM-DD.")
    try:
        datetime.strptime(normalized, "%Y%m%d")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Invalid date.") from exc
    return normalized


def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=4,
        connect=4,
        read=4,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def parse_cdx_payload(payload: Any) -> tuple[list[Capture], str | None]:
    """Parse CDX JSON, including empty results and its optional resume-key trailer.

    The Internet Archive normally returns ``[[header], [row], ...]``. For a
    valid query with no matches it can also return an empty JSON array (``[]``).
    That is an empty result, not a malformed response.
    """
    if payload == []:
        return [], None

    if isinstance(payload, dict):
        # Some gateways/proxies may return a JSON error object with HTTP 200.
        detail = payload.get("message") or payload.get("error") or payload
        raise ValueError(f"CDX API-Error: {str(detail)[:500]}")

    if not isinstance(payload, list):
        raise ValueError(
            "Invalid CDX-JSON format: provide a JSON-Array, "
            f"gathered: {type(payload).__name__}."
        )

    if not isinstance(payload[0], list):
        preview = repr(payload[0])[:300]
        raise ValueError(
            "Invalid CDX-JSON format: first row does not contain "
            f"fieldname. Response: {preview}"
        )

    header = [str(field) for field in payload[0]]
    required = {"timestamp", "original"}
    if not required.issubset(header):
        raise ValueError(
            "CDX-response does not contain: "
            f"{sorted(required)}. Tatsächliche Spalten: {header!r}"
        )

    rows: list[Capture] = []
    resume_key: str | None = None

    for row in payload[1:]:
        if not isinstance(row, list) or not row:
            continue
        if len(row) == 1 and isinstance(row[0], str):
            resume_key = row[0]
            continue

        # Map by header names and tolerate optional/missing trailing fields.
        record = {
            field: row[index]
            for index, field in enumerate(header)
            if index < len(row)
        }
        if not record.get("timestamp") or not record.get("original"):
            continue

        rows.append(
            Capture(
                timestamp=str(record["timestamp"]),
                original=str(record["original"]),
                mimetype=str(record.get("mimetype") or ""),
                statuscode=str(record.get("statuscode") or ""),
                digest=str(record.get("digest") or ""),
                length=str(record.get("length") or ""),
            )
        )
    return rows, resume_key


class WaybackClient:
    def __init__(self, session: requests.Session | None = None, page_limit: int = 5000):
        self.session = session or build_session()
        self.page_limit = page_limit

    def search(
        self,
        target: str,
        match_type: str = "prefix",
        from_date: str | None = None,
        to_date: str | None = None,
        status: str | None = None,
        max_pages: int = 20,
    ) -> list[Capture]:
        if match_type not in ALLOWED_MATCH_TYPES:
            raise ValueError(f"match_type musst be {sorted(ALLOWED_MATCH_TYPES)}")
        if max_pages < 1:
            raise ValueError("max_pages musst be min. 1")

        params: dict[str, str | int] = {
            "url": target,
            "matchType": match_type,
            "output": "json",
            "fl": ",".join(FIELDS),
            "limit": self.page_limit,
            "showResumeKey": "true",
        }
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date
        if status:
            params["filter"] = f"statuscode:{status}"

        all_captures: list[Capture] = []
        seen_resume_keys: set[str] = set()

        for page_number in range(max_pages):
            response = self.session.get(CDX_API, params=params, timeout=(10, 45))
            response.raise_for_status()
            try:
                payload = response.json()
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON-CDX format: {response.text[:300]}") from exc

            captures, resume_key = parse_cdx_payload(payload)
            all_captures.extend(captures)

            if not resume_key:
                break
            if resume_key in seen_resume_keys:
                print("same CDX-Resume-Key; closed Pagination", file=sys.stderr)
                break
            seen_resume_keys.add(resume_key)
            params["resumeKey"] = resume_key
            time.sleep(0.25)  # keep sequential index requests modest
        else:
            print(
                f"Max. pagenumber ({max_pages}) - results may be not complete.",
                file=sys.stderr,
            )

        # Remove exact duplicate rows while retaining the CDX order.
        unique: list[Capture] = []
        seen: set[tuple[str, str, str]] = set()
        for item in all_captures:
            key = (item.timestamp, item.original, item.digest)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    def recover(self, capture: Capture, destination: Path, max_bytes: int = 10 * 1024 * 1024) -> Path:
        """Save one raw archived response. Never execute or render downloaded content."""
        response = self.session.get(capture.raw_url, timeout=(10, 60), stream=True)
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", capture.mimetype).split(";", 1)[0].lower()
        extension = {
            "text/html": ".html",
            "text/plain": ".txt",
            "application/json": ".json",
            "application/ld+json": ".json",
            "image/jpeg": ".jpg",
            "image/png": ".png",
            "image/webp": ".webp",
            "image/gif": ".gif",
        }.get(content_type, ".bin")

        destination.mkdir(parents=True, exist_ok=True)
        safe_original = re.sub(r"[^A-Za-z0-9._-]+", "_", urlparse(capture.original).path.strip("/"))
        safe_original = safe_original[:70] or "profile"
        filename = f"{capture.timestamp}_{safe_original}{extension}"
        output_path = destination / filename

        written = 0
        with output_path.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                written += len(chunk)
                if written > max_bytes:
                    handle.close()
                    output_path.unlink(missing_ok=True)
                    raise ValueError(f"Archive-file bigger than Limit of {max_bytes} Bytes.")
                handle.write(chunk)
        return output_path


def write_exports(captures: list[Capture], target: str, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for capture in captures:
        record = asdict(capture)
        record["captured_at"] = capture.captured_at
        record["replay_url"] = capture.replay_url
        record["raw_url"] = capture.raw_url
        records.append(record)

    (out_dir / "captures.json").write_text(
        json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    with (out_dir / "captures.csv").open("w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(records[0].keys()) if records else ["timestamp", "original"])
        writer.writeheader()
        writer.writerows(records)

    sorted_captures = sorted(captures, key=lambda item: item.timestamp)
    unique_digests = len({item.digest for item in captures if item.digest})
    lines = [
        "# Wayback OSINT report",
        "",
        f"- Target: `{target}`",
        f"- Captures: **{len(captures)}**",
        f"- Distinct content digests: **{unique_digests}**",
        f"- First capture: `{sorted_captures[0].captured_at if sorted_captures else 'n/a'}`",
        f"- Last capture: `{sorted_captures[-1].captured_at if sorted_captures else 'n/a'}`",
        "",
        "> A capture proves only that the archive indexed a URL at a timestamp. It does not prove that every post, image, or profile field was captured.",
        "",
        "## Captures",
        "",
    ]
    for capture in sorted_captures:
        lines.append(
            f"- `{capture.captured_at}` · HTTP `{capture.statuscode}` · `{capture.mimetype}` · "
            f"[{capture.original}]({capture.replay_url}) · digest `{capture.digest}`"
        )
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def make_output_dir(base: Path, target: str) -> Path:
    parsed = urlparse(target)
    path_hint = parsed.path.strip("/").split("/")[-1] if parsed.path.strip("/") else "root"
    label = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{parsed.hostname}_{path_hint}").strip("._-")
    return base / (label[:80] or "target")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Search Internet Archive Wayback captures for a URL or public profile."
    )
    parser.add_argument("target", help="URL, Instagram profile URL, or bare Instagram username")
    parser.add_argument("--scope", choices=sorted(ALLOWED_MATCH_TYPES), default="prefix",
                        help="exact URL, path prefix, host, or domain (default: prefix)")
    parser.add_argument("--from-date", type=validate_date, help="earliest capture date: YYYYMMDD")
    parser.add_argument("--to-date", type=validate_date, help="latest capture date: YYYYMMDD")
    parser.add_argument("--status", help="optional HTTP status filter, e.g. 200")
    parser.add_argument("--max-pages", type=int, default=20, help="pagination cap (default: 20)")
    parser.add_argument("--page-limit", type=int, default=5000, help="CDX rows per page (default: 5000)")
    parser.add_argument("--out", type=Path, default=Path("output"), help="output base directory")
    parser.add_argument("--recover-latest", type=int, default=0, metavar="N",
                        help="download up to N latest distinct captures as raw files")
    parser.add_argument("--max-file-mb", type=int, default=10, help="max size per recovered file (default: 10 MB)")
    parser.add_argument("--allow-broad", action="store_true",
                        help="allow host/domain-wide queries against instagram.com")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        target = normalize_target(args.target)
        if args.from_date and args.to_date and args.from_date > args.to_date:
            parser.error("--from-date darf nicht nach --to-date liegen.")
        if args.recover_latest < 0 or args.max_file_mb < 1 or args.page_limit < 1:
            parser.error("recover-latest darf nicht negativ sein; max-file-mb und page-limit müssen > 0 sein.")

        host = (urlparse(target).hostname or "").lower()
        if host == "instagram.com" or host.endswith(".instagram.com"):
            if args.scope in {"host", "domain"} and not args.allow_broad:
                parser.error("Breite Instagram-Host/Domain-Abfragen sind standardmäßig gesperrt. Für das eigene Profil --scope prefix verwenden; --allow-broad hebt die Sperre bewusst auf.")

        output_dir = make_output_dir(args.out, target)
        print("-- Wayback OSINT-Framework --")
        print(f"Target : {target}")
        print(f"Scope  : {args.scope}")
        print("Querying Internet Archive CDX index ...")

        client = WaybackClient(page_limit=args.page_limit)
        captures = client.search(
            target=target,
            match_type=args.scope,
            from_date=args.from_date,
            to_date=args.to_date,
            status=args.status,
            max_pages=args.max_pages,
        )

        write_exports(captures, target, output_dir)
        print(f"\nCaptures found : {len(captures)}")
        print(f"\nOutput         : {output_dir.resolve()}")

        if captures:
            ordered = sorted(captures, key=lambda item: item.timestamp)
            print(f"First capture  : {ordered[0].captured_at}")
            print(f"Latest capture : {ordered[-1].captured_at}")
            print("\nLatest snapshots:")
            for capture in ordered[-10:][::-1]:
                print(f"  {capture.captured_at}  {capture.statuscode:>3}  {capture.replay_url}")
        else:
            print("\nNo captures found for this exact query. Try --scope exact/prefix, a slash variant, or a different date range.")

        if args.recover_latest and captures:
            # Prefer different archived payloads; identical digests add no new version.
            selected: list[Capture] = []
            seen_digests: set[str] = set()
            for capture in sorted(captures, key=lambda item: item.timestamp, reverse=True):
                if capture.digest and capture.digest in seen_digests:
                    continue
                if capture.digest:
                    seen_digests.add(capture.digest)
                selected.append(capture)
                if len(selected) >= args.recover_latest:
                    break

            recovered_dir = output_dir / "recovered"
            print(f"\nRecovering up to {len(selected)} distinct archived responses ...")
            for capture in selected:
                try:
                    saved = client.recover(
                        capture,
                        recovered_dir,
                        max_bytes=args.max_file_mb * 1024 * 1024,
                    )
                    print(f"	{capture.captured_at}: {saved.name}")
                except requests.RequestException as exc:
                    print(f"	{capture.captured_at}: download failed: {exc}", file=sys.stderr)
                except ValueError as exc:
                    print(f"	{capture.captured_at}: {exc}", file=sys.stderr)

        print("\nDone. Open report.md and captures.csv in the output directory.")
        return 0
    except (ValueError, requests.RequestException) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
