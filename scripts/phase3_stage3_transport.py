#!/usr/bin/env python3
"""Capture Stage 3 HTTPS, security-header, and external TLS scan evidence.

    python3 scripts/phase3_stage3_transport.py --host vorrin.truongdinh.dev

Run from your own machine (it needs curl, which macOS includes). It checks:

1. http://<host>/ answers with a redirect to HTTPS (not followed).
2. https://<host>/ answers 200 with a valid certificate for the host and the
   five required headers: Strict-Transport-Security (max-age of at least a
   year), Content-Security-Policy, X-Content-Type-Options: nosniff,
   Referrer-Policy, and frame-ancestors 'none' (CSP) or X-Frame-Options.
3. TLS protocols, probed with curl: TLS 1.0 and 1.1 must be refused and
   TLS 1.2 accepted. TLS 1.3 is recorded when the local curl supports it.
4. Mozilla HTTP Observatory, an external scanner, grades the headers; the
   grade must be in the A range.

With --ssllabs-email (an address registered with the Qualys SSL Labs API
v4), SSL Labs also grades TLS and every endpoint must get A-, A, or A+.

The raw results go to docs/evidence/stage3/source-reports/external-tls.json;
the unreviewed summaries go to build/phase3/stage3/.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/evidence/stage3/source-reports/external-tls.json"
SOURCE_PATH = "stage3/source-reports/external-tls.json"
DRAFTS = ROOT / "build/phase3/stage3"
OBSERVATORY = "https://observatory-api.mdn.mozilla.net/api/v2/scan"
SSLLABS = "https://api.ssllabs.com/api/v4/analyze"
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MIN_HSTS_SECONDS = 31_536_000


class TransportError(RuntimeError):
    pass


def tls_context() -> ssl.SSLContext:
    """A verifying context that works on python.org macOS builds (see phase3_id_token.py)."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    try:
        import botocore

        bundle = Path(botocore.__file__).with_name("cacert.pem")
        if bundle.is_file():
            return ssl.create_default_context(cafile=str(bundle))
    except ImportError:
        pass
    return ssl.create_default_context()


def header_checks(headers: dict[str, str]) -> dict[str, bool]:
    lowered = {key.lower(): value for key, value in headers.items()}
    hsts = lowered.get("strict-transport-security", "")
    max_age = re.search(r"max-age=(\d+)", hsts)
    csp = lowered.get("content-security-policy", "")
    return {
        "strict_transport_security": bool(max_age and int(max_age.group(1)) >= MIN_HSTS_SECONDS),
        "content_security_policy": "default-src" in csp,
        "x_content_type_options": lowered.get("x-content-type-options", "").strip().lower() == "nosniff",
        "referrer_policy": bool(lowered.get("referrer-policy", "").strip()),
        "frame_ancestors": "frame-ancestors 'none'" in csp
        or lowered.get("x-frame-options", "").strip().upper() == "DENY",
    }


def http_redirect(host: str) -> tuple[int, str]:
    connection = http.client.HTTPConnection(host, 80, timeout=15)
    try:
        connection.request("GET", "/", headers={"User-Agent": "vorrin-stage3-transport"})
        response = connection.getresponse()
        return response.status, response.getheader("Location") or ""
    finally:
        connection.close()


def https_get(host: str) -> tuple[int, dict[str, str], dict[str, Any]]:
    context = tls_context()
    connection = http.client.HTTPSConnection(host, 443, timeout=15, context=context)
    try:
        connection.request("GET", "/", headers={"User-Agent": "vorrin-stage3-transport"})
        response = connection.getresponse()
        response.read()
        certificate = connection.sock.getpeercert()
        protocol = connection.sock.version()
        headers = dict(response.getheaders())
        status = response.status
    finally:
        connection.close()
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), UTC)
    return (
        status,
        headers,
        {
            "verified_for_host": True,
            "negotiated_protocol": protocol,
            "not_after": not_after.isoformat(),
            "days_remaining": (not_after - datetime.now(UTC)).days,
        },
    )


def curl_protocol(host: str, version: str) -> dict[str, Any]:
    curl = shutil.which("curl")
    if not curl:
        raise TransportError("curl is required for the TLS protocol probe")
    result = subprocess.run(
        [
            curl,
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            f"--tlsv{version}",
            "--tls-max",
            version,
            f"https://{host}/",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    supported_locally = result.returncode not in {2, 4}  # 2/4: option or feature unsupported by this curl
    return {
        "http_code": result.stdout.strip() or "000",
        "curl_exit": result.returncode,
        "probe_supported": supported_locally,
    }


def tls_result(probes: dict[str, dict[str, Any]]) -> bool:
    refused = all(probes[v]["http_code"] == "000" and probes[v]["curl_exit"] != 0 for v in ("1.0", "1.1"))
    return refused and probes["1.2"]["http_code"] == "200"


def _fetch_json(request: urllib.request.Request) -> Any:
    with urllib.request.urlopen(request, timeout=60, context=tls_context()) as response:
        return json.loads(response.read())


def observatory_scan(host: str) -> dict[str, Any]:
    url = f"{OBSERVATORY}?{urllib.parse.urlencode({'host': host})}"
    request = urllib.request.Request(url, method="POST", headers={"User-Agent": "vorrin-stage3-transport"})
    try:
        return _fetch_json(request)
    except urllib.error.URLError as exc:
        raise TransportError(f"Mozilla HTTP Observatory could not be reached: {exc}") from None


def ssllabs_scan(host: str, email: str, *, poll_seconds: int = 20, max_minutes: int = 12) -> dict[str, Any]:
    deadline = time.monotonic() + max_minutes * 60
    params = {"host": host, "startNew": "on", "all": "done"}
    while True:
        request = urllib.request.Request(
            f"{SSLLABS}?{urllib.parse.urlencode(params)}",
            headers={"email": email, "User-Agent": "vorrin-stage3"},
        )
        try:
            result = _fetch_json(request)
        except urllib.error.HTTPError as exc:
            raise TransportError(f"SSL Labs returned HTTP {exc.code} (is the email registered?)") from None
        params.pop("startNew", None)
        if result.get("status") in {"READY", "ERROR"}:
            return result
        if time.monotonic() > deadline:
            raise TransportError("SSL Labs did not finish in time; run again later")
        print(f"    SSL Labs: {result.get('status')}…")
        time.sleep(poll_seconds)


def ssllabs_grades(result: dict[str, Any]) -> list[str]:
    return [endpoint.get("grade") or "none" for endpoint in result.get("endpoints", [])]


def write_json(path: Path, value: Any) -> str:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--host", required=True, help="console host name, e.g. vorrin.truongdinh.dev")
    parser.add_argument("--ssllabs-email", help="registered SSL Labs API v4 email (optional)")
    args = parser.parse_args(argv)
    host = args.host.strip().lower()
    if not _HOST.fullmatch(host) or host.endswith(".cloudfront.net"):
        parser.error(
            "--host must be the custom console domain (the default CloudFront domain cannot pass TLS)"
        )

    try:
        print("1/4 HTTP redirect…")
        redirect_status, location = http_redirect(host)
        print(f"    {redirect_status} -> {location}")
        print("2/4 HTTPS response, certificate, and headers…")
        https_status, headers, certificate = https_get(host)
        checks = header_checks(headers)
        print(
            f"    {https_status}; {certificate['negotiated_protocol']}; certificate valid {certificate['days_remaining']} more days"
        )
        for name, passed in checks.items():
            print(f"    {'ok  ' if passed else 'FAIL'} {name}")
        print("3/4 TLS protocol probe (curl)…")
        probes = {version: curl_protocol(host, version) for version in ("1.0", "1.1", "1.2", "1.3")}
        for version, probe in probes.items():
            print(f"    TLS {version}: {probe['http_code']}")
        print("4/4 External scans…")
        observatory = observatory_scan(host)
        print(
            f"    Mozilla HTTP Observatory: grade {observatory.get('grade')} (score {observatory.get('score')})"
        )
        ssllabs = ssllabs_scan(host, args.ssllabs_email) if args.ssllabs_email else None
        if ssllabs is not None:
            print(f"    SSL Labs: {', '.join(ssllabs_grades(ssllabs))}")
    except (TimeoutError, TransportError, OSError, ssl.SSLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    tls_ok = tls_result(probes) and certificate["days_remaining"] >= 14
    if ssllabs is not None:
        tls_ok = (
            tls_ok
            and all(grade in {"A+", "A", "A-"} for grade in ssllabs_grades(ssllabs))
            and bool(ssllabs_grades(ssllabs))
        )
    headers_ok = str(observatory.get("grade", "")).startswith("A") and all(checks.values())
    problems = []
    if redirect_status not in {301, 302, 307, 308} or not location.startswith(f"https://{host}"):
        problems.append(f"HTTP did not redirect to HTTPS ({redirect_status})")
    if https_status != 200:
        problems.append(f"HTTPS returned {https_status}")
    if not tls_ok:
        problems.append(
            "TLS: 1.0/1.1 must be refused, 1.2 accepted, the certificate valid 14+ days, SSL Labs A-range"
        )
    if not headers_ok:
        problems.append("security headers: every header check and an Observatory A-range grade are required")
    if problems:
        print("\nNot written. Fix these first:\n  " + "\n  ".join(problems))
        return 1

    scanned_at = datetime.now().astimezone().replace(microsecond=0).isoformat()
    provider = "Mozilla HTTP Observatory API v2 (headers)" + (
        "; Qualys SSL Labs API v4 (TLS)"
        if ssllabs is not None
        else "; curl TLS protocol probe from the owner's network"
    )
    source_sha = write_json(
        SOURCE,
        {
            "schema_version": 1,
            "host": host,
            "scanned_at": scanned_at,
            "http_redirect": {"status": redirect_status, "location": location},
            "https": {"status": https_status, "certificate": certificate, "header_checks": checks},
            "tls_protocol_probe": probes,
            "mozilla_observatory": observatory,
            "ssllabs": None
            if ssllabs is None
            else {
                "grades": ssllabs_grades(ssllabs),
                "status": ssllabs.get("status"),
                "endpoints": len(ssllabs.get("endpoints", [])),
            },
        },
    )
    write_json(
        DRAFTS / "external-tls-scan.json",
        {
            "schema_version": 1,
            "provider": provider,
            "scanned_at": scanned_at,
            "tls_result": "pass",
            "security_headers_result": "pass",
            "source_report_evidence_path": SOURCE_PATH,
            "source_report_sha256": source_sha,
        },
    )
    write_json(
        DRAFTS / "transport-security.json",
        {
            "schema_version": 1,
            "http_redirect_status": redirect_status,
            "https_status": https_status,
            "headers": checks,
        },
    )
    print(
        f"\nTLS and headers pass. Wrote {SOURCE_PATH} and the unreviewed summaries in build/phase3/stage3/."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
