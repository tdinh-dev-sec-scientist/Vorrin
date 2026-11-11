"""CloudTrail collector: trail configuration AND live logging status.

These are two different questions. A trail can exist and be misconfigured, and a
correctly configured trail can be stopped or failing delivery, so the collector
makes both calls and keeps the answers in separate fields.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ..normalize import cloudtrail as normalize
from ._common import AWS_EXCEPTIONS, OK, record_error, safe_call

log = logging.getLogger(__name__)

SERVICE = "CloudTrail"

REQUIRED_PERMISSIONS = ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"]


def collect(session, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return normalized CloudTrail state.

    ``trails_readable`` is the important field: when DescribeTrails fails, the
    rules must not conclude "no trail exists". Absence of data is not evidence
    of absence of a trail.
    """
    client = session.client("cloudtrail")
    errors: list[dict[str, Any]] = []
    trails: list[dict[str, Any]] = []
    region = getattr(session, "region_name", None)

    log.info("Starting CloudTrail collection")
    try:
        # Include shadow trails so a multi-region trail remains visible outside
        # its home region during per-region fleet scans.
        response = client.describe_trails(includeShadowTrails=True)
    except AWS_EXCEPTIONS as exc:
        record_error(
            errors,
            SERVICE,
            "cloudtrail:DescribeTrails",
            exc,
            required_permissions=["cloudtrail:DescribeTrails"],
        )
        return {"trails": [], "errors": errors, "trails_readable": False, "region": region}

    raw_trails = _deduplicate_trails(response.get("trailList", []), region)
    for raw in raw_trails:
        trails.append(_collect_trail(client, raw, errors))

    log.info("CloudTrail collection complete: %d trails", len(trails))
    return {"trails": trails, "errors": errors, "trails_readable": True, "region": region}


def _deduplicate_trails(raw_trails: list[dict[str, Any]], region: str | None):
    """Return one stable representative for each TrailARN/HomeRegion pair.

    AWS can include the same multi-region trail more than once when shadow
    trails are requested. Sort before selecting a representative so API
    response ordering cannot change the collected result.
    """
    ordered = sorted(
        raw_trails,
        key=lambda raw: (
            str(raw.get("TrailARN") or raw.get("Name") or ""),
            str(raw.get("HomeRegion") or region or ""),
            json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str),
        ),
    )
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for raw in ordered:
        identity = (
            str(raw.get("TrailARN") or raw.get("Name") or ""),
            str(raw.get("HomeRegion") or region or ""),
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(raw)
    return unique


def _collect_trail(client, raw: dict[str, Any], errors) -> dict[str, Any]:
    trail = normalize.trail(raw)
    identifier = trail["arn"] or trail["name"]

    status, outcome = safe_call(
        errors,
        trail["collection_errors"],
        SERVICE,
        "cloudtrail:GetTrailStatus",
        lambda: client.get_trail_status(Name=identifier),
        trail["name"],
        ["cloudtrail:GetTrailStatus"],
    )
    if outcome == OK:
        normalize.apply_status(trail, status)
    return trail
