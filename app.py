import asyncio
import ipaddress
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

try:
    from azure.identity.aio import DefaultAzureCredential
    from azure.storage.blob.aio import BlobServiceClient
    from azure.core.exceptions import ResourceNotFoundError
    _AZURE_BLOB_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency at import time
    DefaultAzureCredential = None  # type: ignore
    BlobServiceClient = None  # type: ignore
    ResourceNotFoundError = Exception  # type: ignore
    _AZURE_BLOB_AVAILABLE = False

logger = logging.getLogger("techops.adapter")

SMG_MCP_URL = os.getenv("SMG_MCP_URL", "https://smg-mcp.orangefield-2f3fdb87.westus3.azurecontainerapps.io/mcp")
SMG_API_KEY = os.getenv("SMG_API_KEY", "")
AUTOTASK_BASE_URL = os.getenv("AUTOTASK_BASE_URL", "").strip().rstrip("/")
AUTOTASK_USERNAME = os.getenv("AUTOTASK_USERNAME", "").strip()
AUTOTASK_SECRET = os.getenv("AUTOTASK_SECRET", "").strip()
AUTOTASK_INTEGRATION_CODE = os.getenv("AUTOTASK_INTEGRATION_CODE", "").strip()
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "20"))
STALE_HOURS = int(os.getenv("REFRESH_WINDOW_HOURS", "72"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "330"))
STATUS_LABELS_TTL_SECONDS = int(os.getenv("STATUS_LABELS_TTL_SECONDS", "21600"))
BLOB_ACCOUNT_URL = os.getenv("TECHOPS_BLOB_ACCOUNT_URL", "").strip()
BLOB_CONTAINER = os.getenv("TECHOPS_BLOB_CONTAINER", "techops").strip()
BLOB_LATEST_NAME = os.getenv("TECHOPS_BLOB_LATEST", "latest.json").strip()
BLOB_WRITE_HISTORY = os.getenv("TECHOPS_BLOB_WRITE_HISTORY", "true").lower() in {"1", "true", "yes", "on"}
SCHEDULE_ENABLED = os.getenv("TECHOPS_SCHEDULE_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
SCHEDULE_INTERVAL_SECONDS = int(os.getenv("TECHOPS_SCHEDULE_INTERVAL_SECONDS", str(30 * 60)))
SCHEDULE_START_HOUR = int(os.getenv("TECHOPS_SCHEDULE_START_HOUR", "6"))
SCHEDULE_END_HOUR = int(os.getenv("TECHOPS_SCHEDULE_END_HOUR", "18"))
REFRESH_TOKEN = os.getenv("TECHOPS_REFRESH_TOKEN", "").strip()
ENFORCE_IP_ALLOWLIST = os.getenv("ENFORCE_IP_ALLOWLIST", "true").lower() in {"1", "true", "yes", "on"}
TECHOPS_ALLOWED_IPS_RAW = os.getenv("TECHOPS_ALLOWED_IPS", "")
BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_FILE = BASE_DIR / "tech-ops-command-center.html"

OPEN_STATUS_EXCLUDE = {5}
FOCUS_TECH_HINTS = ["tim l", "julie c", "tom m", "kevin"]
WAITING_STATUS_KEYWORDS = [
    "waiting customer",
    "waiting on customer",
    "waiting vendor",
    "waiting on vendor",
    "waiting third party",
    "waiting",
]
NETWORK_KEYWORDS = [
    "network",
    "internet",
    "wan",
    "wifi",
    "wireless",
    "switch",
    "router",
    "firewall",
    "vpn",
    "connectivity",
    "packet loss",
    "latency",
    "isp",
]
OFFLINE_KEYWORDS = [
    "offline",
    "device offline",
    "workstation offline",
    "server offline",
    "pc offline",
    "computer offline",
    "host offline",
    "down",
    "not reporting",
    "disconnected",
    "unreachable",
]
PACIFIC_TZ = ZoneInfo("America/Los_Angeles")

app = FastAPI(title="TechOps Azure Adapter", version="1.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
)

LAST_GOOD_PAYLOAD: Optional[Dict[str, Any]] = None
MCP_SESSION_ID: Optional[str] = None
ALLOWED_NETWORKS: List[ipaddress._BaseNetwork] = []
TICKET_STATUS_LABELS: Dict[int, str] = {}
TICKET_STATUS_LABELS_LOADED_AT: Optional[datetime] = None
BLOB_CLIENT: Optional["BlobServiceClient"] = None
BLOB_CREDENTIAL: Optional["DefaultAzureCredential"] = None
REFRESH_LOCK = asyncio.Lock()
SCHEDULER_TASK: Optional[asyncio.Task] = None


def parse_allowed_networks(raw: str) -> List[ipaddress._BaseNetwork]:
    entries = [x.strip() for x in raw.split(",") if x.strip()]
    networks: List[ipaddress._BaseNetwork] = []
    for entry in entries:
        try:
            if "/" in entry:
                networks.append(ipaddress.ip_network(entry, strict=False))
            else:
                ip = ipaddress.ip_address(entry)
                suffix = "/32" if ip.version == 4 else "/128"
                networks.append(ipaddress.ip_network(f"{entry}{suffix}", strict=False))
        except ValueError:
            continue
    return networks


ALLOWED_NETWORKS = parse_allowed_networks(TECHOPS_ALLOWED_IPS_RAW)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def payload_is_fresh(payload: Optional[Dict[str, Any]], now: datetime) -> bool:
    if not payload:
        return False
    meta = payload.get("meta") if isinstance(payload, dict) else None
    generated_at = parse_dt(meta.get("generatedAt")) if isinstance(meta, dict) else None
    if generated_at is None:
        return False
    return (now - generated_at).total_seconds() <= CACHE_TTL_SECONDS


def to_iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(s)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def request_ip(request: Request) -> Optional[ipaddress._BaseAddress]:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        first = xff.split(",")[0].strip()
        try:
            return ipaddress.ip_address(first)
        except ValueError:
            pass
    xrip = request.headers.get("x-real-ip", "").strip()
    if xrip:
        try:
            return ipaddress.ip_address(xrip)
        except ValueError:
            pass
    client_host = request.client.host if request.client else ""
    if client_host:
        try:
            return ipaddress.ip_address(client_host)
        except ValueError:
            return None
    return None


def enforce_office_ip(request: Request) -> None:
    if not ENFORCE_IP_ALLOWLIST:
        return
    if not ALLOWED_NETWORKS:
        raise HTTPException(status_code=403, detail="IP allowlist is enabled but TECHOPS_ALLOWED_IPS is not configured.")
    ip = request_ip(request)
    if ip is None:
        raise HTTPException(status_code=403, detail="Unable to determine client IP.")
    if not any(ip in net for net in ALLOWED_NETWORKS):
        raise HTTPException(status_code=403, detail=f"Client IP {ip} is not authorized.")


def parse_content(result: Any) -> Any:
    if isinstance(result, dict) and isinstance(result.get("content"), list) and result["content"]:
        first = result["content"][0]
        text = first.get("text") if isinstance(first, dict) else None
        if isinstance(text, str):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
    if isinstance(result, str):
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return result
    return result


def coerce_items(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if isinstance(raw, dict):
        for key in ("items", "results", "data", "tickets", "resources", "rows", "records"):
            if isinstance(raw.get(key), list):
                return [x for x in raw[key] if isinstance(x, dict)]
    return []


def normalize_next_page_path(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        path = parsed.path
        if parsed.query:
            path = f"{path}?{parsed.query}"
    else:
        path = raw
    marker = "/atservicesrest/v1.0/"
    if marker in path:
        path = path.split(marker, 1)[1]
    return path.lstrip("/")


def direct_autotask_enabled() -> bool:
    return all(
        (
            AUTOTASK_BASE_URL,
            AUTOTASK_USERNAME,
            AUTOTASK_SECRET,
            AUTOTASK_INTEGRATION_CODE,
        )
    )


def current_data_source() -> str:
    if direct_autotask_enabled():
        return "LIVE_AUTOTASK_DIRECT"
    return "LIVE_AZURE_AUTOTASK"


def resource_display_name(resource: Dict[str, Any]) -> str:
    full = str(resource.get("fullName") or "").strip()
    if full:
        return full
    first = str(resource.get("firstName") or "").strip()
    last = str(resource.get("lastName") or "").strip()
    combined = f"{first} {last}".strip()
    if combined:
        return combined
    user = str(resource.get("userName") or "").strip()
    if user:
        return user
    rid = resource.get("id")
    return f"Resource {rid}" if rid is not None else "Unassigned"


def status_id(ticket: Dict[str, Any]) -> Optional[int]:
    raw = ticket.get("status")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def is_open_ticket(ticket: Dict[str, Any]) -> bool:
    sid = status_id(ticket)
    if sid is not None:
        return sid not in OPEN_STATUS_EXCLUDE
    return parse_dt(ticket.get("resolvedDateTime")) is None


def pct(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 100.0
    return max(0.0, min(100.0, (numerator / denominator) * 100.0))


def parse_number(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    text = text.replace("%", "").replace(",", "")
    try:
        return float(text)
    except ValueError:
        return None


def week_start_string(now: datetime) -> str:
    local_now = now.astimezone(PACIFIC_TZ)
    monday = local_now.date() - timedelta(days=local_now.weekday())
    return monday.isoformat()


def ticket_created_dt(ticket: Dict[str, Any]) -> Optional[datetime]:
    return parse_dt(ticket.get("createDateTime")) or parse_dt(ticket.get("createDate"))


def ticket_last_activity_dt(ticket: Dict[str, Any]) -> Optional[datetime]:
    return parse_dt(ticket.get("lastActivityDate")) or ticket_created_dt(ticket)


def assigned_resource_id(ticket: Dict[str, Any]) -> int:
    raw = ticket.get("assignedResourceID")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def select_focus_resources(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Tuple[Dict[str, Any], str]] = []
    for r in resources:
        normalized.append((r, normalize_name(resource_display_name(r))))

    used_ids: set[int] = set()
    selected: List[Dict[str, Any]] = []
    for hint in FOCUS_TECH_HINTS:
        hint_n = normalize_name(hint)
        candidate: Optional[Dict[str, Any]] = None
        for r, n in normalized:
            rid = r.get("id")
            try:
                rid_int = int(rid)
            except (TypeError, ValueError):
                continue
            if rid_int in used_ids:
                continue
            if n.startswith(hint_n) or f" {hint_n}" in n or hint_n in n:
                candidate = r
                used_ids.add(rid_int)
                break
        if candidate is not None:
            selected.append({"hint": hint, "id": int(candidate["id"]), "name": resource_display_name(candidate)})
        else:
            selected.append({"hint": hint, "id": None, "name": hint.title()})
    return selected


def ticket_account_id(ticket: Dict[str, Any]) -> str:
    for key in ("accountID", "companyID", "accountId", "companyId"):
        val = ticket.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return "unknown"


def ticket_account_name(ticket: Dict[str, Any]) -> str:
    for key in ("accountName", "companyName", "account", "company"):
        val = ticket.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    aid = ticket_account_id(ticket)
    return f"Client {aid}"


def ticket_text_field(ticket: Dict[str, Any]) -> str:
    for key in ("title", "issueDescription", "description", "problemDescription", "summary"):
        val = ticket.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def ticket_status_text(ticket: Dict[str, Any]) -> str:
    for key in ("statusName", "statusLabel", "statusText", "ticketStatus", "statusDisplayName"):
        val = ticket.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    raw = ticket.get("status")
    if raw is None:
        return ""
    raw_str = str(raw).strip()
    if not raw_str:
        return ""
    try:
        status_id = int(raw_str)
    except (TypeError, ValueError):
        return raw_str
    label = TICKET_STATUS_LABELS.get(status_id)
    return label if label else raw_str


def is_waiting_status(ticket: Dict[str, Any]) -> bool:
    status_text = ticket_status_text(ticket).lower()
    if not status_text:
        return False
    return any(keyword in status_text for keyword in WAITING_STATUS_KEYWORDS)


def issue_signature(ticket: Dict[str, Any]) -> str:
    raw = ticket_text_field(ticket)
    if not raw:
        return ""
    cleaned = re.sub(r"\s+", " ", raw.lower())
    cleaned = re.sub(r"[^a-z0-9 ]+", " ", cleaned)
    words = [w for w in cleaned.split(" ") if w]
    stop = {"the", "and", "for", "with", "from", "this", "that", "user", "client", "site", "issue"}
    words = [w for w in words if w not in stop]
    if not words:
        return ""
    return " ".join(words[:6]).upper()


def network_issue_signature(ticket: Dict[str, Any]) -> str:
    raw = ticket_text_field(ticket)
    if not raw:
        return ""
    cleaned = re.sub(r"\s+", " ", raw.lower())
    cleaned = re.sub(r"[^a-z0-9 ]+", " ", cleaned)
    words = [w for w in cleaned.split(" ") if w]
    if not words:
        return ""
    for keyword in NETWORK_KEYWORDS:
        if keyword.replace(" ", "") in cleaned.replace(" ", "") or keyword in cleaned:
            return " ".join(words[:6]).upper()
    return ""


def offline_issue_signature(ticket: Dict[str, Any]) -> str:
    raw = ticket_text_field(ticket)
    if not raw:
        return ""
    cleaned = re.sub(r"\s+", " ", raw.lower())
    for keyword in OFFLINE_KEYWORDS:
        if keyword in cleaned:
            return cleaned
    return ""


def ticket_number(ticket: Dict[str, Any]) -> str:
    for key in ("ticketNumber", "ticketID", "id"):
        val = ticket.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return "UNKNOWN"


def open_duration_text(ticket: Dict[str, Any], now: datetime) -> str:
    created = ticket_created_dt(ticket) or ticket_last_activity_dt(ticket)
    if not created:
        return "00h 00m"
    delta = max(0, int((now - created).total_seconds()))
    hours = delta // 3600
    minutes = (delta % 3600) // 60
    return f"{hours:02d}h {minutes:02d}m"


def duration_text_from_datetime(start: Optional[datetime], now: datetime) -> str:
    if start is None:
        return "00h 00m"
    delta = max(0, int((now - start).total_seconds()))
    hours = delta // 3600
    minutes = (delta % 3600) // 60
    return f"{hours:02d}h {minutes:02d}m"


def is_p0_ticket(ticket: Dict[str, Any]) -> bool:
    if not is_open_ticket(ticket):
        return False
    raw_priority = ticket.get("priority")
    try:
        p = int(raw_priority)
        if p <= 1:
            return True
    except (TypeError, ValueError):
        pass
    title = ticket_text_field(ticket).lower()
    p0_keywords = ["full outage", "outage", "system down", "network down", "offline", "service down", "major incident"]
    return any(k in title for k in p0_keywords)


ALERT_SOURCE_KEYWORDS = ("alert", "monitoring", "datto rmm", "kaseya", "ninja", "auvik", "connectwise automate")
ALERT_TITLE_PREFIXES = ("[alert]", "alert:", "[monitoring]", "monitoring:", "[rmm]", "rmm:")


def is_alert_ticket(ticket: Dict[str, Any]) -> bool:
    for key in ("source", "sourceName", "sourceLabel", "sourceText"):
        val = str(ticket.get(key) or "").lower()
        if any(k in val for k in ALERT_SOURCE_KEYWORDS):
            return True
    issue = str(ticket.get("issueType") or "").lower()
    sub_issue = str(ticket.get("subIssueType") or "").lower()
    if "alert" in issue or "monitoring" in issue:
        return True
    if "alert" in sub_issue or "monitoring" in sub_issue:
        return True
    title = ticket_text_field(ticket).lower()
    if any(title.startswith(prefix) for prefix in ALERT_TITLE_PREFIXES):
        return True
    return False


def day_start_at_7am(now: datetime) -> datetime:
    local_now = now.astimezone(PACIFIC_TZ)
    start_local = local_now.replace(hour=7, minute=0, second=0, microsecond=0)
    if local_now < start_local:
        start_local = start_local - timedelta(days=1)
    return start_local.astimezone(timezone.utc)


def build_day_progress(
    recent_tickets: List[Dict[str, Any]],
    resolved_tickets: List[Dict[str, Any]],
    now: datetime,
) -> Dict[str, Any]:
    start = day_start_at_7am(now)
    bucket_minutes = 15
    bucket_sec = bucket_minutes * 60
    elapsed_min = max(0, int((now - start).total_seconds() // 60))
    num_buckets = max(1, (elapsed_min // bucket_minutes) + 1)

    incoming_counts = [0] * num_buckets
    resolved_counts = [0] * num_buckets

    for ticket in recent_tickets:
        if is_alert_ticket(ticket):
            continue
        created = ticket_created_dt(ticket)
        if created is None or created < start or created > now:
            continue
        idx = int((created - start).total_seconds() // bucket_sec)
        if 0 <= idx < num_buckets:
            incoming_counts[idx] += 1

    for ticket in resolved_tickets:
        if is_alert_ticket(ticket):
            continue
        resolved_at = parse_dt(ticket.get("resolvedDateTime"))
        if resolved_at is None or resolved_at < start or resolved_at > now:
            continue
        idx = int((resolved_at - start).total_seconds() // bucket_sec)
        if 0 <= idx < num_buckets:
            resolved_counts[idx] += 1

    incoming_series: List[Dict[str, int]] = []
    resolved_series: List[Dict[str, int]] = []
    cum_in = 0
    cum_out = 0
    for i in range(num_buckets):
        cum_in += incoming_counts[i]
        cum_out += resolved_counts[i]
        incoming_series.append({"m": i * bucket_minutes, "v": cum_in})
        resolved_series.append({"m": i * bucket_minutes, "v": cum_out})

    return {
        "startIso": to_iso_z(start),
        "nowIso": to_iso_z(now),
        "bucketMinutes": bucket_minutes,
        "elapsedMinutes": elapsed_min,
        "incoming": incoming_series,
        "resolved": resolved_series,
        "incomingTotal": cum_in,
        "resolvedTotal": cum_out,
    }


def build_network_traffic(tickets: List[Dict[str, Any]], now: datetime) -> List[Dict[str, int]]:
    buckets = [0 for _ in range(20)]
    window_hours = 72
    start = now - timedelta(hours=window_hours)
    span_seconds = window_hours * 3600
    for t in tickets:
        if not network_issue_signature(t):
            continue
        created = ticket_created_dt(t) or ticket_last_activity_dt(t)
        if created is None or created < start or created > now:
            continue
        elapsed = (created - start).total_seconds()
        idx = int((elapsed / span_seconds) * 20)
        idx = max(0, min(19, idx))
        buckets[idx] += 1
    return [{"t": i, "v": buckets[i]} for i in range(20)]


def local_date_string(now: datetime) -> str:
    return now.astimezone(PACIFIC_TZ).strftime("%Y-%m-%d")


def build_time_entry_hours(entries: List[Dict[str, Any]]) -> Dict[int, float]:
    totals: Dict[int, float] = {}
    for entry in entries:
        rid = entry.get("resourceID")
        try:
            rid_int = int(rid)
        except (TypeError, ValueError):
            continue
        hours = float(entry.get("hoursWorked") or 0.0)
        totals[rid_int] = round(totals.get(rid_int, 0.0) + hours, 2)
    return totals


def utilization_pct_from_hours(hours: float) -> int:
    return max(0, min(100, int(round((hours / 8.0) * 100.0))))


def utilization_color(utilization_pct: int) -> str:
    if utilization_pct < 20:
        return "#ef4444"
    if utilization_pct < 60:
        return "#f59e0b"
    if utilization_pct >= 80:
        return "#10b981"
    return "#60a5fa"


async def fetch_utilization_summary(now: datetime) -> List[Dict[str, Any]]:
    raw = await call_tool(
        "reporting_get_utilization_summary",
        {
            "week_start": week_start_string(now),
        },
    )
    return coerce_items(raw)


def utilization_pct_from_summary_row(row: Dict[str, Any]) -> Optional[int]:
    percent_keys = (
        "utilizationPct",
        "utilizationPercent",
        "utilization_pct",
        "billableUtilizationPct",
        "billableUtilizationPercent",
        "billable_pct",
        "pct",
        "percent",
        "utilization",
    )
    for key in percent_keys:
        value = parse_number(row.get(key))
        if value is None:
            continue
        if value <= 1:
            value *= 100.0
        return max(0, min(100, int(round(value))))

    numerators = (
        "billableHours",
        "billable_hours",
        "hoursBillable",
        "productiveHours",
        "hoursWorked",
    )
    denominators = (
        "targetHours",
        "capacityHours",
        "availableHours",
        "scheduledHours",
        "workHours",
    )
    numerator = next((parse_number(row.get(key)) for key in numerators if parse_number(row.get(key)) is not None), None)
    denominator = next((parse_number(row.get(key)) for key in denominators if parse_number(row.get(key)) is not None), None)
    if numerator is None or denominator is None or denominator <= 0:
        return None
    return max(0, min(100, int(round((numerator / denominator) * 100.0))))


def build_utilization_map(focus_resources: List[Dict[str, Any]], summary_rows: List[Dict[str, Any]]) -> Dict[int, int]:
    by_name: Dict[str, int] = {}
    by_id: Dict[int, int] = {}
    for row in summary_rows:
        utilization_pct = utilization_pct_from_summary_row(row)
        if utilization_pct is None:
            continue
        for key in ("resourceID", "resourceId", "id"):
            raw_id = row.get(key)
            try:
                by_id[int(raw_id)] = utilization_pct
                break
            except (TypeError, ValueError):
                continue
        for key in ("resourceName", "resource", "resource_name", "fullName", "name"):
            raw_name = row.get(key)
            if raw_name is not None and str(raw_name).strip():
                by_name[normalize_name(str(raw_name))] = utilization_pct
                break

    resolved: Dict[int, int] = {}
    for focus in focus_resources:
        rid = focus.get("id")
        if rid is None:
            continue
        rid_int = int(rid)
        if rid_int in by_id:
            resolved[rid_int] = by_id[rid_int]
            continue
        name = normalize_name(str(focus.get("name") or ""))
        if name and name in by_name:
            resolved[rid_int] = by_name[name]
    return resolved


def count_waiting_customer_tickets(open_tickets: List[Dict[str, Any]]) -> int:
    count = 0
    for ticket in open_tickets:
        status_text = ticket_status_text(ticket).lower()
        if "waiting customer" in status_text or "waiting on customer" in status_text:
            count += 1
    return count


def count_past_due_active_tickets(open_tickets: List[Dict[str, Any]], now: datetime) -> int:
    count = 0
    for ticket in open_tickets:
        if is_waiting_status(ticket):
            continue
        due = (
            parse_dt(ticket.get("dueDateTime"))
            or parse_dt(ticket.get("resolutionPlanDateTime"))
            or parse_dt(ticket.get("firstResponseDueDateTime"))
        )
        if due is not None and due < now:
            count += 1
    return count


def build_target_summary(
    focus_resources: List[Dict[str, Any]],
    hours_by_id: Dict[int, float],
    utilization_by_id: Dict[int, int],
) -> Dict[str, float]:
    tracked_ids = [int(x["id"]) for x in focus_resources if x.get("id") is not None]
    if not tracked_ids:
        return {"dayPct": 0.0, "weekPct": 0.0}

    today_values = [utilization_pct_from_hours(hours_by_id.get(rid, 0.0)) for rid in tracked_ids]
    week_values = [float(utilization_by_id.get(rid, utilization_pct_from_hours(hours_by_id.get(rid, 0.0)))) for rid in tracked_ids]
    day_pct = round(sum(today_values) / len(today_values), 1) if today_values else 0.0
    week_pct = round(sum(week_values) / len(week_values), 1) if week_values else 0.0
    return {"dayPct": day_pct, "weekPct": week_pct}


def build_labor(
    recent_tickets: List[Dict[str, Any]], now: datetime
) -> Tuple[List[Dict[str, float]], Dict[str, float]]:
    weekdays = ["MON", "TUE", "WED", "THU", "FRI"]
    opened_by_day: Dict[str, int] = {d: 0 for d in weekdays}
    resolved_by_day: Dict[str, int] = {d: 0 for d in weekdays}

    recent_cutoff = now - timedelta(days=14)
    for t in recent_tickets:
        created = ticket_created_dt(t)
        if created and created >= recent_cutoff:
            d = created.strftime("%a").upper()[:3]
            if d in opened_by_day:
                opened_by_day[d] += 1
        resolved = parse_dt(t.get("resolvedDateTime"))
        if resolved and resolved >= recent_cutoff:
            d = resolved.strftime("%a").upper()[:3]
            if d in resolved_by_day:
                resolved_by_day[d] += 1

    labor = [{"n": d, "b": float(resolved_by_day[d]), "i": float(opened_by_day[d])} for d in weekdays]

    today_key = now.strftime("%a").upper()[:3]
    day_open = float(opened_by_day.get(today_key, 0))
    day_resolved = float(resolved_by_day.get(today_key, 0))
    week_open = float(sum(opened_by_day.values()))
    week_resolved = float(sum(resolved_by_day.values()))

    targets = {
        "dayPct": round(pct(day_resolved, day_open if day_open > 0 else max(day_resolved, 1.0)), 1),
        "weekPct": round(pct(week_resolved, week_open if week_open > 0 else max(week_resolved, 1.0)), 1),
    }
    return labor, targets


def count_stale_tickets(open_tickets: List[Dict[str, Any]], now: datetime) -> int:
    stale_seconds = STALE_HOURS * 3600
    count = 0
    for t in open_tickets:
        dt = ticket_last_activity_dt(t)
        if not dt:
            continue
        if (now - dt).total_seconds() > stale_seconds:
            count += 1
    return count


def compute_sla_compliance(recent_tickets: List[Dict[str, Any]], now: datetime) -> Tuple[float, int]:
    met = 0
    sample = 0
    for t in recent_tickets:
        raw = t.get("serviceLevelAgreementHasBeenMet")
        interpreted: Optional[bool] = None
        if isinstance(raw, bool):
            interpreted = raw
        elif isinstance(raw, str):
            val = raw.strip().lower()
            if val in {"true", "1", "yes"}:
                interpreted = True
            elif val in {"false", "0", "no"}:
                interpreted = False

        if interpreted is None:
            due = (
                parse_dt(t.get("resolutionPlanDateTime"))
                or parse_dt(t.get("dueDateTime"))
                or parse_dt(t.get("firstResponseDueDateTime"))
            )
            if due is not None:
                resolved = parse_dt(t.get("resolvedDateTime"))
                if resolved is not None:
                    interpreted = resolved <= due
                elif is_open_ticket(t):
                    interpreted = now <= due

        if interpreted is None:
            continue
        sample += 1
        if interpreted:
            met += 1

    if sample == 0:
        return 0.0, 0
    return round((met / sample) * 100.0, 1), sample


def compute_avg_response_minutes(recent_tickets: List[Dict[str, Any]]) -> Optional[int]:
    values: List[float] = []
    max_minutes = 60 * 24 * 7
    for t in recent_tickets:
        raw = t.get("firstResponseTime")
        if raw is None:
            continue
        try:
            minutes = float(raw)
        except (TypeError, ValueError):
            continue
        if minutes <= 0 or minutes > max_minutes:
            continue
        values.append(minutes)
    if not values:
        return None
    return int(round(sum(values) / len(values)))


def build_focus_technicians(
    open_tickets: List[Dict[str, Any]],
    focus_resources: List[Dict[str, Any]],
    hours_by_id: Dict[int, float],
    utilization_by_id: Dict[int, int],
    now: datetime,
    recent_tickets: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    open_by_id: Dict[int, int] = {}
    stale_by_id: Dict[int, int] = {}
    waiting_cust_by_id: Dict[int, int] = {}
    past_due_by_id: Dict[int, int] = {}
    stale_seconds = STALE_HOURS * 3600

    for t in open_tickets:
        rid_int = assigned_resource_id(t)
        open_by_id[rid_int] = open_by_id.get(rid_int, 0) + 1
        last_dt = ticket_last_activity_dt(t)
        if last_dt and (now - last_dt).total_seconds() > stale_seconds:
            stale_by_id[rid_int] = stale_by_id.get(rid_int, 0) + 1
        status_text = ticket_status_text(t).lower()
        if "waiting customer" in status_text or "waiting on customer" in status_text:
            waiting_cust_by_id[rid_int] = waiting_cust_by_id.get(rid_int, 0) + 1
        if not is_waiting_status(t):
            due = (
                parse_dt(t.get("dueDateTime"))
                or parse_dt(t.get("resolutionPlanDateTime"))
                or parse_dt(t.get("firstResponseDueDateTime"))
            )
            if due is not None and due < now:
                past_due_by_id[rid_int] = past_due_by_id.get(rid_int, 0) + 1

    per_tech_recent: Dict[int, List[Dict[str, Any]]] = {}
    if recent_tickets:
        for t in recent_tickets:
            rid_int = assigned_resource_id(t)
            per_tech_recent.setdefault(rid_int, []).append(t)

    roster: List[Dict[str, Any]] = []
    for focus in focus_resources:
        rid = focus.get("id")
        if rid is None:
            roster.append(
                {
                    "name": focus.get("name", "Unknown"),
                    "state": "MISSING",
                    "openTickets": 0,
                    "staleTickets": 0,
                    "waitingCustomer": 0,
                    "pastDueActive": 0,
                    "slaPct": 0.0,
                    "slaSample": 0,
                    "avgResponseMinutes": None,
                    "utilizationPct": 0,
                    "utilizationColor": "#ef4444",
                    "hoursWorkedToday": 0.0,
                }
            )
            continue
        rid_int = int(rid)
        open_count = open_by_id.get(rid_int, 0)
        stale_count = stale_by_id.get(rid_int, 0)
        waiting_cust = waiting_cust_by_id.get(rid_int, 0)
        past_due = past_due_by_id.get(rid_int, 0)
        tech_recent = per_tech_recent.get(rid_int, [])
        sla_pct, sla_sample = compute_sla_compliance(tech_recent, now)
        avg_response = compute_avg_response_minutes(tech_recent)
        hours_worked = round(hours_by_id.get(rid_int, 0.0), 2)
        utilization_pct = utilization_by_id.get(rid_int, utilization_pct_from_hours(hours_worked))
        if open_count >= 12:
            state = "OVERLOAD"
        elif stale_count > 0:
            state = "WATCH"
        elif open_count == 0:
            state = "IDLE"
        else:
            state = "ACTIVE"
        roster.append(
            {
                "name": focus.get("name", "Unknown"),
                "state": state,
                "openTickets": open_count,
                "staleTickets": stale_count,
                "waitingCustomer": waiting_cust,
                "pastDueActive": past_due,
                "slaPct": sla_pct,
                "slaSample": sla_sample,
                "avgResponseMinutes": avg_response,
                "utilizationPct": utilization_pct,
                "utilizationColor": utilization_color(utilization_pct),
                "hoursWorkedToday": hours_worked,
            }
        )

    return roster


def build_ticket_mix(
    focus_resources: List[Dict[str, Any]],
    focus_open_tickets: List[Dict[str, Any]],
    focus_recent_tickets: List[Dict[str, Any]],
    now: datetime,
) -> List[Dict[str, Any]]:
    recent_cutoff = now - timedelta(days=14)
    open_by_id: Dict[int, int] = {}
    resolved_by_id: Dict[int, int] = {}
    for ticket in focus_open_tickets:
        rid = assigned_resource_id(ticket)
        open_by_id[rid] = open_by_id.get(rid, 0) + 1
    for ticket in focus_recent_tickets:
        resolved = parse_dt(ticket.get("resolvedDateTime"))
        if resolved is None or resolved < recent_cutoff:
            continue
        rid = assigned_resource_id(ticket)
        resolved_by_id[rid] = resolved_by_id.get(rid, 0) + 1

    total_open = max(1, sum(open_by_id.values()))
    total_resolved = max(1, sum(resolved_by_id.values()))
    rows: List[Dict[str, Any]] = []
    for focus in focus_resources:
        rid = focus.get("id")
        if rid is None:
            continue
        rid_int = int(rid)
        open_count = open_by_id.get(rid_int, 0)
        resolved_count = resolved_by_id.get(rid_int, 0)
        rows.append(
            {
                "name": focus.get("name", "Unknown"),
                "openCount": open_count,
                "resolvedCount": resolved_count,
                "openPct": round((open_count / total_open) * 100.0, 1),
                "resolvedPct": round((resolved_count / total_resolved) * 100.0, 1),
            }
        )
    return rows


def build_ttr_by_tech(focus_resources: List[Dict[str, Any]], focus_recent_tickets: List[Dict[str, Any]], now: datetime) -> List[Dict[str, Any]]:
    today_local = now.astimezone(PACIFIC_TZ).date()
    totals: Dict[int, float] = {}
    counts: Dict[int, int] = {}
    for ticket in focus_recent_tickets:
        resolved = parse_dt(ticket.get("resolvedDateTime"))
        created = ticket_created_dt(ticket)
        if resolved is None or created is None:
            continue
        if resolved.astimezone(PACIFIC_TZ).date() != today_local:
            continue
        delta_minutes = (resolved - created).total_seconds() / 60.0
        if delta_minutes < 0:
            continue
        rid = assigned_resource_id(ticket)
        totals[rid] = totals.get(rid, 0.0) + delta_minutes
        counts[rid] = counts.get(rid, 0) + 1

    rows: List[Dict[str, Any]] = []
    for focus in focus_resources:
        rid = focus.get("id")
        if rid is None:
            continue
        rid_int = int(rid)
        avg_minutes = round(totals.get(rid_int, 0.0) / counts[rid_int], 1) if counts.get(rid_int, 0) else 0.0
        rows.append(
            {
                "name": focus.get("name", "Unknown"),
                "minutes": avg_minutes,
                "label": f"{avg_minutes:.0f}m" if avg_minutes > 0 else "N/A",
                "count": counts.get(rid_int, 0),
            }
        )
    return rows


def build_nodes(technicians: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    nodes: List[Dict[str, str]] = []
    for tech in technicians[:14]:
        warn = str(tech.get("state")) in {"WATCH", "OVERLOAD"}
        nodes.append({"s": "w" if warn else "u"})
    while len(nodes) < 14:
        nodes.append({"s": "u"})
    return nodes


def build_kpis(
    sla_pct: float,
    avg_response_minutes: Optional[int],
    open_count: int,
    stale_count: int,
    waiting_customer_count: int,
    past_due_count: int,
    rc_metrics: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, str]]:
    avg_text = f"{avg_response_minutes}m" if avg_response_minutes is not None else "N/A"
    rc = rc_metrics or {}
    received = int(rc.get("receivedToday", 0) or 0)
    missed_calls = int(rc.get("inboundMissedToday", rc.get("missedToday", 0)) or 0)
    pct_taken = float(rc.get("pctCallsTakenToday", 0.0) or 0.0)
    return [
        {"l": "SLA COMPLIANCE", "v": f"{sla_pct:.1f}%", "c": "#10b981"},
        {"l": "AVG RESPONSE", "v": avg_text, "c": "#60a5fa"},
        {"l": "OPEN TICKETS", "v": str(open_count), "c": "#f59e0b"},
        {"l": "WAITING CUSTOMER", "v": str(waiting_customer_count), "c": "#facc15"},
        {"l": "PAST DUE ACTIVE", "v": str(past_due_count), "c": "#fb7185"},
        {"l": "STALE TICKETS", "v": str(stale_count), "c": "#f43f5e"},
        {"l": "RC RECEIVED (TODAY)", "v": str(received), "c": "#38bdf8"},
        {"l": "RC MISSED (TODAY)", "v": str(missed_calls), "c": "#ef4444"},
        {"l": "RC % CALLS TAKEN", "v": f"{pct_taken:.1f}%", "c": "#22c55e"},
    ]


def build_ops_lines(open_count: int, stale_count: int, sla_sample: int, tech_count: int, source: str) -> List[str]:
    return [
        f"> [AT] SOURCE: {source}",
        f"> [AT] OPEN={open_count} STALE={stale_count}",
        f"> [AT] SLA SAMPLE SIZE: {sla_sample}",
        f"> [AT] TECHS ASSIGNED: {tech_count}",
    ]


def parse_ringcentral_payload(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}


async def fetch_ringcentral_call_metrics(today: datetime) -> Dict[str, Any]:
    start_of_day = today.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    raw = await call_tool(
        "rc_api_request",
        {
            "method": "GET",
            "url_path": f"/account/~/extension/~/call-log?view=Simple&dateFrom={to_iso_z(start_of_day)}&perPage=100",
        },
    )
    payload = parse_ringcentral_payload(raw)
    records = payload.get("records") if isinstance(payload.get("records"), list) else []
    total_calls = 0
    answered = 0
    missed = 0
    inbound_taken = 0
    inbound_received = 0
    inbound_missed = 0
    outbound_made = 0
    on_phone_minutes = 0
    for record in records:
        if not isinstance(record, dict):
            continue
        if str(record.get("type") or "").lower() != "voice":
            continue
        total_calls += 1
        result = str(record.get("result") or "").lower()
        action = str(record.get("action") or "").lower()
        direction = str(record.get("direction") or "").lower()
        on_phone_minutes += int(round(float(record.get("duration") or 0) / 60.0))
        if direction == "outbound":
            outbound_made += 1
        elif direction == "inbound":
            inbound_received += 1
            if "connected" in result or "accepted" in result or "phone call" in action:
                inbound_taken += 1
            if "missed" in result:
                inbound_missed += 1
        if "missed" in result:
            missed += 1
        elif "connected" in result or "accepted" in result or ("phone call" in action and direction == "inbound"):
            answered += 1

    pct_calls_taken = (
        round((inbound_taken / inbound_received) * 100.0, 1)
        if inbound_received > 0
        else 0.0
    )

    extension_name = ""
    if records and isinstance(records[0], dict):
        to_name = records[0].get("to", {}).get("name") if isinstance(records[0].get("to"), dict) else None
        from_name = records[0].get("from", {}).get("name") if isinstance(records[0].get("from"), dict) else None
        extension_name = str(to_name or from_name or "").strip()

    return {
        "totalToday": total_calls,
        "answeredToday": answered,
        "missedToday": missed,
        "inboundTakenToday": inbound_taken,
        "receivedToday": inbound_received,
        "inboundMissedToday": inbound_missed,
        "pctCallsTakenToday": pct_calls_taken,
        "outboundMadeToday": outbound_made,
        "onPhoneMinutesToday": on_phone_minutes,
        "abandonedToday": missed,
        "lineName": extension_name or "Current RC Extension",
        "healthy": True,
    }


def fallback_ringcentral_call_metrics() -> Dict[str, Any]:
    return {
        "totalToday": 0,
        "answeredToday": 0,
        "missedToday": 0,
        "inboundTakenToday": 0,
        "receivedToday": 0,
        "inboundMissedToday": 0,
        "pctCallsTakenToday": 0.0,
        "outboundMadeToday": 0,
        "onPhoneMinutesToday": 0,
        "abandonedToday": 0,
        "lineName": "Current RC Extension",
        "healthy": False,
    }


def build_console_lines(
    generated_at: str,
    source: str,
    status: str,
    open_count: int,
    stale_count: int,
    sla_sample: int,
    tech_count: int,
    rc: Dict[str, Any],
) -> List[str]:
    rc_line = rc.get("lineName", "Current RC Extension")
    return [
        f"> [SRC] {source} | {status}",
        "> [AT] DATA: GREEN",
        f"> [AT] LAST REFRESH: {generated_at}",
        f"> [AT] OPEN={open_count} STALE={stale_count} SLA_SAMPLE={sla_sample}",
        f"> [AT] FOCUS TECHS TRACKED: {tech_count}",
        f"> [RC] LINE: {rc_line}",
        f"> [RC] FEED: {'GREEN' if rc.get('healthy') else 'DEGRADED'}",
        f"> [RC] TOTAL TODAY: {rc.get('totalToday', 0)}",
        f"> [RC] TAKEN: {rc.get('inboundTakenToday', 0)} MADE: {rc.get('outboundMadeToday', 0)}",
        f"> [RC] ON PHONE TODAY: {rc.get('onPhoneMinutesToday', 0)} MIN",
        f"> [RC] TECH ANSWERED: {rc.get('answeredToday', 0)} ABANDONED: {rc.get('abandonedToday', 0)}",
    ]


def build_network_status(open_tickets: List[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    groups: Dict[str, Dict[str, Any]] = {}
    for ticket in open_tickets:
        if not offline_issue_signature(ticket):
            continue
        account_id = ticket_account_id(ticket)
        created = ticket_created_dt(ticket) or ticket_last_activity_dt(ticket)
        group = groups.setdefault(
            account_id,
            {
                "clientName": ticket_account_name(ticket),
                "count": 0,
                "oldest": created,
            },
        )
        group["count"] += 1
        if created is not None and (group["oldest"] is None or created < group["oldest"]):
            group["oldest"] = created

    candidates = [g for g in groups.values() if int(g["count"]) > 1]
    if not candidates:
        return {"active": False, "clientName": "", "deviceCount": 0, "openFor": ""}

    candidates.sort(key=lambda g: (int(g["count"]), -(g["oldest"].timestamp() if g["oldest"] else now.timestamp())), reverse=True)
    top = candidates[0]
    return {
        "active": True,
        "clientName": top["clientName"],
        "deviceCount": int(top["count"]),
        "openFor": duration_text_from_datetime(top.get("oldest"), now),
    }


def build_ticker_items(open_tickets: List[Dict[str, Any]], now: datetime) -> List[Dict[str, str]]:
    p0_items: List[Tuple[int, Dict[str, str]]] = []
    for t in open_tickets:
        if not is_p0_ticket(t):
            continue
        created = ticket_created_dt(t) or ticket_last_activity_dt(t)
        age_minutes = int((now - created).total_seconds() / 60) if created else 0
        text = f"P0 OUTAGE #{ticket_number(t)} OPEN {open_duration_text(t, now)}"
        p0_items.append((age_minutes, {"text": text, "level": "critical"}))
    p0_items.sort(key=lambda x: x[0], reverse=True)

    grouped: Dict[str, Dict[str, Any]] = {}
    for t in open_tickets:
        sig = issue_signature(t)
        if not sig:
            continue
        grp = grouped.setdefault(sig, {"count": 0, "accounts": set()})
        grp["count"] += 1
        grp["accounts"].add(ticket_account_id(t))

    similar_items: List[Tuple[int, Dict[str, str]]] = []
    for sig, stats in grouped.items():
        account_count = len(stats["accounts"])
        count = int(stats["count"])
        if account_count < 2 or count < 2:
            continue
        text = f"SIMILAR ACTION: {sig} across {account_count} clients ({count} tickets)"
        similar_items.append((count, {"text": text, "level": "warn"}))
    similar_items.sort(key=lambda x: x[0], reverse=True)

    out = [x[1] for x in p0_items[:4]] + [x[1] for x in similar_items[:6]]
    if not out:
        out.append({"text": "AUTOTASK MONITORING ACTIVE - NO CROSS-CLIENT INCIDENT CLUSTERS", "level": "normal"})
    return out


def fallback_payload(source: str, status: str, note: str) -> Dict[str, Any]:
    data = {
        "meta": {
            "source": source,
            "status": status,
            "generatedAt": utc_now_iso(),
            "note": note,
        },
        "traffic": [{"t": i, "v": 0} for i in range(20)],
        "labor": [{"n": d, "b": 0.0, "i": 0.0} for d in ("MON", "TUE", "WED", "THU", "FRI")],
        "nodes": [{"s": "u"} for _ in range(14)],
        "kpis": [
            {"l": "SLA COMPLIANCE", "v": "N/A", "c": "#10b981"},
            {"l": "AVG RESPONSE", "v": "N/A", "c": "#60a5fa"},
            {"l": "OPEN TICKETS", "v": "0", "c": "#f59e0b"},
            {"l": "WAITING CUSTOMER", "v": "0", "c": "#facc15"},
            {"l": "PAST DUE ACTIVE", "v": "0", "c": "#fb7185"},
            {"l": "STALE TICKETS", "v": "0", "c": "#f43f5e"},
            {"l": "RC RECEIVED (TODAY)", "v": "N/A", "c": "#38bdf8"},
            {"l": "RC MISSED (TODAY)", "v": "N/A", "c": "#ef4444"},
            {"l": "RC % CALLS TAKEN", "v": "N/A", "c": "#22c55e"},
        ],
        "technicians": [
            {
                "name": "No Assigned Technicians",
                "state": "IDLE",
                "openTickets": 0,
                "staleTickets": 0,
                "utilizationPct": 0,
                "utilizationColor": "#ef4444",
                "hoursWorkedToday": 0.0,
            }
        ],
        "targets": {"dayPct": 0.0, "weekPct": 0.0},
        "ops": ["> [AT] DATA UNAVAILABLE", "> [AT] FALLBACK PAYLOAD ENABLED"],
        "ticker": [{"text": "AUTOTASK DATA TEMPORARILY UNAVAILABLE", "level": "warn"}],
        "networkStatus": {"active": False, "clientName": "", "deviceCount": 0, "openFor": ""},
        "ticketMix": [],
        "ttrByTech": [],
        "dayProgress": {
            "startIso": "",
            "nowIso": "",
            "bucketMinutes": 15,
            "elapsedMinutes": 0,
            "incoming": [],
            "resolved": [],
            "incomingTotal": 0,
            "resolvedTotal": 0,
        },
    }
    return data


async def mcp_post(payload: Dict[str, Any], session_id: Optional[str] = None) -> httpx.Response:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if SMG_API_KEY:
        headers["Authorization"] = f"Bearer {SMG_API_KEY}"
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        return await client.post(SMG_MCP_URL, json=payload, headers=headers)


async def direct_autotask_request(method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not direct_autotask_enabled():
        raise RuntimeError("Direct Autotask mode is not configured.")

    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        url = f"{AUTOTASK_BASE_URL}/{path.lstrip('/')}"

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "ApiIntegrationCode": AUTOTASK_INTEGRATION_CODE,
        "UserName": AUTOTASK_USERNAME,
        "Secret": AUTOTASK_SECRET,
    }
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        response = await client.request(method.upper(), url, json=body, headers=headers)
    response.raise_for_status()
    return response.json()


async def ensure_mcp_session() -> Optional[str]:
    global MCP_SESSION_ID
    if MCP_SESSION_ID is not None:
        return MCP_SESSION_ID

    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "techops-azure-adapter", "version": "1.1.0"},
        },
    }
    init_resp = await mcp_post(init_payload)
    init_resp.raise_for_status()
    MCP_SESSION_ID = init_resp.headers.get("Mcp-Session-Id")
    if not MCP_SESSION_ID:
        MCP_SESSION_ID = ""
    return MCP_SESSION_ID


async def call_tool(tool_name: str, params: Dict[str, Any]) -> Any:
    session_id = await ensure_mcp_session()

    def payload(arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": int(datetime.now(timezone.utc).timestamp()),
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }

    def extract_tool_error(response_json: Dict[str, Any]) -> Optional[str]:
        if "error" in response_json:
            return response_json["error"].get("message", f"Tool call failed: {tool_name}")
        result = response_json.get("result")
        if isinstance(result, dict) and result.get("isError"):
            content = result.get("content")
            if isinstance(content, list) and content:
                first = content[0]
                if isinstance(first, dict) and isinstance(first.get("text"), str):
                    return first["text"]
            return f"Tool call failed: {tool_name}"
        return None

    first = await mcp_post(payload({"params": params}), session_id=session_id or None)
    if first.status_code == 401:
        global MCP_SESSION_ID
        MCP_SESSION_ID = None
        session_id = await ensure_mcp_session()
        first = await mcp_post(payload({"params": params}), session_id=session_id or None)
    first.raise_for_status()
    first_json = first.json()
    first_error = extract_tool_error(first_json)
    if first_error is None:
        return parse_content(first_json.get("result"))
    if "Field required" not in first_error or "params" not in first_error:
        raise RuntimeError(first_error)

    second = await mcp_post(payload(params), session_id=session_id or None)
    second.raise_for_status()
    second_json = second.json()
    second_error = extract_tool_error(second_json)
    if second_error is not None:
        raise RuntimeError(second_error)
    return parse_content(second_json.get("result"))


AUTOTASK_PAGE_LIMIT = 500


async def autotask_query(entity: str, filters: Optional[List[Dict[str, Any]]] = None, max_records: int = 500) -> List[Dict[str, Any]]:
    page_size = min(max_records, AUTOTASK_PAGE_LIMIT)
    body: Dict[str, Any] = {"MaxRecords": page_size}
    if filters:
        body["Filter"] = filters

    if direct_autotask_enabled():
        first_page = await direct_autotask_request("POST", f"{entity}/query", body)
    else:
        first_page = await call_tool(
            "autotask_api_request",
            {"method": "POST", "path": f"{entity}/query", "body": body},
        )

    items = coerce_items(first_page)
    if len(items) >= max_records:
        return items[:max_records]

    page_details = first_page.get("pageDetails") if isinstance(first_page, dict) else {}
    next_url = page_details.get("nextPageUrl") if isinstance(page_details, dict) else None
    next_path = normalize_next_page_path(next_url)
    page_count = 1

    while next_path and len(items) < max_records and page_count < 5:
        if direct_autotask_enabled():
            next_page = await direct_autotask_request("GET", next_path)
        else:
            next_page = await call_tool(
                "autotask_api_request",
                {"method": "GET", "path": next_path},
            )
        items.extend(coerce_items(next_page))
        page_details = next_page.get("pageDetails") if isinstance(next_page, dict) else {}
        next_url = page_details.get("nextPageUrl") if isinstance(page_details, dict) else None
        next_path = normalize_next_page_path(next_url)
        page_count += 1

    return items[:max_records]


async def load_ticket_status_labels(now: datetime) -> None:
    global TICKET_STATUS_LABELS, TICKET_STATUS_LABELS_LOADED_AT
    if (
        TICKET_STATUS_LABELS
        and TICKET_STATUS_LABELS_LOADED_AT is not None
        and (now - TICKET_STATUS_LABELS_LOADED_AT).total_seconds() < STATUS_LABELS_TTL_SECONDS
    ):
        return
    try:
        if direct_autotask_enabled():
            raw = await direct_autotask_request("GET", "Tickets/entityInformation/fields")
        else:
            raw = await call_tool(
                "autotask_api_request",
                {"method": "GET", "path": "Tickets/entityInformation/fields"},
            )
    except Exception:
        return

    fields = raw.get("fields") if isinstance(raw, dict) else None
    if not isinstance(fields, list):
        return
    labels: Dict[int, str] = {}
    for field in fields:
        if not isinstance(field, dict):
            continue
        name = str(field.get("name") or "").lower()
        if name != "status":
            continue
        picklist = field.get("picklistValues")
        if not isinstance(picklist, list):
            break
        for option in picklist:
            if not isinstance(option, dict):
                continue
            try:
                status_id = int(option.get("value"))
            except (TypeError, ValueError):
                continue
            label = str(option.get("label") or "").strip()
            if label:
                labels[status_id] = label
        break

    if labels:
        TICKET_STATUS_LABELS = labels
        TICKET_STATUS_LABELS_LOADED_AT = now


@app.get("/healthz")
async def healthz() -> Dict[str, Any]:
    return {"status": "ok", "service": "techops-azure-adapter", "time": utc_now_iso()}


@app.get("/dashboard")
async def dashboard() -> FileResponse:
    if not DASHBOARD_FILE.exists():
        raise HTTPException(status_code=404, detail="Dashboard file not found.")
    return FileResponse(str(DASHBOARD_FILE), media_type="text/html")


def get_blob_service_client() -> Optional["BlobServiceClient"]:
    global BLOB_CLIENT, BLOB_CREDENTIAL
    if BLOB_CLIENT is not None:
        return BLOB_CLIENT
    if not _AZURE_BLOB_AVAILABLE or not BLOB_ACCOUNT_URL:
        return None
    try:
        BLOB_CREDENTIAL = DefaultAzureCredential()
        BLOB_CLIENT = BlobServiceClient(account_url=BLOB_ACCOUNT_URL, credential=BLOB_CREDENTIAL)
    except Exception as ex:  # pragma: no cover - credential init rarely fails at boot
        logger.warning("Blob client init failed: %s", ex)
        BLOB_CLIENT = None
    return BLOB_CLIENT


def history_blob_name(now: datetime) -> str:
    local = now.astimezone(PACIFIC_TZ)
    return f"history/{local:%Y/%m/%d/%H%M}.json"


async def write_payload_to_blob(payload: Dict[str, Any], now: datetime) -> None:
    client = get_blob_service_client()
    if client is None:
        return
    try:
        container = client.get_container_client(BLOB_CONTAINER)
        body = json.dumps(payload, default=str).encode("utf-8")
        await container.upload_blob(
            name=BLOB_LATEST_NAME,
            data=body,
            overwrite=True,
            content_type="application/json",
        )
        if BLOB_WRITE_HISTORY:
            try:
                await container.upload_blob(
                    name=history_blob_name(now),
                    data=body,
                    overwrite=True,
                    content_type="application/json",
                )
            except Exception as ex:
                logger.warning("Blob history write failed: %s", ex)
    except Exception as ex:
        logger.warning("Blob latest write failed: %s", ex)


async def read_payload_from_blob() -> Optional[Dict[str, Any]]:
    client = get_blob_service_client()
    if client is None:
        return None
    try:
        container = client.get_container_client(BLOB_CONTAINER)
        blob = container.get_blob_client(BLOB_LATEST_NAME)
        stream = await blob.download_blob()
        data = await stream.readall()
        payload = json.loads(data.decode("utf-8"))
        if isinstance(payload, dict):
            return payload
    except ResourceNotFoundError:
        return None
    except Exception as ex:
        logger.warning("Blob latest read failed: %s", ex)
    return None


def _schedule_window_contains(dt_local: datetime) -> bool:
    if SCHEDULE_START_HOUR == SCHEDULE_END_HOUR:
        return False
    hour = dt_local.hour
    if SCHEDULE_START_HOUR < SCHEDULE_END_HOUR:
        return SCHEDULE_START_HOUR <= hour < SCHEDULE_END_HOUR
    return hour >= SCHEDULE_START_HOUR or hour < SCHEDULE_END_HOUR


def _seconds_until_next_run(now: datetime) -> float:
    local = now.astimezone(PACIFIC_TZ)
    if _schedule_window_contains(local):
        return float(SCHEDULE_INTERVAL_SECONDS)
    target = local.replace(hour=SCHEDULE_START_HOUR, minute=0, second=0, microsecond=0)
    if local >= target:
        target = target + timedelta(days=1)
    return max(30.0, (target - local).total_seconds())


async def _scheduler_loop() -> None:
    logger.info(
        "techops scheduler started: every %ss within %02d:00-%02d:00 %s",
        SCHEDULE_INTERVAL_SECONDS,
        SCHEDULE_START_HOUR,
        SCHEDULE_END_HOUR,
        PACIFIC_TZ.key,
    )
    while True:
        try:
            now = utc_now()
            local = now.astimezone(PACIFIC_TZ)
            if _schedule_window_contains(local):
                await refresh_techops_payload("schedule")
            sleep_for = _seconds_until_next_run(utc_now())
            await asyncio.sleep(sleep_for)
        except asyncio.CancelledError:
            raise
        except Exception as ex:
            logger.warning("Scheduler iteration error: %s", ex)
            await asyncio.sleep(60)


@app.on_event("startup")
async def _on_startup() -> None:
    global LAST_GOOD_PAYLOAD, SCHEDULER_TASK
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    hydrated = await read_payload_from_blob()
    if hydrated is not None:
        LAST_GOOD_PAYLOAD = hydrated
        logger.info(
            "Hydrated LAST_GOOD_PAYLOAD from blob (generatedAt=%s)",
            hydrated.get("meta", {}).get("generatedAt"),
        )
    if SCHEDULE_ENABLED:
        SCHEDULER_TASK = asyncio.create_task(_scheduler_loop())


@app.on_event("shutdown")
async def _on_shutdown() -> None:
    global BLOB_CLIENT, BLOB_CREDENTIAL, SCHEDULER_TASK
    if SCHEDULER_TASK is not None:
        SCHEDULER_TASK.cancel()
        try:
            await SCHEDULER_TASK
        except (asyncio.CancelledError, Exception):
            pass
        SCHEDULER_TASK = None
    if BLOB_CLIENT is not None:
        try:
            await BLOB_CLIENT.close()
        except Exception:
            pass
        BLOB_CLIENT = None
    if BLOB_CREDENTIAL is not None:
        try:
            await BLOB_CREDENTIAL.close()
        except Exception:
            pass
        BLOB_CREDENTIAL = None


async def build_live_payload(now: datetime) -> Dict[str, Any]:
    recent_30d = now - timedelta(days=30)
    source_name = current_data_source()

    await load_ticket_status_labels(now)
    open_tickets = await autotask_query(
        "Tickets",
        filters=[{"field": "status", "op": "noteq", "value": 5}],
        max_records=500,
    )
    recent_tickets = await autotask_query(
        "Tickets",
        filters=[{"field": "createDate", "op": "gte", "value": to_iso_z(recent_30d)}],
        max_records=700,
    )
    resolved_tickets = await autotask_query(
        "Tickets",
        filters=[{"field": "resolvedDateTime", "op": "gte", "value": to_iso_z(recent_30d)}],
        max_records=700,
    )
    resources = await autotask_query("Resources", filters=[{"field": "isActive", "op": "eq", "value": True}], max_records=500)
    today_entries = await autotask_query(
        "TimeEntries",
        filters=[{"field": "dateWorked", "op": "eq", "value": local_date_string(now)}],
        max_records=500,
    )
    try:
        utilization_rows = await fetch_utilization_summary(now)
    except Exception:
        utilization_rows = []

    focus_resources = select_focus_resources(resources)
    focus_ids = {int(x["id"]) for x in focus_resources if x.get("id") is not None}
    focus_recent_tickets = [t for t in recent_tickets if assigned_resource_id(t) in focus_ids]
    focus_resolved_tickets = [t for t in resolved_tickets if assigned_resource_id(t) in focus_ids]
    focus_open_tickets = [t for t in open_tickets if assigned_resource_id(t) in focus_ids]
    hours_by_id = build_time_entry_hours(today_entries)
    utilization_by_id = build_utilization_map(focus_resources, utilization_rows)

    generated_at = utc_now_iso()
    open_count = len(open_tickets)
    stale_count = count_stale_tickets(open_tickets, now)
    waiting_customer_count = count_waiting_customer_tickets(open_tickets)
    past_due_count = count_past_due_active_tickets(open_tickets, now)
    sla_pct, sla_sample = compute_sla_compliance(recent_tickets, now)
    avg_response_minutes = compute_avg_response_minutes(recent_tickets)
    labor, targets = build_labor(focus_recent_tickets, now)
    targets = build_target_summary(focus_resources, hours_by_id, utilization_by_id)
    traffic = build_network_traffic(recent_tickets, now)
    day_progress = build_day_progress(recent_tickets, resolved_tickets, now)
    technicians = build_focus_technicians(
        focus_open_tickets,
        focus_resources,
        hours_by_id,
        utilization_by_id,
        now,
        focus_recent_tickets,
    )
    ticket_mix = build_ticket_mix(focus_resources, focus_open_tickets, focus_resolved_tickets, now)
    ttr_by_tech = build_ttr_by_tech(focus_resources, focus_resolved_tickets, now)
    network_status = build_network_status(open_tickets, now)
    nodes = build_nodes(technicians)
    try:
        rc_metrics = await fetch_ringcentral_call_metrics(now)
    except Exception:
        rc_metrics = fallback_ringcentral_call_metrics()
    kpis = build_kpis(
        sla_pct,
        avg_response_minutes,
        open_count,
        stale_count,
        waiting_customer_count,
        past_due_count,
        rc_metrics,
    )
    ops = build_console_lines(
        generated_at,
        source_name,
        "NOMINAL",
        open_count,
        stale_count,
        sla_sample,
        len([t for t in technicians if t.get("state") != "MISSING"]),
        rc_metrics,
    )
    ticker = build_ticker_items(open_tickets, now)

    return {
        "meta": {
            "source": source_name,
            "status": "NOMINAL",
            "generatedAt": generated_at,
        },
        "traffic": traffic,
        "labor": labor,
        "nodes": nodes,
        "kpis": kpis,
        "technicians": technicians,
        "targets": targets,
        "ops": ops,
        "ticker": ticker,
        "networkStatus": network_status,
        "ticketMix": ticket_mix,
        "ttrByTech": ttr_by_tech,
        "dayProgress": day_progress,
    }


async def refresh_techops_payload(trigger: str) -> Optional[Dict[str, Any]]:
    global LAST_GOOD_PAYLOAD

    if not direct_autotask_enabled() and not SMG_API_KEY:
        return None

    async with REFRESH_LOCK:
        now = utc_now()
        try:
            payload = await build_live_payload(now)
        except Exception as ex:
            logger.warning("techops refresh (%s) failed: %s", trigger, ex)
            return None
        LAST_GOOD_PAYLOAD = payload
        await write_payload_to_blob(payload, now)
        logger.info("techops refresh (%s) succeeded at %s", trigger, payload["meta"]["generatedAt"])
        return payload


@app.get("/api/techops")
async def get_techops(request: Request) -> Dict[str, Any]:
    global LAST_GOOD_PAYLOAD
    enforce_office_ip(request)

    if not direct_autotask_enabled() and not SMG_API_KEY:
        return fallback_payload("SIM_AZURE", "DEGRADED", "Neither direct Autotask credentials nor SMG_API_KEY is configured")

    now = utc_now()
    if payload_is_fresh(LAST_GOOD_PAYLOAD, now):
        return LAST_GOOD_PAYLOAD

    if LAST_GOOD_PAYLOAD is None:
        hydrated = await read_payload_from_blob()
        if hydrated is not None:
            LAST_GOOD_PAYLOAD = hydrated
            if payload_is_fresh(LAST_GOOD_PAYLOAD, now):
                return LAST_GOOD_PAYLOAD

    refreshed = await refresh_techops_payload("dashboard")
    if refreshed is not None:
        return refreshed
    if LAST_GOOD_PAYLOAD is not None:
        cached = dict(LAST_GOOD_PAYLOAD)
        cached["meta"] = {
            "source": "CACHE_AZURE",
            "status": "DEGRADED",
            "generatedAt": utc_now_iso(),
            "note": "Serving last-good snapshot; live pull failed",
        }
        return cached
    return fallback_payload("SIM_AZURE", "DEGRADED", "Live pull failed and no cached snapshot is available")


@app.post("/api/techops/refresh")
async def post_refresh(request: Request) -> Dict[str, Any]:
    enforce_office_ip(request)
    if REFRESH_TOKEN:
        header_token = request.headers.get("x-techops-refresh-token", "").strip()
        if not header_token or header_token != REFRESH_TOKEN:
            raise HTTPException(status_code=401, detail="Invalid or missing refresh token.")

    refreshed = await refresh_techops_payload("http")
    if refreshed is None:
        raise HTTPException(status_code=503, detail="Refresh failed; no payload was produced.")
    meta = refreshed.get("meta", {}) if isinstance(refreshed, dict) else {}
    return {
        "status": "ok",
        "generatedAt": meta.get("generatedAt"),
        "source": meta.get("source"),
    }
