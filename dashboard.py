import json
import time
import requests
import pandas as pd
import streamlit as st
import altair as alt
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors


API = "http://127.0.0.1:8000"

st.set_page_config(page_title="AVAP Dashboard", layout="wide")
st.title("AVAP Scan Dashboard")

if "selected_severity" not in st.session_state:
    st.session_state["selected_severity"] = None
st.markdown("""
<style>
.metric-card {
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 14px;
    padding: 16px 18px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.18);
    margin-bottom: 12px;
}
.metric-label {
    font-size: 0.85rem;
    color: #9ca3af;
    margin-bottom: 6px;
    font-weight: 500;
}
.metric-value {
    font-size: 1.7rem;
    font-weight: 700;
    color: #f9fafb;
    line-height: 1.2;
}
.section-box {
    background: #0b1220;
    border: 1px solid #1f2937;
    border-radius: 16px;
    padding: 18px;
    margin-bottom: 18px;
}
            .status-card {
    background: #0b1220;
    border: 1px solid #1f2937;
    border-radius: 16px;
    padding: 18px;
    margin-bottom: 18px;
}
.status-label {
    font-size: 0.82rem;
    color: #9ca3af;
    margin-bottom: 4px;
    font-weight: 500;
}
.status-value {
    font-size: 1rem;
    color: #f9fafb;
    font-weight: 600;
    word-break: break-word;
}
.status-badge {
    display: inline-block;
    padding: 6px 12px;
    border-radius: 999px;
    font-size: 0.85rem;
    font-weight: 700;
}
.badge-running {
    background: rgba(245, 158, 11, 0.18);
    color: #fbbf24;
    border: 1px solid rgba(245, 158, 11, 0.35);
}
.badge-completed {
    background: rgba(34, 197, 94, 0.18);
    color: #4ade80;
    border: 1px solid rgba(34, 197, 94, 0.35);
}
.badge-failed {
    background: rgba(239, 68, 68, 0.18);
    color: #f87171;
    border: 1px solid rgba(239, 68, 68, 0.35);
}
.badge-queued {
    background: rgba(59, 130, 246, 0.18);
    color: #60a5fa;
    border: 1px solid rgba(59, 130, 246, 0.35);
}
.badge-default {
    background: rgba(156, 163, 175, 0.18);
    color: #d1d5db;
    border: 1px solid rgba(156, 163, 175, 0.35);
}
</style>
""", unsafe_allow_html=True)

# -------------------------
# Helpers
# -------------------------
def safe_get_json(url: str, timeout=30):
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()

def safe_post_json(url: str, payload: dict, timeout=30):
    r = requests.post(url, json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()

def safe_get_recent_scan(url: str, timeout=30):
    r = requests.get(f"{API}/api/scans/recent", params={"url": url}, timeout=timeout)
    r.raise_for_status()
    return r.json()

def get_status_badge_class(status_value: str) -> str:
    s = str(status_value).lower().strip()
    if s == "running":
        return "badge-running"
    if s == "completed":
        return "badge-completed"
    if s == "failed":
        return "badge-failed"
    if s == "queued":
        return "badge-queued"
    return "badge-default"

def render_status_item(label: str, value):
    st.markdown(
        f"""
        <div class="status-label">{label}</div>
        <div class="status-value">{value if value not in [None, ''] else 'N/A'}</div>
        """,
        unsafe_allow_html=True
    )

def format_metric_value(value):
    if value is None:
        return "N/A"
    try:
        if isinstance(value, float):
            return f"{value:.2f}"
        return str(value)
    except Exception:
        return str(value)

def render_metric_card(label: str, value):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{format_metric_value(value)}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

def get_severity_badge(severity: str):
    sev = str(severity).upper()
    if sev == "CRITICAL":
        return "#ef4444", "#7f1d1d"
    elif sev == "HIGH":
        return "#f97316", "#7c2d12"
    elif sev == "MEDIUM":
        return "#f59e0b", "#78350f"
    elif sev == "LOW":
        return "#3b82f6", "#1e3a8a"
    else:
        return "#9ca3af", "#374151"

def get_validation_badge(status: str):
    s = str(status).lower()
    if s == "confirmed":
        return "#22c55e", "#14532d"
    elif s == "needs_manual_review":
        return "#f59e0b", "#78350f"
    elif s == "false_positive":
        return "#ef4444", "#7f1d1d"
    else:
        return "#9ca3af", "#374151"

def render_finding_card(row):
    sev_fg, sev_bg = get_severity_badge(row.get("severity", "INFO"))
    val_fg, val_bg = get_validation_badge(row.get("validated", "unknown"))

    reason = str(row.get("validation_reason", "N/A"))
    if len(reason) > 140:
        reason = reason[:137] + "..."

    st.markdown(
        f"""
        <div style="
            background:#111827;
            border:1px solid #1f2937;
            border-radius:16px;
            padding:16px;
            margin-bottom:16px;
            min-height:220px;
        ">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:10px; margin-bottom:10px;">
                <div style="font-size:1rem; font-weight:700; color:#f9fafb;">
                    {row.get("finding_name", "N/A")}
                </div>
                <div style="background:{sev_bg}; color:{sev_fg}; padding:4px 10px; border-radius:999px; font-size:0.8rem; font-weight:700;">
                    {str(row.get("severity", "INFO")).upper()}
                </div>
            </div>

            <div style="margin-bottom:8px; color:#d1d5db; font-size:0.9rem;">
                <b>Tool:</b> {row.get("tool", "N/A")}
            </div>

            <div style="margin-bottom:8px;">
                <span style="background:{val_bg}; color:{val_fg}; padding:4px 10px; border-radius:999px; font-size:0.8rem; font-weight:700;">
                    {row.get("validated", "unknown")}
                </span>
            </div>

            <div style="margin-bottom:8px; color:#d1d5db; font-size:0.9rem; word-break:break-word;">
                <b>URL:</b> {row.get("url", "N/A")}
            </div>

            <div style="color:#9ca3af; font-size:0.88rem; margin-top:10px;">
                <b>Reason:</b> {reason}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )



def make_arrow_safe_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Convert dict/list cells to JSON string so Streamlit/Arrow won't crash."""
    df2 = df.copy()
    for col in df2.columns:
        df2[col] = df2[col].apply(
            lambda x: json.dumps(x, ensure_ascii=False) if isinstance(x, (dict, list)) else x
        )
    return df2

def normalize_findings(result_json: dict) -> pd.DataFrame:
    findings = result_json.get("findings") or result_json.get("results") or []
    if not findings:
        return pd.DataFrame()

    df = pd.DataFrame(findings)
    df = make_arrow_safe_dataframe(df)

    # Normalize common columns (because tools might use different key names)
    rename_map = {}
    if "finding_name" not in df.columns and "name" in df.columns:
        rename_map["name"] = "finding_name"
    if "tool" not in df.columns and "source" in df.columns:
        rename_map["source"] = "tool"
    if "url" not in df.columns and "endpoint" in df.columns:
        rename_map["endpoint"] = "url"
    if "severity" not in df.columns and "level" in df.columns:
        rename_map["level"] = "severity"

    if rename_map:
        df = df.rename(columns=rename_map)

    # Ensure base columns exist
    for c in ["severity", "tool", "finding_name", "url"]:
        if c not in df.columns:
            df[c] = ""

    
    # Build/Map per-finding validation label if it exists under other names
    if "validated" not in df.columns:
        if "validation_status" in df.columns:
            df["validated"] = df["validation_status"]
        elif "validation" in df.columns:
            df["validated"] = df["validation"]
        elif "verified" in df.columns:
            df["validated"] = df["verified"]
        elif "is_validated" in df.columns:
            df["validated"] = df["is_validated"]
        elif "final_status" in df.columns:
            df["validated"] = df["final_status"]
        elif "confirmed" in df.columns:
            df["validated"] = df["confirmed"].apply(
                lambda x: "Confirmed" if x is True else "Needs Review"
            )
        else:
            df["validated"] = "Not Available"

    # Make validated cleaner (string)
    df["validated"] = df["validated"].fillna("Not Available").astype(str)
    return df

def draw_severity_pie(df: pd.DataFrame):
    if df.empty:
        st.info("No findings to chart.")
        return None

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]

    sev = df["severity"].fillna("").astype(str).str.upper().replace({"": "UNKNOWN"})
    counts = sev.value_counts().reindex(severity_order, fill_value=0)
    counts = counts[counts > 0].reset_index()
    counts.columns = ["severity", "count"]

    chart = (
        alt.Chart(counts)
        .mark_arc()
        .encode(
            theta=alt.Theta(field="count", type="quantitative"),
            color=alt.Color(
                field="severity",
                type="nominal",
                sort=severity_order
            ),
            tooltip=["severity", "count"],
        )
        .properties(title="Severity Distribution")
    )

    st.altair_chart(chart, width="stretch")

def build_pdf_report(scan_id: str, status: dict, metrics: dict, df: pd.DataFrame) -> bytes:
    """
    Builds a clean vulnerability report PDF from scan status, metrics, and findings table.
    Returns PDF bytes.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title="AVAP Vulnerability Report")
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("AVAP Vulnerability Report", styles["Title"]))
    story.append(Spacer(1, 12))

    # Scan info
    target_url = status.get("url", "N/A")
    mode = status.get("mode", "N/A")
    started = status.get("started_at", "N/A")
    finished = status.get("finished_at", "N/A")
    scan_status = status.get("status", "N/A")

    story.append(Paragraph("<b>Scan Information</b>", styles["Heading2"]))
    info_table = Table(
        [
            ["Scan ID", scan_id],
            ["Target URL", target_url],
            ["Mode", mode],
            ["Status", scan_status],
            ["Started At", started],
            ["Finished At", finished],
        ],
        colWidths=[120, 380],
    )
    info_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                ("BOX", (0, 0), (-1, -1), 1, colors.black),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(info_table)
    story.append(Spacer(1, 12))

    # Executive summary (metrics)
    story.append(Paragraph("<b>Executive Summary</b>", styles["Heading2"]))
    total_findings = metrics.get("total_findings", "N/A")
    confirmed = metrics.get("confirmed", "N/A")
    manual = metrics.get("needs_manual_review", "N/A")
    fp = metrics.get("false_positive", "N/A")

    summary_table = Table(
        [
            ["Total Findings", str(total_findings)],
            ["Confirmed", str(confirmed)],
            ["Needs Manual Review", str(manual)],
            ["False Positives", str(fp)],
        ],
        colWidths=[200, 300],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                ("BOX", (0, 0), (-1, -1), 1, colors.black),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 12))

    # Severity breakdown table
    story.append(Paragraph("<b>Severity Breakdown</b>", styles["Heading2"]))
    if not df.empty and "severity" in df.columns:
        sev_counts = (
            df["severity"].fillna("").astype(str).str.upper().replace({"": "UNKNOWN"}).value_counts()
        )
        sev_rows = [["Severity", "Count"]] + [[k, str(v)] for k, v in sev_counts.items()]
        sev_table = Table(sev_rows, colWidths=[200, 300])
        sev_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("BOX", (0, 0), (-1, -1), 1, colors.black),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ]
            )
        )
        story.append(sev_table)
    else:
        story.append(Paragraph("No severity data available.", styles["BodyText"]))
    story.append(PageBreak())

    # Detailed findings
    story.append(Paragraph("<b>Detailed Findings</b>", styles["Heading2"]))
    story.append(Spacer(1, 8))

    # Keep report readable: choose key columns
    wanted_cols = ["severity", "tool", "finding_name", "url", "validated"]
    cols = [c for c in wanted_cols if c in df.columns]

    # Create a compact table (limit long text)
    def clip(x, n=90):
        s = "" if pd.isna(x) else str(x)
        return (s[: n - 3] + "...") if len(s) > n else s

    body_style = styles["BodyText"]
    body_style.fontSize = 8
    body_style.leading = 10

    header_style = styles["BodyText"]
    header_style.fontSize = 9
    header_style.leading = 11

    rows = [[Paragraph(f"<b>{c}</b>", header_style) for c in cols]]

    for _, r in df[cols].iterrows():
        row = []
        for c in cols:
            cell_text = clip(r[c], 90)
            row.append(Paragraph(str(cell_text), body_style))
        rows.append(row)

    findings_table = Table(
        rows,
        colWidths=[55, 55, 140, 180, 70],
        repeatRows=1
    )
    findings_table.setStyle(
    TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
            ("BOX", (0, 0), (-1, -1), 1, colors.black),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
    )
)

    story.append(findings_table)

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

# -------------------------
# Start Scan
# -------------------------
st.subheader("Start a Scan")
target = st.text_input("Target URL", "http://testphp.vulnweb.com/")
mode = st.selectbox("Mode", ["basic", "deep"])

if "recent_scan" not in st.session_state:
    st.session_state["recent_scan"] = None

col1, col2, col3 = st.columns([1, 1, 3])

with col1:
    check_recent_btn = st.button("Check Recent")

with col2:
    start_btn = st.button("Start Scan")

if check_recent_btn:
    try:
        recent_data = safe_get_recent_scan(target)
        st.session_state["recent_scan"] = recent_data
    except Exception as e:
        st.session_state["recent_scan"] = None
        st.error(f"Failed to check recent scan: {e}")

if start_btn:
    try:
        data = safe_post_json(f"{API}/api/scans", {"url": target, "mode": mode})
        scan_id = data.get("scan_id") or data.get("id") or data.get("scanId")
        if not scan_id:
            st.error(f"API response missing scan_id: {data}")
        else:
            st.session_state["scan_id"] = scan_id
            st.success(f"Started fresh scan: {scan_id}")
    except Exception as e:
        st.error(f"Failed to start scan: {e}")

st.markdown("### View Recent Dashboard")

recent = st.session_state.get("recent_scan")

if recent:
    if recent.get("found"):
        st.success("Previous scan found for this URL.")

        recent_scan_id = recent.get("scan_id", "")
        recent_mode = recent.get("mode", "N/A")
        recent_status = recent.get("status", "N/A")
        recent_started = recent.get("started_at", "N/A")
        recent_finished = recent.get("finished_at", "N/A")

        st.write(f"**Scan ID:** {recent_scan_id}")
        st.write(f"**Mode:** {recent_mode}")
        st.write(f"**Status:** {recent_status}")
        st.write(f"**Started At:** {recent_started}")
        st.write(f"**Finished At:** {recent_finished}")

        if st.button("View Recent"):
            st.session_state["scan_id"] = recent_scan_id
            st.success(f"Loaded recent scan: {recent_scan_id}")
    else:
        st.info(recent.get("message", "No previous scan found for this URL."))

st.divider()

# -------------------------
# View Scan
# -------------------------
st.subheader("View Scan")
scan_id_input = st.text_input("Scan ID", st.session_state.get("scan_id", ""))

colA, colB, colC = st.columns([1, 1, 2])
with colA:
    load_btn = st.button("Load / Refresh")
with colB:
    auto_refresh = st.checkbox("Auto refresh (while running)", value=True)
with colC:
    refresh_sec = st.slider("Refresh interval (seconds)", 3, 15, 5)

if load_btn and scan_id_input:
    st.session_state["scan_id"] = scan_id_input

scan_id = st.session_state.get("scan_id", "")

if not scan_id:
    st.info("Start a scan or paste a scan_id to view it.")
    st.stop()

# Fetch status
status = None
try:
    status = safe_get_json(f"{API}/api/scans/{scan_id}/status")
except Exception as e:
    st.error(f"Could not fetch status: {e}")
    st.stop()

status_str = str(status.get("status", "")).lower()
phase_str = str(status.get("phase", "")).lower()

# Auto-refresh if running
is_running = status_str in ["running", "processing", "queued"] or phase_str in ["pipeline", "running"]
if auto_refresh and is_running:
    st.info("Scan is running... auto refreshing.")
    time.sleep(refresh_sec)
    st.rerun()

# Result + Improvements
validated_result = None

try:
    validated_result = safe_get_json(f"{API}/api/scans/{scan_id}/validated-result")
except Exception:
    validated_result = None

if validated_result and validated_result.get("validated_findings"):
    result = validated_result
    df = pd.DataFrame(validated_result["validated_findings"])
    df = make_arrow_safe_dataframe(df)

    # map validated-report fields to dashboard table fields
    if "final_severity" in df.columns:
        df["severity"] = df["final_severity"]

    if "original_tool" in df.columns:
        df["tool"] = df["original_tool"]

    if "validation_status" in df.columns:
        df["validated"] = df["validation_status"]

    if "vuln_class" in df.columns:
        df["finding_name"] = df["vuln_class"]

    # ensure required columns exist
    for c in ["severity", "tool", "finding_name", "url", "validated"]:
        if c not in df.columns:
            df[c] = ""

else:
    try:
        result = safe_get_json(f"{API}/api/scans/{scan_id}/result")
    except Exception as e:
        st.warning(f"Result not ready yet. Details: {e}")
        st.stop()

    df = normalize_findings(result)

if df.empty:
    st.info("No findings found (or result format differs). Showing raw result JSON:")
    st.json(result)
    st.stop()

left_col, right_col = st.columns([3, 2])

with left_col:
    st.subheader("Scan Summary")
    scan_status = status.get("status", "N/A")
    badge_class = get_status_badge_class(scan_status)

    st.markdown('<div class="status-card">', unsafe_allow_html=True)

    top1, top2, top3 = st.columns(3)
    with top1:
        render_status_item("Scan ID", status.get("scan_id", "N/A"))
    with top2:
        render_status_item("Target URL", status.get("url", "N/A"))
    with top3:
        render_status_item("Mode", status.get("mode", "N/A"))

    mid1, mid2, mid3 = st.columns(3)
    with mid1:
        st.markdown(
            f"""
            <div class="status-label">Status</div>
            <div class="status-badge {badge_class}">{scan_status}</div>
            """,
            unsafe_allow_html=True
        )
    with mid2:
        render_status_item("Phase", status.get("phase", "N/A"))
    with mid3:
        render_status_item("Started At", status.get("started_at", "N/A"))

    bot1, bot2 = st.columns(2)
    with bot1:
        render_status_item("Finished At", status.get("finished_at", "N/A"))
    with bot2:
        render_status_item("Error", status.get("error", "None"))

    st.markdown("</div>", unsafe_allow_html=True)

    st.subheader("Metrics")

    metrics = {}
    try:
        metrics = safe_get_json(f"{API}/api/scans/{scan_id}/metrics")

        total_findings = metrics.get("total_findings", "N/A")
        confirmed = metrics.get("confirmed", "N/A")
        needs_manual_review = metrics.get("needs_manual_review", "N/A")
        false_positive = metrics.get("false_positive", "N/A")

        false_positive_rate = metrics.get("false_positive_rate", "N/A")
        validation_resolution_rate = metrics.get("validation_resolution_rate", "N/A")
        manual_review_rate = metrics.get("manual_review_rate", "N/A")

        st.markdown('<div class="section-box">', unsafe_allow_html=True)

        row1 = st.columns(4)
        with row1[0]:
            render_metric_card("Total Findings", total_findings)
        with row1[1]:
            render_metric_card("Confirmed", confirmed)
        with row1[2]:
            render_metric_card("Manual Review", needs_manual_review)
        with row1[3]:
            render_metric_card("False Positives", false_positive)

        row2 = st.columns(3)
        with row2[0]:
            render_metric_card("False Positive Rate", false_positive_rate)
        with row2[1]:
            render_metric_card("Resolution Rate", validation_resolution_rate)
        with row2[2]:
            render_metric_card("Manual Review Rate", manual_review_rate)

        st.markdown("</div>", unsafe_allow_html=True)

        with st.expander("View Detailed Metrics"):
            st.json(metrics)

    except Exception:
        st.info("Metrics not ready yet (scan may still be running).")


with right_col:
    st.subheader("Threat Distribution")
    st.markdown('<div class="section-box">', unsafe_allow_html=True)

    draw_severity_pie(df)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    sev = df["severity"].fillna("").astype(str).str.upper().replace({"": "UNKNOWN"})
    sev_counts = sev.value_counts().reindex(severity_order, fill_value=0)
    sev_counts = sev_counts[sev_counts > 0]

    st.markdown("#### Filter by Severity")

    btn_cols = st.columns(len(sev_counts) + 1)

    for i, (sev_name, sev_count) in enumerate(sev_counts.items()):
        with btn_cols[i]:
            if st.button(f"{sev_name} ({sev_count})", key=f"sev_btn_{sev_name}"):
                st.session_state["selected_severity"] = sev_name
                st.rerun()

    with btn_cols[len(sev_counts)]:
        if st.button("Show All", key="show_all_severity"):
            st.session_state["selected_severity"] = None
            st.rerun()

    selected = st.session_state.get("selected_severity")
    if selected:
        st.markdown(f"**Selected Severity:** {selected}")

    st.markdown("</div>", unsafe_allow_html=True)

    st.subheader("Severity Overview")
    st.markdown('<div class="section-box">', unsafe_allow_html=True)

    sev_col1, sev_col2 = st.columns(2)
    sev_items = list(sev_counts.items())

    for i, (sev_name, sev_count) in enumerate(sev_items):
        with sev_col1 if i % 2 == 0 else sev_col2:
            render_metric_card(sev_name.title(), sev_count)

    st.markdown("</div>", unsafe_allow_html=True)

# -------------------------
# Filters / Search
# -------------------------
st.markdown("### Filters & Search")

left, mid, right = st.columns(3)

with left:
    search = st.text_input("Search (url / finding / tool)", "")

with mid:
    severities = sorted(df["severity"].fillna("").astype(str).str.upper().unique().tolist())
    severity_filter = st.multiselect("Severity filter", options=severities, default=severities)

with right:
    tools = sorted(df["tool"].fillna("").astype(str).unique().tolist())
    tool_filter = st.multiselect("Tool filter", options=tools, default=tools)

filtered = df.copy()

# Apply severity filter
filtered["severity"] = filtered["severity"].fillna("").astype(str).str.upper()
filtered = filtered[filtered["severity"].isin(severity_filter)]

# Apply tool filter
filtered["tool"] = filtered["tool"].fillna("").astype(str)
filtered = filtered[filtered["tool"].isin(tool_filter)]

# Apply search filter
if search.strip():
    s = search.strip().lower()
    filtered = filtered[
        filtered["url"].astype(str).str.lower().str.contains(s, na=False)
        | filtered["finding_name"].astype(str).str.lower().str.contains(s, na=False)
        | filtered["tool"].astype(str).str.lower().str.contains(s, na=False)
    ]

selected_severity = st.session_state.get("selected_severity")

if selected_severity:
    filtered = filtered[
        filtered["severity"].fillna("").astype(str).str.upper() == selected_severity
    ]

# -------------------------
# Nice Table (only key columns)
# -------------------------
show_cols = ["severity", "tool", "finding_name", "url", "validated"]
show_cols = [c for c in show_cols if c in filtered.columns]

severity_order_map = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5
}

filtered["severity"] = filtered["severity"].fillna("").astype(str).str.upper()
filtered["_severity_order"] = filtered["severity"].map(severity_order_map).fillna(99)

if "validated" in filtered.columns:
    validation_order_map = {
        "confirmed": 0,
        "needs_manual_review": 1,
        "false_positive": 2,
        "unknown": 3
    }
    filtered["validated"] = filtered["validated"].fillna("unknown").astype(str).str.lower()
    filtered["_validated_order"] = filtered["validated"].map(validation_order_map).fillna(99)
    filtered = filtered.sort_values(by=["_severity_order", "_validated_order", "tool", "url"])
    filtered = filtered.drop(columns=["_severity_order", "_validated_order"])
else:
    filtered = filtered.sort_values(by=["_severity_order", "tool", "url"])
    filtered = filtered.drop(columns=["_severity_order"])

st.subheader("Validated Findings")
st.markdown('<div class="section-box">', unsafe_allow_html=True)
st.markdown(f"Showing **{len(filtered)}** of **{len(df)}** findings")

st.dataframe(
    filtered[show_cols].reset_index(drop=True),
    width="stretch",
    hide_index=True
)

st.markdown("</div>", unsafe_allow_html=True)
# -------------------------
# Download buttons
# -------------------------
st.markdown("### Download")
colx, coly, colz = st.columns(3)

with colx:
    st.download_button(
        "Download findings CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name=f"{scan_id}_findings.csv",
        mime="text/csv",
    )

with coly:
    st.download_button(
        "Download raw result JSON",
        data=json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8"),
        file_name=f"{scan_id}_result.json",
        mime="application/json",
    )

with colz:
    pdf_bytes = build_pdf_report(scan_id, status, metrics, filtered)
    st.download_button(
        "Download PDF Report",
        data=pdf_bytes,
        file_name=f"{scan_id}_AVAP_Report.pdf",
        mime="application/pdf",
    )
         
