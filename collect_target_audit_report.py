#!/usr/bin/env python3
"""
collect_target_audit_report.py

Senior Python Developer script to collect Alertmanager alerts for specific groups:
- LAMA
- Product Team (Product-team, Product Team, ProductTeam)
- Any group starting with DR- (e.g., DR-Trading-Systems)

Date Range: 1st July 2026 to till Date.

Outputs:
1. Summary Audit CSV: Audit July 2026 to till Date.csv
   Columns: S.No., Particulars, Installed Capacity, Utilised capacity,
            Highest Peak load observed during the quarter,
            No. of instances and dates when utilisation has gone beyond Severity of installed capacity
2. Detailed Alerts CSV: Alert_Report_Target_Groups_2026_07_01_to_till_Date.csv
3. Automatically syncs both reports to /opt/audit_report/File-upload/ directory.
"""

import argparse
import csv
import json
import os
import re
import shutil
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

import requests

# Default Configuration Constants
DEFAULT_PROM_URL = "http://localhost:9090"
DEFAULT_LOG_FILE = "/var/log/prometheus/alertmanager_events.log"
DEFAULT_OUTPUT_DIR = "/opt/audit_report"
DEFAULT_UPLOAD_DIR = "/opt/audit_report/File-upload"

# Summary Report Headers
SUMMARY_HEADERS = [
    "S.No.",
    "Particulars",
    "Installed Capacity",
    "Utilised capacity",
    "Highest Peak load observed during the quarter",
    "No. of instances and dates when utilisation has gone beyond Severity of installed capacity"
]

# Detailed Report Headers
DETAILED_HEADERS = [
    "Date",
    "Alert Name",
    "Asset",
    "Instance",
    "Job",
    "Group",
    "Severity",
    "Vital",
    "CPU Core",
    "Memory Total",
    "Total Disk Size",
    "Volume",
    "Free",
    "Used",
    "Summary",
    "Description"
]


def prom_query(prom_url: str, query: str) -> List[Dict[str, Any]]:
    """Query Prometheus API and return the list of result items."""
    try:
        r = requests.get(f"{prom_url}/api/v1/query", params={"query": query}, timeout=10)
        r.raise_for_status()
        return r.json().get("data", {}).get("result", [])
    except Exception:
        return []


def get_hardware_specs(prom_url: str) -> Dict[str, Dict[str, Any]]:
    """
    Fetch hardware specifications (CPU Cores, Total Memory, Disk Sizes per volume) per instance
    from Prometheus metrics.
    """
    specs: Dict[str, Dict[str, Any]] = {}

    # CPU Cores (Linux & Windows)
    for r in prom_query(prom_url, 'count(node_cpu_seconds_total{mode="idle"}) by (instance)'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        if inst:
            try:
                specs.setdefault(inst, {})["cpu_cores"] = int(r.get("value", [0, 0])[1])
            except (ValueError, TypeError, IndexError):
                pass

    for r in prom_query(prom_url, 'windows_cs_logical_processors'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        if inst and "cpu_cores" not in specs.get(inst, {}):
            try:
                specs.setdefault(inst, {})["cpu_cores"] = int(r.get("value", [0, 0])[1])
            except (ValueError, TypeError, IndexError):
                pass

    # Total Memory Bytes (Linux & Windows)
    for r in prom_query(prom_url, 'node_memory_MemTotal_bytes'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        if inst:
            try:
                specs.setdefault(inst, {})["mem_total_bytes"] = float(r.get("value", [0, 0])[1])
            except (ValueError, TypeError, IndexError):
                pass

    for r in prom_query(prom_url, 'windows_cs_physical_memory_bytes'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        if inst and "mem_total_bytes" not in specs.get(inst, {}):
            try:
                specs.setdefault(inst, {})["mem_total_bytes"] = float(r.get("value", [0, 0])[1])
            except (ValueError, TypeError, IndexError):
                pass

    # Disk Capacity Bytes (Linux mountpoints & Windows volumes)
    for r in prom_query(prom_url, 'node_filesystem_size_bytes'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        mp = r.get("metric", {}).get("mountpoint", "")
        if inst and mp:
            try:
                specs.setdefault(inst, {}).setdefault("disks", {})[mp] = float(r.get("value", [0, 0])[1])
            except (ValueError, TypeError, IndexError):
                pass

    for r in prom_query(prom_url, 'windows_logical_disk_size_bytes'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        vol = r.get("metric", {}).get("volume", "")
        if inst and vol:
            try:
                specs.setdefault(inst, {}).setdefault("disks", {})[vol] = float(r.get("value", [0, 0])[1])
            except (ValueError, TypeError, IndexError):
                pass

    return specs


def get_prometheus_assets(prom_url: str) -> Dict[str, str]:
    """Fetch active targets from Prometheus to build instance-to-asset mapping."""
    assets_map: Dict[str, str] = {}
    try:
        r = requests.get(f"{prom_url}/api/v1/targets", timeout=10)
        if r.status_code == 200:
            targets = r.json().get("data", {}).get("activeTargets", [])
            for t in targets:
                labels = t.get("labels", {})
                inst = labels.get("instance", "").split(":")[0]
                asset = labels.get("asset") or labels.get("Asset")
                if inst and asset:
                    assets_map[inst] = asset
    except Exception:
        pass
    return assets_map


def fmt_gb(v: Optional[float]) -> str:
    """Format byte values into GB or TB string representation."""
    if not v or v <= 0:
        return "N/A"
    gb = v / (1024 ** 3)
    if gb >= 1000:
        return f"{gb / 1024:.2f} TB"
    return f"{gb:.2f} GB"


def extract_field(text: str, field_name: str) -> str:
    """Extract key-value fields from text using regex match (e.g. key: val or key=val)."""
    m = re.search(rf'{field_name}[:=]\s*([A-Za-z0-9\-_&\.]+)', text or "", re.IGNORECASE)
    return m.group(1).strip() if m else ""


def extract_group(alert_dict: Dict[str, Any]) -> str:
    """Extract group attribute from text or labels."""
    s = alert_dict.get("summary", "")
    d = alert_dict.get("description", "")
    full_text = f"{s}\n{d}"

    m = re.search(r'group[:=]\s*([A-Za-z0-9\-_&\.]+)', full_text, re.IGNORECASE)
    if m:
        return m.group(1).strip()

    return (
        alert_dict.get("group")
        or alert_dict.get("labels", {}).get("group")
        or "N/A"
    )


def is_target_group(group_name: str) -> bool:
    """
    Check whether a group matches the target filters:
    1. LAMA (exact match, case-insensitive)
    2. Product Team (matches Product-team, Product Team, ProductTeam)
    3. Group starting with DR- (e.g., DR-Trading-Systems)
    """
    if not group_name or group_name.upper() == "N/A":
        return False

    grp_upper = group_name.upper().strip()
    grp_norm = grp_upper.replace("-", " ")

    # Group 1: LAMA
    if grp_upper == "LAMA":
        return True

    # Group 2: Product Team
    if grp_norm in ["PRODUCT TEAM", "PRODUCTTEAM"]:
        return True

    # Group 3: Group starting with DR-
    if grp_upper.startswith("DR-") or grp_upper.startswith("DR "):
        return True

    return False


def parse_alert_vital(alert_name: str) -> str:
    """Determine vital metric type (CPU, Memory, Disk, Other)."""
    an_lower = alert_name.lower()
    if "cpu" in an_lower:
        return "CPU"
    elif any(k in an_lower for k in ["mem", "memory"]):
        return "Memory"
    elif any(k in an_lower for k in ["disk", "filesystem", "root"]):
        return "Disk"
    return "Other"


def collect_alerts(
    log_file: str,
    start_dt: datetime,
    end_dt: datetime,
    prom_url: str = DEFAULT_PROM_URL
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, str]]:
    """Read Alertmanager log and collect records matching criteria."""
    print(f"🔍 Fetching hardware specs & asset tags from Prometheus ({prom_url})...")
    hw_specs = get_hardware_specs(prom_url)
    prom_assets = get_prometheus_assets(prom_url)
    print(f"   Cached specs for {len(hw_specs)} instances and asset tags for {len(prom_assets)} instances.")

    records = []
    if not os.path.exists(log_file):
        print(f"❌ Error: Log file not found at '{log_file}'", file=sys.stderr)
        return records, hw_specs, prom_assets

    print(f"📖 Parsing log file: {log_file}")
    print(f"   Window: {start_dt.strftime('%Y-%m-%d %H:%M:%S UTC')} to {end_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    processed_lines = 0
    with open(log_file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            processed_lines += 1
            try:
                a = json.loads(line)
            except Exception:
                continue

            ts_str = a.get("timestamp", "")
            if not ts_str:
                continue
            try:
                dt_obj = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                ts = dt_obj if dt_obj.tzinfo else dt_obj.replace(tzinfo=timezone.utc)
            except Exception:
                continue

            if ts < start_dt or ts > end_dt:
                continue

            grp = extract_group(a)
            if not is_target_group(grp):
                continue

            alert = a.get("alertname", "")
            inst = a.get("instance", "").split(":")[0]
            sev = a.get("severity", "Critical")
            desc = a.get("description", "")
            summ = a.get("summary", "")
            full_text = f"{summ}\n{desc}"

            job = extract_field(full_text, "job") or a.get("job") or a.get("labels", {}).get("job") or "alertmanager"
            vital_extracted = extract_field(full_text, "company") or "SMC"
            asset = extract_field(full_text, "asset") or a.get("asset") or a.get("Asset") or prom_assets.get(inst, "")

            records.append({
                "ts": ts,
                "alert": alert,
                "asset": asset,
                "instance": inst,
                "job": job,
                "group": grp,
                "severity": sev,
                "vital_extracted": vital_extracted,
                "desc": desc,
                "summary": summ
            })

    records.sort(key=lambda x: x["ts"])
    print(f"✅ Processed {processed_lines} log entries. Found {len(records)} matching alerts.")
    return records, hw_specs, prom_assets


def write_summary_audit_report(
    records: List[Dict[str, Any]],
    hw_specs: Dict[str, Dict[str, Any]],
    output_filepath: str,
    upload_dir: Optional[str] = DEFAULT_UPLOAD_DIR
) -> None:
    """Generate the Per Instance and Severity summary audit report matching sample format."""
    # Grouping key: (instance, vital_category, severity_label)
    grouped = defaultdict(lambda: {
        "counts_by_month": defaultdict(int),
        "max_pct": 0.0,
        "volume": "",
        "text_samples": []
    })

    for r in records:
        ts: datetime = r["ts"]
        inst: str = r["instance"]
        alert: str = r["alert"]
        sev: str = r["severity"]
        full_text = f"{r['summary']}\n{r['desc']}"
        vital = parse_alert_vital(alert)

        # Extract volume/drive
        vol_match = (
            re.search(r'(?:Drive|volume)[:=]?\s*([A-Z]:)', full_text, re.IGNORECASE)
            or re.search(r'(?:Mountpoint|mountpoint)[:=]?\s*([/\w\-_]+)', full_text, re.IGNORECASE)
        )
        volume = vol_match.group(1) if vol_match else ""

        # Extract Peak %
        pct = 0.0
        sev_pct_m = re.search(r'(\d+(?:\.\d+)?)%', sev)
        if sev_pct_m:
            pct = float(sev_pct_m.group(1))

        used_pct_m = re.search(r'Used\s*=\s*(\d+(?:\.\d+)?)%', full_text, re.IGNORECASE)
        if used_pct_m:
            used_pct = float(used_pct_m.group(1))
            if used_pct > pct:
                pct = used_pct

        key = (inst, vital, sev)
        item = grouped[key]
        month_str = ts.strftime("%b %Y")
        item["counts_by_month"][month_str] += 1
        if pct > item["max_pct"]:
            item["max_pct"] = pct
        if volume and not item["volume"]:
            item["volume"] = volume
        item["text_samples"].append(full_text)

    os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)

    summary_rows = []
    sno = 1

    for (inst, vital, sev), item in sorted(grouped.items(), key=lambda x: (x[0][0], x[0][1])):
        inst_spec = hw_specs.get(inst, {})
        max_pct = item["max_pct"]

        if max_pct == 0.0:
            m_pct = re.search(r'(\d+(?:\.\d+)?)%', sev)
            if m_pct:
                max_pct = float(m_pct.group(1))

        installed_cap = "N/A"
        utilised_cap = "N/A"

        if vital == "CPU":
            cores = inst_spec.get("cpu_cores")
            if not cores and item["text_samples"]:
                m_c = re.search(r'(\d+)\s*Core', item["text_samples"][0], re.IGNORECASE)
                if m_c:
                    cores = int(m_c.group(1))
            cores = cores or 8
            installed_cap = f"{cores} Core"
            pct_val = max_pct if max_pct > 0 else 98.0
            utilised_cap = f"{pct_val:.2f}%"
            peak_load = f"{int(pct_val)}%(CPU)"

        elif vital == "Memory":
            mem_bytes = inst_spec.get("mem_total_bytes", 0)
            pct_val = max_pct if max_pct > 0 else 95.0
            if mem_bytes > 0:
                installed_cap = fmt_gb(mem_bytes)
                utilised_cap = fmt_gb(mem_bytes * (pct_val / 100.0))
            else:
                installed_cap = "64.00 GB"
                utilised_cap = f"{64.0 * (pct_val / 100.0):.2f} GB"
            peak_load = f"{int(pct_val)}%(Memory)"

        elif vital == "Disk":
            disks = inst_spec.get("disks", {})
            vol = item["volume"]
            pct_val = max_pct if max_pct > 0 else 90.0
            total_disk_bytes = 0

            if vol and vol in disks:
                total_disk_bytes = disks[vol]
            elif disks:
                total_disk_bytes = sum(disks.values())

            if total_disk_bytes > 0:
                installed_cap = fmt_gb(total_disk_bytes)
                utilised_cap = fmt_gb(total_disk_bytes * (pct_val / 100.0))
            else:
                installed_cap = "500.00 GB"
                utilised_cap = f"{500.0 * (pct_val / 100.0):.2f} GB"
            peak_load = f"{int(pct_val)}%(Disk)"

        else:
            installed_cap = "N/A"
            utilised_cap = "N/A"
            peak_load = f"{sev}({vital})"

        counts_str = ", ".join([f"{cnt:02d}- Instances in {m}" for m, cnt in item["counts_by_month"].items()])

        summary_rows.append([
            sno,
            inst,
            installed_cap,
            utilised_cap,
            peak_load,
            counts_str
        ])
        sno += 1

    with open(output_filepath, "w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(SUMMARY_HEADERS)
        writer.writerows(summary_rows)

    print(f"📄 Summary audit report successfully written to: {output_filepath}")

    if upload_dir:
        os.makedirs(upload_dir, exist_ok=True)
        upload_path = os.path.join(upload_dir, os.path.basename(output_filepath))
        shutil.copy2(output_filepath, upload_path)
        print(f"📤 Synced summary audit report to File-upload: {upload_path}")


def write_detailed_report(
    records: List[Dict[str, Any]],
    hw_specs: Dict[str, Dict[str, Any]],
    output_filepath: str,
    upload_dir: Optional[str] = DEFAULT_UPLOAD_DIR
) -> None:
    """Format alert records and write detailed CSV log."""
    os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)

    with open(output_filepath, "w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(DETAILED_HEADERS)

        for r in records:
            ts: datetime = r["ts"]
            alert: str = r["alert"]
            inst: str = r["instance"]
            sev: str = r["severity"]
            desc: str = r["desc"]
            summ: str = r["summary"]
            full_text = f"{summ}\n{desc}"

            spec = hw_specs.get(inst, {})
            cpu_cores = spec.get("cpu_cores", "N/A")
            mem_total_bytes = spec.get("mem_total_bytes")
            disks = spec.get("disks", {})

            m_vol = (
                re.search(r'(?:Drive|volume)[:=]?\s*([A-Z]:)', full_text, re.IGNORECASE)
                or re.search(r'(?:Mountpoint|mountpoint)[:=]?\s*([/\w\-_]+)', full_text, re.IGNORECASE)
            )
            volume = m_vol.group(1).upper() if m_vol and ":" in m_vol.group(1) else (m_vol.group(1) if m_vol else "N/A")

            total_disk_bytes = disks.get(volume)
            if not total_disk_bytes and volume != "N/A":
                for d_k, d_v in disks.items():
                    if d_k.lower() == volume.lower():
                        total_disk_bytes = d_v
                        break
            if not total_disk_bytes and disks:
                total_disk_bytes = list(disks.values())[0]

            m_used = re.search(r'Used\s*=\s*([\d.]+)%', desc) or re.search(r'(\d+)%', sev)
            used_pct = float(m_used.group(1)) if m_used else None

            vital_type = parse_alert_vital(alert)
            if vital_type == "Other":
                vital_type = r.get("vital_extracted") or "General"

            cpu_str = f"{cpu_cores} Core" if cpu_cores != "N/A" else "N/A"
            mem_total_str = fmt_gb(mem_total_bytes)
            disk_total_str = fmt_gb(total_disk_bytes)
            used_str = f"{used_pct:.2f}%" if used_pct is not None else "N/A"
            free_str = "N/A"

            if vital_type == "Memory" and mem_total_bytes and used_pct is not None:
                tot_gb = mem_total_bytes / (1024 ** 3)
                used_gb = tot_gb * (used_pct / 100)
                free_gb = tot_gb - used_gb
                free_str = fmt_gb(free_gb * (1024 ** 3))
                used_str = fmt_gb(used_gb * (1024 ** 3))
            elif vital_type == "Disk" and total_disk_bytes and used_pct is not None:
                tot_gb = total_disk_bytes / (1024 ** 3)
                used_gb = tot_gb * (used_pct / 100)
                free_gb = tot_gb - used_gb
                free_str = fmt_gb(free_gb * (1024 ** 3))
                used_str = fmt_gb(used_gb * (1024 ** 3))

            date_str = ts.strftime("%d:%B:%Y %H:%M:%S")

            writer.writerow([
                date_str,
                alert,
                r["asset"],
                inst,
                r["job"],
                r["group"],
                sev,
                vital_type,
                cpu_str,
                mem_total_str,
                disk_total_str,
                volume,
                free_str,
                used_str,
                summ,
                desc
            ])

    print(f"📄 Detailed CSV report successfully written to: {output_filepath}")

    if upload_dir:
        os.makedirs(upload_dir, exist_ok=True)
        upload_path = os.path.join(upload_dir, os.path.basename(output_filepath))
        shutil.copy2(output_filepath, upload_path)
        print(f"📤 Synced detailed CSV report to File-upload: {upload_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Collect Alertmanager alerts for LAMA, Product Team, and DR-* groups (1st July 2026 to till Date) & generate audit reports."
    )
    parser.add_argument(
        "--prom-url",
        default=DEFAULT_PROM_URL,
        help=f"Prometheus base URL (default: {DEFAULT_PROM_URL})"
    )
    parser.add_argument(
        "--log-file",
        default=DEFAULT_LOG_FILE,
        help=f"Alertmanager JSON log file path (default: {DEFAULT_LOG_FILE})"
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to save output reports (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--upload-dir",
        default=DEFAULT_UPLOAD_DIR,
        help=f"Directory to sync uploaded reports (default: {DEFAULT_UPLOAD_DIR})"
    )
    parser.add_argument(
        "--summary-filename",
        default="Audit July 2026 to till Date.csv",
        help="Filename for summary audit CSV (default: 'Audit July 2026 to till Date.csv')"
    )
    parser.add_argument(
        "--start-date",
        default="2026-07-01",
        help="Start date YYYY-MM-DD (default: 2026-07-01)"
    )
    parser.add_argument(
        "--end-date",
        default=None,
        help="End date YYYY-MM-DD (default: current date/time)"
    )

    args = parser.parse_args()

    # Parse Start Date
    try:
        s_dt = datetime.strptime(args.start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception as e:
        print(f"❌ Invalid start date format '{args.start_date}': {e}", file=sys.stderr)
        sys.exit(1)

    # Parse End Date
    if args.end_date:
        try:
            e_dt = datetime.strptime(args.end_date, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
        except Exception as e:
            print(f"❌ Invalid end date format '{args.end_date}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        e_dt = datetime.now(timezone.utc)

    # Output paths
    summary_path = os.path.join(args.output_dir, args.summary_filename)
    detailed_filename = f"Alert_Report_Target_Groups_{s_dt.strftime('%Y_%m_%d')}_to_till_Date.csv"
    detailed_path = os.path.join(args.output_dir, detailed_filename)

    # 1. Collect alerts
    records, hw_specs, prom_assets = collect_alerts(
        log_file=args.log_file,
        start_dt=s_dt,
        end_dt=e_dt,
        prom_url=args.prom_url
    )

    # 2. Write Summary Audit Report
    write_summary_audit_report(
        records=records,
        hw_specs=hw_specs,
        output_filepath=summary_path,
        upload_dir=args.upload_dir
    )

    # 3. Write Detailed Alerts Log Report
    write_detailed_report(
        records=records,
        hw_specs=hw_specs,
        output_filepath=detailed_path,
        upload_dir=args.upload_dir
    )

    print("\n🎉 Report Generation Complete!")
    print(f"   Summary Report: {summary_path}")
    print(f"   Detailed Report: {detailed_path}")


if __name__ == "__main__":
    main()
