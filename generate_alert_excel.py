#!/usr/bin/env python3
"""
generate_alert_excel.py

Collects alert data from /var/log/prometheus/alertmanager_events.log
from 1st Dec 2025 to 31st Aug 2026 for All Critical Alerts.
Enriches with hardware specs & asset labels from Prometheus.
Evaluates Exchange Holidays and Trading Hours (9:00 AM to 11:55 PM).
Outputs high-performance formatted Excel (.xlsx) and CSV reports.
"""

import os
import sys
import json
import re
import time
import shutil
import requests
import xlsxwriter
import csv
from datetime import datetime, timezone, time as dtime

# Configuration
LOG_FILE = "/var/log/prometheus/alertmanager_events.log"
PROM = "http://localhost:9090"
OUTPUT_DIR = "/opt/audit_report"
UPLOAD_DIR = os.path.join(OUTPUT_DIR, "File-upload")
LOCAL_DIR = "/var/log/prometheus"

BASE_FILENAME = "Alert_Report_2025_12_01_to_2026_08_31"
EXCEL_OUTPUT = os.path.join(OUTPUT_DIR, f"{BASE_FILENAME}.xlsx")
CSV_OUTPUT = os.path.join(OUTPUT_DIR, f"{BASE_FILENAME}.csv")

START_DATE = datetime(2025, 12, 1, 0, 0, 0, tzinfo=timezone.utc)
END_DATE   = datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc)

# 2025-2026 Indian Exchange Trading Holidays
EXCHANGE_HOLIDAYS = {
    "2025-12-25": "Christmas",
    "2026-01-26": "Republic Day",
    "2026-03-03": "Holi",
    "2026-03-26": "Shri Ram Navami",
    "2026-03-31": "Shri Mahavir Jayanti",
    "2026-04-03": "Good Friday",
    "2026-04-14": "Dr. Baba Saheb Ambedkar Jayanti",
    "2026-05-01": "Maharashtra Day",
    "2026-05-28": "Bakri Id (Id-Ul-Adha)",
    "2026-06-26": "Muharram",
    "2026-08-15": "Independence Day",
}

HEADERS = [
    "Date",
    "Year",
    "Month",
    "Weekday",
    "Trading Hours/Non Trading Hours",
    "Alert Name",
    "Company",
    "Asset",
    "Instance",
    "Job",
    "Group",
    "Group1",
    "Severity",
    "Vital",
    "CPU Core",
    "Memory Total",
    "Total Disk Size",
    "Volume",
    "Free",
    "Used"
]

def prom_query(query):
    try:
        r = requests.get(f"{PROM}/api/v1/query", params={"query": query}, timeout=10)
        r.raise_for_status()
        return r.json().get("data", {}).get("result", [])
    except Exception as e:
        print(f"Warning querying Prometheus ({query}): {e}", file=sys.stderr)
        return []

def get_hardware_specs():
    print("Querying Prometheus for hardware specifications...")
    specs = {}
    
    # 1. CPU Cores
    for r in prom_query('count(node_cpu_seconds_total{mode="idle"}) by (instance)'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        if inst:
            specs.setdefault(inst, {})["cpu_cores"] = int(r.get("value", [0, 0])[1])
    for r in prom_query('windows_cs_logical_processors'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        if inst and "cpu_cores" not in specs.get(inst, {}):
            specs.setdefault(inst, {})["cpu_cores"] = int(r.get("value", [0, 0])[1])

    # 2. Total Memory
    for r in prom_query('node_memory_MemTotal_bytes'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        if inst:
            specs.setdefault(inst, {})["mem_total_bytes"] = float(r.get("value", [0, 0])[1])
    for r in prom_query('windows_cs_physical_memory_bytes'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        if inst and "mem_total_bytes" not in specs.get(inst, {}):
            specs.setdefault(inst, {})["mem_total_bytes"] = float(r.get("value", [0, 0])[1])

    # 3. Disks
    for r in prom_query('node_filesystem_size_bytes'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        mp = r.get("metric", {}).get("mountpoint", "")
        if inst and mp:
            specs.setdefault(inst, {}).setdefault("disks", {})[mp] = float(r.get("value", [0, 0])[1])
    for r in prom_query('windows_logical_disk_size_bytes'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        vol = r.get("metric", {}).get("volume", "")
        if inst and vol:
            specs.setdefault(inst, {}).setdefault("disks", {})[vol] = float(r.get("value", [0, 0])[1])

    print(f"Cached hardware specs for {len(specs)} instances.")
    return specs

def get_prometheus_assets():
    print("Querying Prometheus for target asset labels...")
    assets_map = {}
    try:
        r = requests.get(f"{PROM}/api/v1/targets", timeout=10)
        if r.status_code == 200:
            targets = r.json().get("data", {}).get("activeTargets", [])
            for t in targets:
                labels = t.get("labels", {})
                inst = labels.get("instance", "").split(":")[0]
                asset = labels.get("asset") or labels.get("Asset")
                if inst and asset:
                    assets_map[inst] = asset
    except Exception as e:
        print(f"Warning fetching targets: {e}", file=sys.stderr)
    print(f"Cached asset labels for {len(assets_map)} instances.")
    return assets_map

def fmt_gb(v):
    if not v or v <= 0:
        return ""
    gb = v / (1024 ** 3)
    if gb >= 1000:
        return f"{gb / 1024:.2f} TB"
    return f"{gb:.2f} GB"

def get_trading_status(dt):
    """
    Checks if datetime dt falls into Trading or Non-Trading:
    - Saturdays & Sundays: Non-Trading
    - Declared Exchange Holidays: Non-Trading
    - Normal weekdays: 9:00 AM to 11:55 PM (09:00:00 to 23:55:00) -> Trading, else Non-Trading
    """
    # 5 = Saturday, 6 = Sunday
    if dt.weekday() in (5, 6):
        return "Non-Trading"
    
    date_str = dt.strftime("%Y-%m-%d")
    if date_str in EXCHANGE_HOLIDAYS:
        return "Non-Trading"
    
    t = dt.time()
    if dtime(9, 0, 0) <= t <= dtime(23, 55, 0):
        return "Trading"
    return "Non-Trading"

def extract_field(text, field_name):
    if not text:
        return ""
    m = re.search(rf'\b{field_name}[:=]\s*(.+?)(?=\s+[a-zA-Z0-9_\-]+:|$|\n|\])', text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m2 = re.search(rf'{field_name}[:=]\s*([A-Za-z0-9\-_&\.]+)', text, re.IGNORECASE)
    return m2.group(1).strip() if m2 else ""

def extract_volume(full_text):
    m_vol = re.search(r'(?:Drive|volume)[:=]?\s*([A-Z]:)', full_text, re.IGNORECASE) or \
            re.search(r'(?:Mountpoint|mountpoint)[:=]?\s*([/\w\-_]+)', full_text, re.IGNORECASE)
    if m_vol:
        val = m_vol.group(1).strip()
        return val.upper() if ":" in val else val
    return ""

def determine_vital(alert, full_text):
    al = (alert or "").lower()
    if "disk" in al or "rootdisk" in al or "space" in al:
        return "Disk"
    elif "memory" in al or "mem" in al:
        return "Memory"
    elif "cpu" in al or "load" in al:
        return "CPU"
    elif "ssl" in al or "cert" in al:
        return "SSL"
    elif "network" in al or "traffic" in al or "bandwidth" in al:
        return "Network"
    elif "uptime" in al:
        return "Uptime"
    elif "down" in al or "instance" in al or "port" in al:
        return "Instance/Port"
    
    db = extract_field(full_text, "database")
    if db:
        return db
    return "Other"

def main():
    start_total_time = time.time()
    print("=================================================================")
    print("Starting Alertmanager Log Collector & Excel Report Generator")
    print(f"Target Range: {START_DATE.strftime('%Y-%m-%d')} to {END_DATE.strftime('%Y-%m-%d')}")
    print(f"Scope: All Critical Alerts")
    print("=================================================================")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    hw_specs = get_hardware_specs()
    prom_assets = get_prometheus_assets()

    print(f"Opening and streaming log file: {LOG_FILE}...")
    if not os.path.exists(LOG_FILE):
        print(f"Error: Log file {LOG_FILE} does not exist!", file=sys.stderr)
        sys.exit(1)

    # Initialize XlsxWriter in constant_memory mode for streaming
    wb = xlsxwriter.Workbook(EXCEL_OUTPUT, {"constant_memory": True})
    ws = wb.add_worksheet("Critical_Alerts")

    # Header style formatting
    header_format = wb.add_format({
        'bold': True,
        'bg_color': '#1F497D',
        'font_color': '#FFFFFF',
        'border': 1,
        'align': 'center',
        'valign': 'vcenter'
    })

    # Write headers to Excel
    ws.write_row(0, 0, HEADERS, header_format)

    # Open CSV writer simultaneously
    csv_file = open(CSV_OUTPUT, "w", newline="", encoding="utf-8")
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(HEADERS)

    row_count = 0
    scanned_lines = 0
    last_log_time = time.time()

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            scanned_lines += 1
            if scanned_lines % 200000 == 0:
                elapsed = time.time() - last_log_time
                print(f"Scanned {scanned_lines:,} lines | Matched {row_count:,} critical records ({elapsed:.1f}s)")
                last_log_time = time.time()

            # Fast pre-filtering: must be Critical and match year/month pattern
            if "critical" not in line.lower() and "crit" not in line.lower():
                continue

            # Quick date match for 2025-12 through 2026-08
            if not ("2025-12-" in line or any(f"2026-{m:02d}-" in line for m in range(1, 9))):
                continue

            try:
                a = json.loads(line)
            except Exception:
                continue

            # Timestamp parsing
            ts_str = a.get("timestamp") or a.get("startsAt") or ""
            if not ts_str:
                continue

            try:
                dt_obj = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                ts = dt_obj if dt_obj.tzinfo else dt_obj.replace(tzinfo=timezone.utc)
            except Exception:
                continue

            if ts < START_DATE or ts > END_DATE:
                continue

            # Alert details
            alert = a.get("alertname") or a.get("labels", {}).get("alertname") or ""
            sev = a.get("severity") or a.get("labels", {}).get("severity") or ""
            if not str(sev).strip().lower().startswith("critical") and "crit" not in str(sev).strip().lower():
                continue

            inst = (a.get("instance") or a.get("labels", {}).get("instance") or "").split(":")[0]
            desc = a.get("description") or a.get("annotations", {}).get("description") or ""
            summ = a.get("summary") or a.get("annotations", {}).get("summary") or ""
            full_text = f"{summ}\n{desc}"

            # Hardware specs
            spec = hw_specs.get(inst, {})
            cpu_cores = spec.get("cpu_cores")
            mem_total_bytes = spec.get("mem_total_bytes")
            disks = spec.get("disks", {})

            # Extracted metadata
            company = a.get("company") or extract_field(full_text, "company") or "SMC"
            asset = a.get("asset") or a.get("Asset") or extract_field(full_text, "Asset") or extract_field(full_text, "asset") or prom_assets.get(inst, "")
            job = a.get("job") or a.get("labels", {}).get("job") or extract_field(full_text, "job") or "alertmanager"
            group = a.get("group") or a.get("labels", {}).get("group") or extract_field(full_text, "group") or "N/A"
            group1 = a.get("group1") or a.get("labels", {}).get("group1") or extract_field(full_text, "group1") or ""

            # Vital classification
            vital_type = determine_vital(alert, full_text)

            # Volume extraction for Disk alerts
            volume = extract_volume(full_text) if vital_type == "Disk" else ""

            # Total disk bytes lookup
            total_disk_bytes = None
            if vital_type == "Disk":
                if volume:
                    total_disk_bytes = disks.get(volume)
                    if not total_disk_bytes:
                        for d_k, d_v in disks.items():
                            if d_k.lower() == volume.lower():
                                total_disk_bytes = d_v
                                break
                if not total_disk_bytes and disks:
                    total_disk_bytes = list(disks.values())[0]

            # Used percentage and Free Space extraction
            m_used = re.search(r'Used\s*=\s*([\d.]+)%', desc) or re.search(r'(\d+)%', str(sev))
            used_pct = float(m_used.group(1)) if m_used else None

            m_free = re.search(r'(?:Free Space|Available)\s*=\s*([0-9\.\s\wGBTB]+)', desc, re.IGNORECASE)
            free_str = ""
            if m_free:
                raw_free = m_free.group(1).strip()
                m_clean = re.search(r'([0-9.]+\s*(?:GB|MB|TB|KB|%))', raw_free, re.IGNORECASE)
                free_str = m_clean.group(1).strip() if m_clean else raw_free.split('\n')[0].strip()

            cpu_str = f"{cpu_cores} Core" if cpu_cores is not None else ("N/A" if vital_type == "CPU" else "")
            mem_total_str = fmt_gb(mem_total_bytes) if vital_type == "Memory" else ""
            disk_total_str = fmt_gb(total_disk_bytes) if vital_type == "Disk" else ""
            used_str = f"{used_pct:.2f}%" if used_pct is not None else ""

            if vital_type == "Memory":
                if mem_total_bytes and used_pct is not None:
                    tot_gb = mem_total_bytes / (1024 ** 3)
                    used_gb = tot_gb * (used_pct / 100)
                    free_gb = tot_gb - used_gb
                    free_str = fmt_gb(free_gb * (1024**3))
                    used_str = fmt_gb(used_gb * (1024**3))
            elif vital_type == "Disk":
                if total_disk_bytes and used_pct is not None:
                    tot_gb = total_disk_bytes / (1024 ** 3)
                    used_gb = tot_gb * (used_pct / 100)
                    free_gb = tot_gb - used_gb
                    free_str = fmt_gb(free_gb * (1024**3))
                    used_str = fmt_gb(used_gb * (1024**3))
            elif vital_type == "CPU":
                if used_pct is not None:
                    used_str = f"{used_pct:.2f}%"
                    free_str = f"{100 - used_pct:.2f}%"

            # Trading Hours / Non Trading Hours check
            trading_status = get_trading_status(ts)

            # Build record row in exact order
            row_data = [
                ts.strftime("%d:%B:%Y %H:%M:%S"),
                ts.strftime("%Y"),
                ts.strftime("%B"),
                ts.strftime("%A"),
                trading_status,
                alert,
                company,
                asset,
                inst,
                job,
                group,
                group1,
                sev,
                vital_type,
                cpu_str,
                mem_total_str,
                disk_total_str,
                volume,
                free_str,
                used_str
            ]

            row_count += 1
            ws.write_row(row_count, 0, row_data)
            csv_writer.writerow(row_data)

    print(f"\nCompleted data extraction: {row_count:,} rows collected.")
    print("Finalizing and closing Excel workbook...")
    wb.close()
    csv_file.close()

    # Create copies in File-upload and current directory
    excel_upload = os.path.join(UPLOAD_DIR, os.path.basename(EXCEL_OUTPUT))
    csv_upload = os.path.join(UPLOAD_DIR, os.path.basename(CSV_OUTPUT))
    shutil.copyfile(EXCEL_OUTPUT, excel_upload)
    shutil.copyfile(CSV_OUTPUT, csv_upload)

    excel_local = os.path.join(LOCAL_DIR, os.path.basename(EXCEL_OUTPUT))
    csv_local = os.path.join(LOCAL_DIR, os.path.basename(CSV_OUTPUT))
    shutil.copyfile(EXCEL_OUTPUT, excel_local)
    shutil.copyfile(CSV_OUTPUT, csv_local)

    total_time = time.time() - start_total_time
    print("=================================================================")
    print("SUCCESS: Report generation completed!")
    print(f"Total Rows Written: {row_count:,}")
    print(f"Excel Output:  {EXCEL_OUTPUT} ({os.path.getsize(EXCEL_OUTPUT):,} bytes)")
    print(f"Uploaded To:   {excel_upload}")
    print(f"Local Copy:    {excel_local}")
    print(f"CSV Output:    {CSV_OUTPUT} ({os.path.getsize(CSV_OUTPUT):,} bytes)")
    print(f"Total Execution Time: {total_time:.2f} seconds")
    print("=================================================================")

if __name__ == "__main__":
    main()
