#!/usr/bin/env python3
"""
daily_alert_collector.py

Automated Daily Alert Data Collector.
Runs daily (e.g., at 3:00 AM via Cron) to collect alerts for yesterday.
Appends rows to the current quarter's CSV file.
When a quarter changes, automatically starts writing to the new quarter's CSV file.
"""

import csv
import json
import os
import re
import requests
import shutil
import sys
from datetime import datetime, timezone, timedelta

PROM = "http://localhost:9090"
LOG_FILE = "/var/log/prometheus/alertmanager_events.log"
BASE_DIR = "/opt/audit_report"
FILE_UPLOAD_DIR = os.path.join(BASE_DIR, "File-upload")

HEADERS = [
    "Date", "Alert Name", "Asset", "Instance", "Job", "Group", "Severity", "Vital",
    "CPU Core", "Memory Total", "Total Disk Size", "Volume", "Free", "Used"
]

def prom_query(query):
    try:
        r = requests.get(f"{PROM}/api/v1/query", params={"query": query}, timeout=10)
        r.raise_for_status()
        return r.json().get("data", {}).get("result", [])
    except Exception:
        return []

def get_hardware_specs():
    specs = {}
    # CPU
    for r in prom_query('count(node_cpu_seconds_total{mode="idle"}) by (instance)'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        if inst:
            specs.setdefault(inst, {})["cpu_cores"] = int(r.get("value", [0, 0])[1])
    for r in prom_query('windows_cs_logical_processors'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        if inst and "cpu_cores" not in specs.get(inst, {}):
            specs.setdefault(inst, {})["cpu_cores"] = int(r.get("value", [0, 0])[1])

    # Memory
    for r in prom_query('node_memory_MemTotal_bytes'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        if inst:
            specs.setdefault(inst, {})["mem_total_bytes"] = float(r.get("value", [0, 0])[1])
    for r in prom_query('windows_cs_physical_memory_bytes'):
        inst = r.get("metric", {}).get("instance", "").split(":")[0]
        if inst and "mem_total_bytes" not in specs.get(inst, {}):
            specs.setdefault(inst, {})["mem_total_bytes"] = float(r.get("value", [0, 0])[1])

    # Disks
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

    return specs

def get_prometheus_assets():
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
    except Exception:
        pass
    return assets_map

def fmt_gb(v):
    if not v or v <= 0:
        return "N/A"
    gb = v / (1024 ** 3)
    if gb >= 1000:
        return f"{gb / 1024:.2f} TB"
    return f"{gb:.2f} GB"

def extract_field(text, field_name):
    m = re.search(rf'{field_name}[:=]\s*([A-Za-z0-9\-_&\.]+)', text or "", re.IGNORECASE)
    return m.group(1).strip() if m else ""

def get_quarter_filename(dt):
    """Determines the CSV filename based on the quarter of the given date."""
    year = dt.year
    month = dt.month
    if 1 <= month <= 3:
        quarter_str = f"{year}_01_01_to_{year}_03_31"
    elif 4 <= month <= 6:
        quarter_str = f"{year}_04_01_to_{year}_06_30"
    elif 7 <= month <= 9:
        quarter_str = f"{year}_07_01_to_{year}_09_30"
    else:
        quarter_str = f"{year}_10_01_to_{year}_12_31"
    
    return f"SMC_Alert_Report_{quarter_str}.csv"

def collect_daily_alerts(target_date=None):
    """
    Collects alerts for a specific date (defaults to YESTERDAY for 3:00 AM run).
    Appends to the appropriate quarter CSV file.
    """
    if target_date is None:
        if len(sys.argv) > 1:
            try:
                target_date = datetime.strptime(sys.argv[1], "%Y-%m-%d").date()
            except ValueError:
                pass
        if target_date is None:
            # Default to yesterday's full date in system local time (e.g. IST)
            target_date = (datetime.now().astimezone() - timedelta(days=1)).date()

    target_date_str = target_date.strftime("%Y-%m-%d")
    print(f"[{datetime.now().isoformat()}] Processing daily alerts for date: {target_date_str}")

    # Determine quarter CSV filename
    filename = get_quarter_filename(target_date)
    main_output = os.path.join(BASE_DIR, filename)
    upload_output = os.path.join(FILE_UPLOAD_DIR, filename)

    print(f"Target Quarter File: {filename}")

    # Fetch hardware specs and Prometheus assets
    hw_specs = get_hardware_specs()
    prom_assets = get_prometheus_assets()

    start_dt = datetime(target_date.year, target_date.month, target_date.day, 0, 0, 0, tzinfo=timezone.utc)
    end_dt   = datetime(target_date.year, target_date.month, target_date.day, 23, 59, 59, tzinfo=timezone.utc)

    records = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if target_date_str not in line:
                    continue
                line = line.strip()
                if not line:
                    continue
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

                alert = a.get("alertname", "")
                if not any(k in alert.lower() for k in ["disk", "cpu", "memory", "mem"]):
                    continue

                inst = a.get("instance", "").split(":")[0]
                sev = a.get("severity", "Critical")
                if not str(sev).strip().lower().startswith("critical"):
                    continue

                desc = a.get("description", "")
                summ = a.get("summary", "")
                full_text = f"{summ}\n{desc}"

                job = extract_field(full_text, "job") or "alertmanager"
                group = extract_field(full_text, "group") or "N/A"
                vital = extract_field(full_text, "company") or "SMC"
                asset = extract_field(full_text, "asset") or a.get("asset") or a.get("Asset") or prom_assets.get(inst, "")

                records.append({
                    "ts": ts,
                    "alert": alert,
                    "asset": asset,
                    "instance": inst,
                    "job": job,
                    "group": group,
                    "severity": sev,
                    "vital": vital,
                    "desc": desc,
                    "summary": summ
                })

    records.sort(key=lambda x: x["ts"])
    print(f"Extracted {len(records)} events for {target_date_str}.")

    # Check if destination CSV exists to write headers if creating a new file
    file_exists = os.path.exists(main_output)

    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(FILE_UPLOAD_DIR, exist_ok=True)

    with open(main_output, "a", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        if not file_exists:
            writer.writerow(HEADERS)
            print(f"Created new quarter file: {main_output}")

        for r in records:
            ts = r["ts"]
            alert = r["alert"]
            inst = r["instance"]
            sev = r["severity"]
            desc = r["desc"]
            summ = r["summary"]
            full_text = f"{summ}\n{desc}"

            spec = hw_specs.get(inst, {})
            cpu_cores = spec.get("cpu_cores", "N/A")
            mem_total_bytes = spec.get("mem_total_bytes")
            disks = spec.get("disks", {})

            m_vol = re.search(r'(?:Drive|volume)[:=]?\s*([A-Z]:)', full_text, re.IGNORECASE) or \
                    re.search(r'(?:Mountpoint|mountpoint)[:=]?\s*([/\w\-_]+)', full_text, re.IGNORECASE)
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

            m_free = re.search(r'(?:Free Space|Available)\s*=\s*([0-9\.\s\wGBTB]+)', desc, re.IGNORECASE)
            free_str = m_free.group(1).strip() if m_free else "N/A"

            vital_type = "Memory" if "memory" in alert.lower() else ("Disk" if "disk" in alert.lower() else ("CPU" if "cpu" in alert.lower() else r["vital"]))
            
            cpu_str = f"{cpu_cores} Core" if cpu_cores != "N/A" else "N/A"
            mem_total_str = fmt_gb(mem_total_bytes)
            disk_total_str = fmt_gb(total_disk_bytes)
            used_str = f"{used_pct:.2f}%" if used_pct is not None else "N/A"

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

            row = [
                ts.strftime("%d:%B:%Y %H:%M:%S"),
                alert,
                r.get("asset", ""),
                inst,
                r["job"],
                r["group"],
                sev,
                vital_type,
                cpu_str,
                mem_total_str if vital_type == "Memory" else "",
                disk_total_str if vital_type == "Disk" else "",
                volume if vital_type == "Disk" else "",
                free_str,
                used_str
            ]
            writer.writerow(row)

    # Sync to File-upload directory
    shutil.copyfile(main_output, upload_output)
    print(f"✅ Daily appended {len(records)} records into {main_output} & synced to {upload_output}")

if __name__ == "__main__":
    collect_daily_alerts()
