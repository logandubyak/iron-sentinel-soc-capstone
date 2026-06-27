#!/usr/bin/env python3
"""
parse_nessus.py

Parses a Nessus .nessus scan export (XML format) and produces a clean,
severity-sorted CSV summary of findings. Built for the Iron Sentinel
SOC capstone to demonstrate basic security automation / scripting skills.

Usage:
    python3 parse_nessus.py scan_results.nessus -o findings.csv
"""

import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Nessus severity levels: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
SEVERITY_LABELS = {
    "0": "Info",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",
}

# Used to sort findings worst-first
SEVERITY_SORT_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}


def parse_nessus_file(filepath):
    """
    Parses a .nessus XML file and returns a list of finding dicts.
    Each finding includes host, plugin name, severity, CVSS score,
    port, protocol, and a short description.
    """
    try:
        tree = ET.parse(filepath)
    except ET.ParseError as e:
        print(f"Error: could not parse '{filepath}' as XML — {e}")
        sys.exit(1)

    root = tree.getroot()
    findings = []

    # .nessus files are structured as Report > ReportHost > ReportItem
    for report_host in root.iter("ReportHost"):
        host_name = report_host.get("name", "unknown-host")

        for item in report_host.findall("ReportItem"):
            severity_code = item.get("severity", "0")
            severity_label = SEVERITY_LABELS.get(severity_code, "Unknown")

            plugin_name = item.get("pluginName", "Unnamed Finding")
            port = item.get("port", "0")
            protocol = item.get("protocol", "")
            svc_name = item.get("svc_name", "")

            cvss_elem = item.find("cvss_base_score")
            cvss_score = cvss_elem.text.strip() if cvss_elem is not None and cvss_elem.text else "N/A"

            desc_elem = item.find("description")
            description = desc_elem.text.strip().replace("\n", " ") if desc_elem is not None and desc_elem.text else ""
            # Trim long descriptions for CSV readability
            if len(description) > 200:
                description = description[:200].rstrip() + "..."

            solution_elem = item.find("solution")
            solution = solution_elem.text.strip().replace("\n", " ") if solution_elem is not None and solution_elem.text else ""
            if len(solution) > 200:
                solution = solution[:200].rstrip() + "..."

            # Skip pure Info findings by default — they add noise.
            # Comment this out if you want everything included.
            if severity_label == "Info":
                continue

            findings.append({
                "host": host_name,
                "port": port,
                "protocol": protocol,
                "service": svc_name,
                "severity": severity_label,
                "cvss_score": cvss_score,
                "finding": plugin_name,
                "description": description,
                "solution": solution,
            })

    return findings


def write_csv(findings, output_path):
    """Writes findings to CSV, sorted Critical -> High -> Medium -> Low."""
    findings_sorted = sorted(
        findings,
        key=lambda f: (SEVERITY_SORT_ORDER.get(f["severity"], 99), f["host"])
    )

    fieldnames = ["host", "port", "protocol", "service", "severity",
                  "cvss_score", "finding", "description", "solution"]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings_sorted)

    return findings_sorted


def print_summary(findings_sorted):
    """Prints a quick severity breakdown to the console."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings_sorted:
        if f["severity"] in counts:
            counts[f["severity"]] += 1

    print("\n--- Vulnerability Summary ---")
    for sev in ["Critical", "High", "Medium", "Low"]:
        print(f"  {sev:<10} {counts[sev]}")
    print(f"  {'Total':<10} {len(findings_sorted)}")
    print("------------------------------\n")

    print("Top 5 findings:")
    for f in findings_sorted[:5]:
        print(f"  [{f['severity']}] {f['host']}:{f['port']} — {f['finding']} (CVSS {f['cvss_score']})")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Parse a Nessus .nessus export into a clean, prioritized CSV."
    )
    parser.add_argument("input_file", help="Path to the .nessus scan export file")
    parser.add_argument(
        "-o", "--output",
        default="nessus_findings.csv",
        help="Output CSV path (default: nessus_findings.csv)"
    )
    args = parser.parse_args()

    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: file not found — {input_path}")
        sys.exit(1)

    print(f"Parsing {input_path} ...")
    findings = parse_nessus_file(input_path)

    if not findings:
        print("No findings above Info severity were found in this scan.")
        sys.exit(0)

    findings_sorted = write_csv(findings, args.output)
    print(f"Wrote {len(findings_sorted)} findings to {args.output}")
    print_summary(findings_sorted)


if __name__ == "__main__":
    main()
