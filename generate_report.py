
import os
import re
import json
import getpass
import requests
import urllib3

from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Splunk Enterprise configuration
SPLUNK_URL = "https://192.168.64.9:8089"
USERNAME = input("Splunk username: ").strip()
PASSWORD = getpass.getpass("Splunk password: ")

SEARCH_URL = SPLUNK_URL + "/services/search/jobs/export"

# Retrieve SSH events from the last 24 hours
SEARCH_QUERY = '''
search index=main sourcetype="macos:ssh_auth_live"
earliest=-24h latest=now
("Failed password" OR "Accepted")
| table _time host _raw
'''

def get_splunk_events():
    print("\nConnecting to Splunk...")

    response = requests.post(
        SEARCH_URL,
        auth=(USERNAME, PASSWORD),
        data={
            "search": SEARCH_QUERY,
            "output_mode": "json"
        },
        verify=False,
        timeout=120
    )

    if response.status_code != 200:
        raise Exception(
            f"Splunk API error: HTTP {response.status_code}\n"
            f"{response.text[:500]}"
        )

    events = []

    for line in response.text.splitlines():
        try:
            item = json.loads(line)
            result = item.get("result")

            if result:
                events.append(result)

        except json.JSONDecodeError:
            continue

    return events


def analyse_events(events):
    failed = []
    successful = []

    for event in events:
        raw = event.get("_raw", "")

        username_match = re.search(
            r"(?:Failed password for|Accepted \S+ for)\s+(\S+)",
            raw
        )

        ip_match = re.search(r"from\s+(\S+)", raw)

        username = username_match.group(1) if username_match else "Unknown"
        source_ip = ip_match.group(1) if ip_match else "Unknown"

        record = {
            "time": event.get("_time", "Unknown"),
            "host": event.get("host", "Unknown"),
            "username": username,
            "source_ip": source_ip,
            "raw": raw
        }

        if "Failed password" in raw:
            failed.append(record)
        elif "Accepted" in raw:
            successful.append(record)

    return failed, successful


def get_severity(count):
    if count >= 10:
        return "HIGH"
    elif count >= 5:
        return "MEDIUM"
    elif count >= 3:
        return "LOW"
    return "INFORMATIONAL"


def create_pdf(failed, successful):
    os.makedirs("reports", exist_ok=True)

    filename = datetime.now().strftime(
        "SOC_Incident_Report_%Y%m%d_%H%M%S.pdf"
    )
    filepath = os.path.join("reports", filename)

    document = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(
        "SOC SECURITY INCIDENT REPORT",
        styles["Title"]
    ))

    story.append(Paragraph(
        "Automated SSH Authentication Monitoring",
        styles["Heading2"]
    ))

    story.append(Spacer(1, 12))

    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles["Normal"]
    ))

    story.append(Paragraph(
        "Monitoring period: Last 24 hours",
        styles["Normal"]
    ))

    story.append(Spacer(1, 15))

    story.append(Paragraph(
        "1. Executive Summary",
        styles["Heading2"]
    ))

    summary_data = [
        ["Metric", "Total"],
        ["Total SSH Events", str(len(failed) + len(successful))],
        ["Failed Logins", str(len(failed))],
        ["Successful Logins", str(len(successful))]
    ]

    summary_table = Table(summary_data, colWidths=[90 * mm, 50 * mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263B5A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8)
    ]))

    story.append(summary_table)
    story.append(Spacer(1, 18))

    # Group failed attempts by username and source IP
    incidents = {}

    for event in failed:
        key = (event["username"], event["source_ip"])
        incidents[key] = incidents.get(key, 0) + 1

    story.append(Paragraph(
        "2. Failed Login Incident Analysis",
        styles["Heading2"]
    ))

    incident_data = [
        ["Username", "Source IP", "Attempts", "Severity"]
    ]

    for (username, source_ip), count in incidents.items():
        incident_data.append([
            username,
            source_ip,
            str(count),
            get_severity(count)
        ])

    if not incidents:
        incident_data.append([
            "No failed logins", "-", "0", "N/A"
        ])

    incident_table = Table(
        incident_data,
        colWidths=[42 * mm, 43 * mm, 28 * mm, 37 * mm]
    )

    incident_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263B5A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    story.append(incident_table)
    story.append(Spacer(1, 18))

    story.append(Paragraph(
        "3. Recent SSH Authentication Events",
        styles["Heading2"]
    ))

    recent_data = [
        ["Time", "Username", "Source IP", "Status"]
    ]

    combined = [
        (event, "FAILED") for event in failed
    ] + [
        (event, "SUCCESS") for event in successful
    ]

    combined.sort(
        key=lambda item: str(item[0]["time"]),
        reverse=True
    )

    for event, status in combined[:20]:
        recent_data.append([
            str(event["time"])[:19],
            event["username"],
            event["source_ip"],
            status
        ])

    if len(recent_data) == 1:
        recent_data.append(["No events found", "-", "-", "-"])

    recent_table = Table(
        recent_data,
        colWidths=[43 * mm, 35 * mm, 42 * mm, 30 * mm]
    )

    recent_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263B5A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("PADDING", (0, 0), (-1, -1), 6)
    ]))

    story.append(recent_table)
    story.append(Spacer(1, 18))

    story.append(Paragraph(
        "4. Analyst Notes",
        styles["Heading2"]
    ))

    story.append(Paragraph(
        "Severity is calculated using custom laboratory thresholds: "
        "10 or more failed attempts = HIGH, 5-9 = MEDIUM, "
        "3-4 = LOW, and fewer than 3 = INFORMATIONAL. "
        "These thresholds are for this lab and are not universal SOC standards.",
        styles["Normal"]
    ))

    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "This report is automatically generated from Splunk SSH "
        "authentication events. Source IP addresses such as ::1 "
        "and 127.0.0.1 represent localhost and may indicate controlled "
        "laboratory tests rather than external attacks.",
        styles["Normal"]
    ))

    document.build(story)

    return filepath


if __name__ == "__main__":
    try:
        events = get_splunk_events()

        print(f"Events retrieved: {len(events)}")

        failed, successful = analyse_events(events)

        print(f"Failed logins: {len(failed)}")
        print(f"Successful logins: {len(successful)}")

        pdf_path = create_pdf(failed, successful)

        print("\nPDF REPORT CREATED SUCCESSFULLY!")
        print(f"Location: {os.path.abspath(pdf_path)}")

    except Exception as error:
        print("\nREPORT GENERATION FAILED")
        print(error)

