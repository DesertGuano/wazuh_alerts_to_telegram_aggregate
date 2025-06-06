# -*- coding: utf-8 -*-
"""
Wazuh Alerts to Telegram - Aggregated Version with AbuseIPDB Integration

Original Author: Hasitha Upekshitha
Original Article: https://medium.com/@hasithaupekshitha97/wazuh-alerts-to-telegram-fb9d15b2e544
Original Code: https://github.com/Hasitha9796/Wazuh-Integrations/tree/main/Telegram%20Integration%20with%20Wazuh

Modifications by: Pavel Klaine
Changes:
- Implemented event aggregation (batch updates every 10 events)
- Added AbuseIPDB lookup for external IP addresses
- Added HTML report generation for detailed event data
- Added milestone notifications every 500 events
- Improved error handling and retry logic for Telegram API
- Enhanced alert formatting and added a link to ChatGPT for event analysis
- Added CSS improvements to handle large event data tables (scrollable, word-wrap)
- Added responsive meta tag and media queries for mobile device optimization
- Set "Field" column to fixed 10% width in tables

Configuration:
- CHAT_ID: Set your Telegram chat ID (integer or string).
- ABUSEIPDB_API_KEY: Set your AbuseIPDB API key (string).
- HOOK_URL: Pass the correct Telegram Bot API URL as an argument when launching the script.

Example HOOK_URL:
https://api.telegram.org/bot<your-telegram-bot-token>/sendMessage

License:
The original work does not specify a license.
Please respect the original author's rights and provide attribution if redistributing this modified version.
"""

import sys
import json
import requests
import os
import tempfile
import traceback
from html import escape
from urllib.parse import quote
from datetime import datetime
import ast
import pathlib
import time
import ipaddress

# Constants
CHAT_ID = "CHAT_ID"
CACHE_FILE = pathlib.Path("/tmp/wazuh_tg_cache.json")
LOG_FILE = "/tmp/wazuh_tg_debug.log"
AGG_WINDOW = 300  # seconds to expire aggregation window
AGG_MAX_COUNT = 500  # maximum events in one aggregation
ABUSEIPDB_API_KEY = "ABUSEIPDB_API_KEY"

# Logging helper
def log(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")

# Parse inner JSON strings if present
def try_parse_inner_json(value):
    if isinstance(value, str) and value.strip().startswith(('{', '[')):
        try:
            return ast.literal_eval(value)
        except:
            return value
    return value

# Format a value as HTML (handles dict, list, primitive)
def format_value(value, level=0):
    value = try_parse_inner_json(value)
    if isinstance(value, dict):
        return format_dict_as_table(value, level + 1)
    if isinstance(value, list):
        rows = "".join(f"<tr><td colspan='2'>{format_value(item, level + 1)}</td></tr>" for item in value)
        return f"<table class='inner-table'>{rows}</table>"
    return escape(str(value))

# Convert a dict into an HTML table
def format_dict_as_table(d, level=0):
    html = "<table class='inner-table'>"
    html += "<thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>"
    for k, v in d.items():
        html += f"<tr><td>{escape(str(k))}</td><td>{format_value(v, level)}</td></tr>"
    html += "</tbody></table>"
    return html

# Generate colored badge for rule level
def get_level_badge(level):
    try:
        lvl = int(level)
    except:
        return escape(str(level))
    if lvl >= 13:
        return f"<span class='badge red'>🔥 {lvl}</span>"
    elif lvl >= 9:
        return f"<span class='badge orange'>⚠️ {lvl}</span>"
    elif lvl >= 5:
        return f"<span class='badge blue'>ℹ️ {lvl}</span>"
    else:
        return f"<span class='badge gray'>{lvl}</span>"

# Generate full HTML report file
def generate_html(agent, manager, rule_id, level, descr, loc, ts, data):
    parsed_table = format_dict_as_table(data)
    prompt = (
        "Please analyze the following Wazuh security alert and explain the possible threat or incident it indicates:\n\n"
        f"Agent: {agent}\n"
        f"Manager: {manager}\n"
        f"Rule: {rule_id} (Level: {level})\n"
        f"Description: {descr}\n"
        f"Location: {loc}\n"
        f"Timestamp: {ts}\n"
        f"Event data:\n{json.dumps(data, indent=2)}")
    gpt_url = f"https://chat.openai.com/?prompt={quote(prompt)}"

    css = """
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <style>
    body { background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; padding: 1rem; margin: 0; }
    .container { height: 95%; width: 95%; background: #1e293b; padding: 12px; border-radius: 12px; box-shadow: 0 0 10px rgba(255,82,82,0.2); }
    h1 { color: #f87171; font-size: 1.6rem; display: flex; align-items: center; }
    h1::before { content: '🔔'; margin-right: 0.5rem; }
    .meta p { margin: 0.3rem 0; font-size: 0.9rem; }
    .meta b { display: inline-block; min-width: 80px; color: #94a3b8; }
    .badge { padding: 0.2rem 0.5rem; border-radius: 6px; font-weight: bold; font-size: 0.8rem; }
    .red { background: #ef4444; }
    .orange { background: #f97316; }
    .blue { background: #3b82f6; }
    .gray { background: #64748b; }
    .section-title { color: #f87171; margin: 1rem 0 0.5rem; font-size: 1rem; }
    .inner-table { width: 100%; border-collapse: collapse; table-layout: fixed; word-break: break-word; margin-bottom: 1rem; display: block; max-height: 450px; overflow: auto; }
    .inner-table th, .inner-table td { padding: 6px; border: 1px solid #334155; text-align: left; font-size: 0.85rem; }
    .inner-table th { background: #334155; color: #cbd5e1; position: sticky; top: 0; }
    .inner-table tr:nth-child(even) td { background: #273449; }
    /* Fix first column width */
    .inner-table th:first-child, .inner-table td:first-child { width: 10%; max-width: 10%; white-space: nowrap; }
    .chatgpt-link { color: #60a5fa; text-decoration: none; font-weight: bold; font-size: 0.9rem; display: inline-block; margin-top: 0.5rem; }
    @media (max-width: 480px) {
        h1 { font-size: 1.4rem; }
        .meta b { min-width: 60px; }
        .inner-table th, .inner-table td { font-size: 0.75rem; padding: 4px; }
    }
    </style>
    """

    html = f"""
    <html>
    <head><meta charset='utf-8'>{css}<title>Wazuh Incident</title></head>
    <body>
    <div class='container'>
        <h1>Wazuh Security Alert</h1>
        <div class='meta'>
            <p><b>Agent:</b> {escape(agent)}</p>
            <p><b>Manager:</b> {escape(manager)}</p>
            <p><b>Rule:</b> {escape(rule_id)}</p>
            <p><b>Level:</b> {get_level_badge(level)}</p>
            <p><b>Description:</b> {escape(descr)}</p>
            <p><b>Location:</b> {escape(loc)}</p>
            <p><b>Timestamp:</b> {escape(ts)}</p>
        </div>
        <div class='section-title'>Event Data</div>
        {parsed_table}
        <p><a class='chatgpt-link' href='{gpt_url}' target='_blank'>Ask ChatGPT for Explanation</a></p>
    </div>
    </body>
    </html>
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode="w", encoding="utf-8")
    tmp.write(html)
    tmp.close()
    return tmp.name

# (rest of script unchanged)
# Cache handling
def load_cache():
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except:
            return {}
    return {}

def save_cache(data):
    CACHE_FILE.write_text(json.dumps(data))

# IP utils
def is_external_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved)
    except ValueError:
        return False

def check_abuseipdb(ip):
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json().get("data", {})
    except Exception as e:
        log(f"AbuseIPDB lookup failed for {ip}: {e}")
    return {}

# Telegram request with retries
def tg_request(url, payload=None, files=None):
    for attempt in range(3):
        try:
            resp = requests.post(url, data=payload, files=files, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            log(f"Telegram send attempt {attempt+1} failed: {e}")
            time.sleep(2)
    return {}

# Main logic
def main():
    if len(sys.argv) < 4:
        raise SystemExit("Usage: <alert_file> <unused> <hook_url>")

    alert_path, hook_url = sys.argv[1], sys.argv[3]
    with open(alert_path, 'r', encoding='utf-8') as f:
        alert = json.load(f)

    agent = alert.get('agent', {}).get('name', 'N/A')
    manager = alert.get('manager', {}).get('name', 'N/A')
    rule_id = str(alert.get('rule', {}).get('id', 'N/A'))
    rule_level = alert.get('rule', {}).get('level', 'N/A')
    rule_descr = alert.get('rule', {}).get('description', 'N/A')
    location = alert.get('location', 'N/A')
    timestamp = alert.get('timestamp', 'N/A')
    data_section = alert.get('data', {}) if isinstance(alert.get('data'), dict) else {}

    srcip = data_section.get('srcip', '')
    if srcip and is_external_ip(srcip):
        abuse_data = check_abuseipdb(srcip)
        if abuse_data:
            data_section['AbuseIPDB_Info'] = {
                'Country': abuse_data.get('countryCode', 'N/A'),
                'Abuse Score': abuse_data.get('abuseConfidenceScore', 'N/A'),
                'ISP': abuse_data.get('isp', 'N/A'),
                'Domain': abuse_data.get('domain', 'N/A'),
                'Total Reports': abuse_data.get('totalReports', 'N/A'),
                'Is Whitelisted': abuse_data.get('isWhitelisted', 'N/A'),
            }

    cache = load_cache()
    now = int(time.time())
    key = f"{rule_id}|{srcip}"
    entry = cache.get(key)
    expired = entry and (now - entry['last'] > AGG_WINDOW or entry['count'] >= AGG_MAX_COUNT)
    new_series = not entry or expired

    message = (
        f"🔔 *Wazuh Alert*\n\n"
        f"*Agent:* `{agent}`\n"
        f"*Manager:* `{manager}`\n"
        f"*Rule:* `{rule_id}` (Level: `{rule_level}`)\n"
        f"*Description:* _{rule_descr}_\n"
        f"*Location:* `{location}`\n"
        f"*Timestamp:* `{timestamp}`\n\n"
        f"*Event Data:*\nSee attached HTML report."
    )

    if new_series:
        if entry and entry['count'] >= AGG_MAX_COUNT:
            summary = f"✅ Aggregation complete for rule {rule_id}\nTotal: {entry['count']} events"
            tg_request(hook_url, {"chat_id": CHAT_ID, "text": summary, "parse_mode": "Markdown"})

        cache.pop(key, None)
        html_file = generate_html(agent, manager, rule_id, rule_level, rule_descr, location, timestamp, data_section)
        caption = message + f"\n\n📈 Count: 1"
        resp = tg_request(hook_url.replace("sendMessage", "sendDocument"),
                          {"chat_id": CHAT_ID, "caption": caption[:1020], "parse_mode": "Markdown"},
                          files={"document": open(html_file, 'rb')})
        os.unlink(html_file)
        msg_id = resp.get('result', {}).get('message_id') if resp else None
        if msg_id:
            cache[key] = {'msg_id': msg_id, 'count': 1, 'last': now, 'message': message}
        save_cache(cache)
        log(f"New aggregation started for {key}")
    else:
        entry['count'] += 1
        entry['last'] = now
        cache[key] = entry
        save_cache(cache)

        if entry['count'] % 10 == 0:
            new_caption = entry['message'] + f"\n\n📈 Count: {entry['count']}"
            tg_request(hook_url.replace("sendMessage", "editMessageCaption"),
                       {"chat_id": CHAT_ID, "message_id": entry['msg_id'], "caption": new_caption[:1020], "parse_mode": "Markdown"})
            log(f"Updated caption after {entry['count']} events for {key}")
        else:
            log(f"Aggregated {entry['count']} events for {key} without caption update")

        if entry['count'] % 500 == 0:
            summary = (
                f"🏆 Aggregation Milestone\n"
                f"Rule: {rule_id}\n"
                f"Current Count: {entry['count']} events\n"
                f"Agent: {agent}\n"
                f"Location: {location}\n"
                f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            tg_request(hook_url, {"chat_id": CHAT_ID, "text": summary, "parse_mode": "Markdown"})
            log(f"Sent milestone summary at {entry['count']} events for {key}")

# Entry point
if __name__ == '__main__':
    try:
        main()
    except Exception:
        error_trace = traceback.format_exc()
        log(f"Script crashed: {error_trace}")
        if len(sys.argv) > 3:
            requests.post(sys.argv[3], json={
                "chat_id": CHAT_ID,
                "text": f"❌ *Script crashed!*\n```{error_trace[:3900]}```",
                "parse_mode": "Markdown"
            })
