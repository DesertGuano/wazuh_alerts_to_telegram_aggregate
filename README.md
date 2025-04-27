# README.md

# Wazuh Alerts to Telegram (Aggregated Version with AbuseIPDB Integration)

## Overview
This script receives alerts from Wazuh, formats them into structured HTML reports, and sends them to a Telegram chat.
It also integrates with AbuseIPDB to enrich alerts that involve external IP addresses.

Originally developed by [Hasitha Upekshitha](https://medium.com/@hasithaupekshitha97/wazuh-alerts-to-telegram-fb9d15b2e544) and heavily modified for extended functionality.

## Features
- Sends Wazuh alerts to Telegram.
- Groups multiple events into a single message (aggregation).
- Updates the message every 10 events.
- Posts a milestone notification every 500 events.
- Generates detailed HTML reports.
- Performs AbuseIPDB lookups for external IPs.
- Retry logic for Telegram API failures.

## Requirements
- Python 3.x
- `requests` library

Install dependencies:
```bash
pip install requests
```

## Configuration
- Replace `<Your Telegram Chat ID>` with your target chat ID.
- Replace `<Your AbuseIPDB API Key>` with a valid AbuseIPDB API key.
- When running the script, provide the correct Telegram Bot API Hook URL.

Example:
```bash
python3 wazuh_telegram_alerts.py /path/to/alert.json unused https://api.telegram.org/bot<your-bot-token>/sendMessage
```

## Usage in Wazuh
In your `ossec.conf`, configure the integration:
```xml
<integration>
  <name>custom-telegram</name>
  <hook_url>https://api.telegram.org/bot<your-bot-token>/sendMessage</hook_url>
  <alert_format>json</alert_format>
</integration>
```

## License
This work is based on the original project by Hasitha Upekshitha. Please respect the original author's rights and link back to the original project if you distribute this code.

---

Feel free to contribute or suggest improvements!
