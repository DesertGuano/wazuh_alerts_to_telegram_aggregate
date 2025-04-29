# README.md

# 🚨 Wazuh Alerts to Telegram (Aggregated Version with AbuseIPDB Integration)

## 📖 Overview
This script collects alerts from **Wazuh**, formats them into structured **HTML reports**, and sends them to a **Telegram chat**.
It also integrates with **AbuseIPDB** to enrich alerts involving external IP addresses, and generates a direct **ChatGPT** analysis link for every event.

Originally developed by [Hasitha Upekshitha](https://medium.com/@hasithaupekshitha97/wazuh-alerts-to-telegram-fb9d15b2e544) and heavily modified by **Pavel Klaine** for extended functionality.
[Telegram Integration with Wazuh](https://github.com/Hasitha9796/Wazuh-Integrations/tree/1b7a26df448d5b2ab88aef97ec8b05569a9c660c/Telegram%20Integration%20with%20Wazuh)
---

## ✨ Features
- 🚀 Sends Wazuh alerts directly to Telegram.
- 📦 Groups multiple events into a single aggregated message.
- 🔄 Updates the aggregation every 10 events.
- 🎯 Posts milestone notifications every 500 events.
- 📄 Generates structured HTML reports for each alert.
- 🌍 Enriches external IP addresses via AbuseIPDB lookups.
- 🔁 Implements retry logic for Telegram API failures.
- 🤖 Creates ChatGPT prompt links for deeper event analysis.

---

## 🛠️ Requirements
- Python 3.x
- `requests` library

Install dependencies:
```bash
pip install requests
```

---

## ⚙️ Configuration
- Replace `<Your Telegram Chat ID>` with your target chat ID.
- Replace `<Your AbuseIPDB API Key>` with a valid AbuseIPDB API key.
- Provide the correct Telegram Bot API Hook URL when running the script.

Example usage:
```bash
python3 wazuh_telegram_alerts.py /path/to/alert.json unused https://api.telegram.org/bot<your-bot-token>/sendMessage
```

---

## 🔗 Usage in Wazuh
Configure the integration inside your `ossec.conf`:
```xml
<integration>
  <name>custom-telegram</name>
  <hook_url>https://api.telegram.org/bot<your-bot-token>/sendMessage</hook_url>
  <alert_format>json</alert_format>
</integration>
```

---

## 📜 License
This work is based on the original project by **Hasitha Upekshitha**. 
Please respect the original author's rights and provide appropriate credit if redistributing this code.

---

## 🙌 Feel free to explore and use this project!
