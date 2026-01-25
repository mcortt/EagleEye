# 🦅 EagleEye: Advanced Email Forensics

![Version](https://img.shields.io/badge/version-1.0-blue) ![Thunderbird](https://img.shields.io/badge/Thunderbird-115%2B-fea40f) ![License](https://img.shields.io/badge/license-MIT-green)

**EagleEye** is a professional-grade cybersecurity extension for Mozilla Thunderbird. It analyzes the "Received" headers of incoming emails to trace their origin, detect VPNs/Proxies, and score the sender's reputation against global threat intelligence databases.

## 🚀 Features

* **🛡️ IP Reputation Analysis:** Automatically queries **AbuseIPDB** to score the sender's IP.
* **🕵️ VPN & Proxy Detection:** Uses **vpnapi.io** to detect if the sender is hiding behind a VPN, Tor, or Public Proxy.
* **📍 Hop Visualization:** Maps the routing path from the sender to your inbox, visualizing geographic hops.
* **🏢 Network Context:** Displays the ISP, ASN, Usage Type (Data Center vs. Residential), and Timezone.
* **🚦 Smart Alerts:**
    * **GREEN:** Clean residential/corporate IPs.
    * **ORANGE:** Suspicious usage (VPNs, Data Centers) or low-level abuse history.
    * **RED:** High-risk IPs, known botnets, or countries you have blacklisted.
* **☁️ Cloud Intelligence:** Distinguishes between "Safe" cloud providers (AWS, Google Cloud) and suspicious VPS hosts.
* **🌑 Adaptive UI:** Fully supports Thunderbird Dark and Light modes.

## ⚙️ Installation & Setup

### 1. Install the Extension
Download the latest `.xpi` release or load the extension manually via **Debug Add-ons**.

### 2. Get Your Free API Keys
EagleEye relies on industry-standard threat intelligence APIs. You will need to obtain free keys for the extension to function:
1.  **[AbuseIPDB](https://www.abuseipdb.com/):** (Required) For abuse confidence scores.
2.  **[vpnapi.io](https://vpnapi.io/):** (Required) For VPN/Proxy detection.
3.  **[ipinfo.io](https://ipinfo.io/):** (Optional) For detailed hop mapping.

### 3. Configure
Open the **EagleEye Settings** in Thunderbird:
* Paste your API keys.
* Set your **Risk Threshold** (Default: 50%).
* (Optional) Blacklist specific countries or whitelist specific Cloud Providers.

## 🔒 Privacy & Data Usage

EagleEye is designed with privacy as a priority:
* **Local Processing:** All logic runs locally in your Thunderbird client.
* **Direct API Calls:** IP addresses are sent *directly* from your computer to the API providers (AbuseIPDB, vpnapi). No middleman servers are used.
* **Zero Analytics:** This extension collects **no** usage data, telemetry, or personal information.
* **Auto-Cleanup:** The extension includes a garbage collector that automatically deletes cached IP data after 7 days and email analysis data after 24 hours.

## 🛠️ Development

To build from source:
1.  Clone this repository.
2.  Zip the contents (ensure `manifest.json` is at the root).
3.  Load into Thunderbird via `Tools > Developer Tools > Debug Add-ons`.

---
*Built by [Your Name/Handle]*