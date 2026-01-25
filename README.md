# 🦅 EagleEye: Advanced Email Forensics

![Version](https://img.shields.io/badge/version-1.1-blue) ![Thunderbird](https://img.shields.io/badge/Thunderbird-115%2B-fea40f) ![License](https://img.shields.io/badge/license-MIT-green)

**EagleEye** is a professional-grade cybersecurity extension for Mozilla Thunderbird. It provides real-time forensic analysis of incoming messages by tracing network hops, detecting anonymity networks (VPN/Tor), and validating cryptographic identity markers (DKIM/SPF/ARC) [cite: 2026-01-21, 2026-01-22].

---

## 🚦 Forensic Logic (TLP)

EagleEye utilizes a strict **Top-Down Hierarchy** to categorize email risk levels. It employs a "Veto System"—if any critical security check fails, the status is immediately escalated [cite: 2026-01-21].

### 🔴 RED (High Risk)
* **Blocked Country**: Source IP originates from a country on your blacklist [cite: 2026-01-21].
* **Reputation Threshold**: Abuse Confidence $Score \ge User Threshold$ [cite: 2026-01-21].
* **Security Fail (DKIM)**: Cryptographic proof of message tampering [cite: 2026-01-21].
* **Spoof Detected (SPF)**: Unauthorized sender identity (where $ARC \neq pass$) [cite: 2026-01-21].

### 🟠 ORANGE (Caution)
* **Auth Issue**: SPF "Softfail" or DMARC policy violation [cite: 2026-01-21].
* **Hidden Identity**: Sender is utilizing a VPN, Tor exit node, or Proxy (excluding whitelisted Cloud Providers) [cite: 2026-01-21].
* **Suspicious IP**: Abuse Confidence Score falls between $15\%$ and your custom limit [cite: 2026-01-21].

### 🟢 GREEN (Clean)
* **Cloud Server**: Verified origin from a whitelisted infrastructure provider (e.g., Microsoft 365, Google Workspace, Amazon SES) [cite: 2026-01-21].
* **Clean Sender**: Passed all forensic checks with a reputation score $\le 15\%$ [cite: 2026-01-21].

---

## ⚠️ Security Disclaimers

> [!WARNING]
> **"Clean" is not "Safe":** A "Clean Sender" status only indicates that the sending infrastructure has a neutral reputation and identity markers (SPF/DKIM) are valid [cite: 2026-01-21]. It does **not** guarantee the content of the email is safe. Legitimate accounts can be compromised to send phishing or malware. Always practice "Zero Trust" with links and attachments [cite: 2026-01-21].

> [!NOTE]
> **Not a Cryptographic Verifier:** EagleEye is a forensic reporting tool that displays the results of authentication checks performed by your mail server [cite: 2026-01-22]. It is **not** a replacement for dedicated cryptographic verification extensions like [DKIM Verifier](https://github.com/protomouse/dkim_verifier) [cite: 2026-01-22].

---

## 🚀 Features

* **🛡️ Multi-Vector Authentication:** Parsed results for **SPF, DKIM, DMARC, and ARC** displayed in a single view [cite: 2026-01-21, 2026-01-22].
* **🕵️ Anonymity Detection:** Real-time identification of VPN, Tor, and Proxy usage [cite: 2026-01-21].
* **📍 Hop Visualization:** Geographic mapping of the routing path from sender to inbox [cite: 2026-01-21].
* **🏢 Network Context:** Deep metadata including ISP, ASN, Usage Type, and Local Timezone [cite: 2026-01-21].
* **☁️ Cloud Whitelisting:** Intelligent filtering for major AWS, Google, and Microsoft IP ranges to reduce noise [cite: 2026-01-21].
* **🔗 Direct Drill-down:** One-click links to full **AbuseIPDB** forensic reports [cite: 2026-01-21].

## ⚙️ Installation & Setup

### 1. Install the Extension
Download the latest `.xpi` release or load the extension manually via **Debug Add-ons**.

### 2. Get Your Free API Keys
> [!IMPORTANT]
> **API Keys Required:** EagleEye is a "Bring Your Own Key" (BYOK) extension. It **will not function** without valid API keys from the providers below [cite: 2026-01-21].

1.  **[AbuseIPDB](https://www.abuseipdb.com/)**: (Required) Reputation scoring.
2.  **[vpnapi.io](https://vpnapi.io/)**: (Required) VPN/Proxy detection.
3.  **[ipinfo.io](https://ipinfo.io/)**: (Optional) Enhanced geographic mapping.

## 🔒 Privacy & Data Usage

* **Local Processing:** All forensic logic runs locally in your Thunderbird client [cite: 2026-01-21].
* **Zero Analytics:** No usage data, telemetry, or personal information is collected [cite: 2026-01-21].
* **Auto-Cleanup:** Built-in garbage collector deletes cached IP data after 7 days and email analysis data after 24 hours [cite: 2026-01-21].

---
*Built by mcortt*