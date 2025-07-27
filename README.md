# 📡 HomeIDS – IoT Intrusion Detection System

**HomeIDS** is a modular, plug-and-play intrusion detection system (IDS) tailored for smart home environments. Built for the Raspberry Pi 4, it passively monitors and analyzes IoT traffic using Suricata, behavioral detection, and a real-time dashboard. Devices connect to a dedicated Wi-Fi access point (wlan1) hosted by the Pi.

---

## 🧰 Features

- 🔍 Dual-engine detection: Suricata (signatures) + Behavioral engine (Python)
- 📶 Raspberry Pi broadcasts Wi-Fi AP (`HomeIDS`) on `wlan1`
- 🧠 Real-time CVE detection, port scans, brute-force login attempts
- 📊 Streamlit dashboard running on `http://<pi_ip>:1337`
- 🧱 Firewall, DHCP, and NAT setup for AP isolation
- ✅ Systemd auto-start and status monitoring
- 📦 Lightweight footprint with Python and SQLite support (planned)

---

## 💻 Setup Instructions

### 1. Flash Raspberry Pi with Raspberry Pi OS Lite

- Recommended: Raspberry Pi 4 Model B (2GB or higher)
- Default user: `admin` (or configure your own)
- Set correct **timezone** and **locale** during setup

---

### 2. Clone the Repository

```bash
git clone https://github.com/LeviMillhollon/iot_ids.git
cd iot_ids
```

---

### 3. Run the Automated Setup Script

This script:
- Installs Suricata, hostapd, dnsmasq
- Configures a Wi-Fi AP on `wlan1`
- Enables NAT and firewall rules
- Creates systemd services for:
  - `iotids.service` (detection engine)
  - `iot-ids-dashboard.service` (dashboard)
  - `wlan1-down.service` (network prep)

```bash
chmod +x setup_iot_ids.sh
sudo ./setup_iot_ids.sh
```

---

### 4. Dashboard Access

Once running:

- Access dashboard on the Pi:  
  `http://localhost:1337`

- Access from another device:  
  `http://10.10.0.1:1337` (when connected to HomeIDS Wi-Fi)

---

## ⚙️ Development Tools

- Python 3.8+ (ensure it's installed with `python3 --version`)
- Virtual environment recommended:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

> Requirements include: `scapy`, `streamlit`, `pandas`, `requests`, `netifaces`


## 📦 File Structure

```
iot_ids/
├── main.py                  # Orchestrator
├── dashboard.py             # Streamlit dashboard
├── detection.py             # Behavioral engine
├── discovery.py             # Device profiling
├── nmap_runner.py           # Active scan logic
├── logger.py                # JSONL logger
├── Device_setup.sh          # Setup script
└── alerts.jsonl             # Example alert output
```



## 📚 Resources

- [Alert Corpus (Google Doc)](https://docs.google.com/document/d/1TQV793w_Rc0TXcZHvD40LS-VkZSN9w8n/edit?usp=sharing)
- [Project Report (PDF)](https://github.com/LeviMillhollon/iot_ids/blob/main/HomeIDS_Report.pdf)


---

## Notes

- Ensure the Pi has both `eth0` (internet) and `wlan1` (AP) interfaces
- Reboot once after setup to finalize `denyinterfaces`
- If services fail, run:  
  `journalctl -u iotids.service --no-pager`


