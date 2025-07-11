#!/usr/bin/env bash
# setup_iot_ids.sh – Comprehensive setup for IoT IDS on Raspberry Pi using wlan1
# This script installs Suricata, configures a wireless AP, creates systemd services for the IDS and dashboard,
# grants necessary network capabilities, and provides inline comments explaining each step.

set -euo pipefail  # Exit on any error, treat unset variables as errors, and ensure piped commands fail on first error

# === Variables ===
# Define the user and group under which the IDS will run. Left blank runs as root.
IDS_USER=
IDS_GROUP=
# Base directory for the IDS code and virtual environment
IDS_DIR=/home/admin/IDS
PYTHON_BIN=${IDS_DIR}/venv/bin/python
MAIN_PY=${IDS_DIR}/main.py
# Wireless interface for the AP
AP_INTERFACE=wlan1
# Systemd directories and service file paths
SERVICE_DIR=/etc/systemd/system
IOTIDS_SERVICE=${SERVICE_DIR}/iotids.service
IOTIDS_DROPIN_DIR=${SERVICE_DIR}/iotids.service.d
IOTIDS_DROPIN=${IOTIDS_DROPIN_DIR}/20-netcaps.conf
# Service to bring down the AP interface before hostapd starts
DOWN_SERVICE=${SERVICE_DIR}/${AP_INTERFACE}-down.service
# Configuration files for DHCP and network interfaces
DHCPCD_CONF=/etc/dhcpcd.conf
INTERFACES_DIR=/etc/network/interfaces.d
# Hostapd and DNSMasq configuration
HOSTAPD_DEFAULT=/etc/default/hostapd
HOSTAPD_CONF=/etc/hostapd/hostapd.conf
DNSMASQ_CONF=/etc/dnsmasq.conf
# Dashboard service settings
DASHBOARD_SERVICE=${SERVICE_DIR}/iot-ids-dashboard.service
DASHBOARD_DIR=${IDS_DIR}
DASHBOARD_PYTHON=/home/pi/ids-dashboard/venv/bin/python3

# === 1. Install Suricata ===
# Suricata is the IDS engine for deep packet inspection and rule-based detection
echo "=== Installing Suricata ==="
# Remove any existing Suricata installations to avoid conflicts
apt update -y
apt purge -y suricata suricata-update || true
rm -rf /etc/suricata /var/lib/suricata /var/log/suricata
# Install Suricata and its update tool
apt install -y suricata suricata-update
# Verify installation and test configuration
suricata --version | head -n1     # display version
suricata -T | tail -n3           # test config syntax
# Fetch the latest rule sets
suricata-update
# Restart the daemon to apply updates
systemctl restart suricata
# Show a brief status to confirm it's running
systemctl status --no-pager suricata | head -n5

# === 2. Configure Wireless AP on wlan1 ===
echo "=== Configuring AP on ${AP_INTERFACE} ==="
# Install packages for AP functionality and persistent firewall rules
apt install -y hostapd dnsmasq iptables-persistent
# Stop services if already running to safely update configs
systemctl stop hostapd dnsmasq 2>/dev/null || true

# Prevent DHCP client and wpa_supplicant from managing the AP interface
grep -q "denyinterfaces ${AP_INTERFACE}" ${DHCPCD_CONF} || \
  printf "\n# IoT-IDS AP interface configuration\ndenyinterfaces ${AP_INTERFACE}\nnohook wpa_supplicant\n" >> ${DHCPCD_CONF}
systemctl mask wpa_supplicant@${AP_INTERFACE}.service

# Assign a static IP to the AP interface for client devices
cat > ${INTERFACES_DIR}/${AP_INTERFACE} <<EOF
auto ${AP_INTERFACE}
iface ${AP_INTERFACE} inet static
    address 10.10.0.1
    netmask 255.255.255.0
EOF

# Configure hostapd with SSID, security, and driver settings
echo "DAEMON_CONF=${HOSTAPD_CONF}" > ${HOSTAPD_DEFAULT}
cat > ${HOSTAPD_CONF} <<EOF
interface=${AP_INTERFACE}
driver=nl80211
ssid=HomeIDS
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
auth_algs=1
wpa=2
rsn_pairwise=CCMP
wpa_key_mgmt=WPA-PSK
wpa_passphrase=myhomeids
EOF

# Set up DNSMasq for DHCP service on the AP subnet
mv ${DNSMASQ_CONF} ${DNSMASQ_CONF}.orig 2>/dev/null || true
cat > ${DNSMASQ_CONF} <<EOF
interface=${AP_INTERFACE}
dhcp-range=10.10.0.50,10.10.0.150,255.255.255.0,12h
EOF

# Enable IP forwarding and configure NAT so AP clients can reach the internet
sed -i 's/^#\?net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1
# Clear existing iptables rules and set up NAT
iptables -F
iptables -t nat -F
iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i ${AP_INTERFACE} -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o ${AP_INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT
netfilter-persistent save

# Enable and start network services for the AP
systemctl unmask hostapd
systemctl enable hostapd dnsmasq suricata
systemctl restart dhcpcd
systemctl start hostapd dnsmasq suricata

# === 3. Create wlan1-down Service ===
# Ensures the AP interface is down before hostapd initializes to avoid conflicts
echo "=== Creating ${AP_INTERFACE}-down service ==="
tee ${DOWN_SERVICE} > /dev/null <<EOF
[Unit]
Description=Bring down ${AP_INTERFACE} before hostapd starts
Before=hostapd.service
After=local-fs.target sys-subsystem-net-devices-${AP_INTERFACE}.device

[Service]
Type=oneshot
ExecStart=/sbin/ip link set ${AP_INTERFACE} down
ExecStart=/sbin/ip addr flush dev ${AP_INTERFACE}

[Install]
WantedBy=hostapd.service
EOF
systemctl daemon-reload
systemctl enable ${AP_INTERFACE}-down.service

# === 4. Create IoT IDS Service ===
# Runs your main IDS Python script under systemd
echo "=== Creating IoT IDS service ==="
tee ${IOTIDS_SERVICE} > /dev/null <<EOF
[Unit]
Description=IoT IDS orchestrator
After=network-online.target suricata.service
Wants=network-online.target

[Service]
User=${IDS_USER}
Group=${IDS_GROUP}
WorkingDirectory=${IDS_DIR}
ExecStart=${PYTHON_BIN} ${MAIN_PY}
Environment=PYTHONUNBUFFERED=1  # ensures logs stream without buffering
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable iotids.service
systemctl restart iotids.service
# Show brief status to confirm
systemctl status --no-pager iotids.service | head -n5

# === 5. Grant Network Capabilities ===
# Allows the IDS service to open raw sockets and perform packet capture without root
echo "=== Granting network capabilities ==="
mkdir -p ${IOTIDS_DROPIN_DIR}
tee ${IOTIDS_DROPIN} > /dev/null <<EOF
[Service]
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN  # raw packet capture & admin tasks
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
EOF
systemctl daemon-reload
systemctl restart iotids.service

# === 6. Create Dashboard Service ===
# Deploys the Streamlit dashboard to visualize IDS alerts
echo "=== Creating dashboard service ==="
tee ${DASHBOARD_SERVICE} > /dev/null <<EOF
[Unit]
Description=IoT IDS Dashboard
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=${DASHBOARD_DIR}
ExecStart=${DASHBOARD_PYTHON} -m streamlit run dashboard.py \
  --server.port 1337 --server.address 0.0.0.0
Restart=on-failure
Environment=STREAMLIT_SERVER_HEADLESS=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable iot-ids-dashboard.service
systemctl start iot-ids-dashboard.service

# === Setup Complete ===
echo "=== All components installed and services started successfully ==="

