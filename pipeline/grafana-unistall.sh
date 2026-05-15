#!/bin/bash
# Uninstallation Script
# Author: dattrangia
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
info()    { echo -e "${GREEN}[INFO]${NC} $1"; }

echo -e "${RED}WARNING: This will REMOVE Grafana, Loki, Promtail, Prometheus, SNMP Exporter and ALL collected data.${NC}"
read -p "Are you sure you want to proceed? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    info "Uninstallation aborted."
    exit 1
fi

info "1. Stopping and disabling services..."
sudo systemctl stop grafana-server loki promtail prometheus snmp-exporter rsyslog || true
sudo systemctl disable grafana-server loki promtail prometheus snmp-exporter || true

info "2. Removing Systemd Service files..."
sudo rm -f /etc/systemd/system/loki.service
sudo rm -f /etc/systemd/system/promtail.service
sudo rm -f /etc/systemd/system/prometheus.service
sudo rm -f /etc/systemd/system/snmp-exporter.service
sudo systemctl daemon-reload

info "3. Removing Binaries..."
sudo rm -f /usr/local/bin/loki
sudo rm -f /usr/local/bin/promtail
sudo rm -f /usr/local/bin/prometheus
sudo rm -f /usr/local/bin/promtool
sudo rm -f /usr/local/bin/snmp_exporter

info "4. Removing Configuration & Data Directories..."
sudo rm -rf /etc/loki
sudo rm -rf /var/lib/loki
sudo rm -rf /var/lib/promtail
sudo rm -rf /etc/prometheus
sudo rm -rf /var/lib/prometheus
sudo rm -f /etc/snmp_exporter.yml
sudo rm -rf /var/log/ai-report
sudo rm -f /var/log/network.log

info "5. Removing Grafana (APT)..."
sudo apt-get remove --purge grafana -y || true
sudo rm -rf /var/lib/grafana
sudo rm -rf /etc/grafana

info "6. Cleaning Firewall Rules..."
if command -v ufw &>/dev/null; then
    sudo ufw delete allow 514/udp || true
    sudo ufw delete allow 3000/tcp || true
    sudo ufw delete allow 3100/tcp || true
    sudo ufw delete allow 9090/tcp || true
    sudo ufw delete allow 9116/tcp || true
fi

info "7. Restoring Rsyslog..."
sudo sed -i '/module(load="imudp")/d' /etc/rsyslog.conf
sudo sed -i '/input(type="imudp" port="514")/d' /etc/rsyslog.conf
sudo rm -f /etc/rsyslog.d/10-network.conf
sudo systemctl start rsyslog

echo -e "\n${GREEN}----------------------------------------------------${NC}"
echo -e "${GREEN}UNINSTALLATION COMPLETE!${NC}"
echo "MIMIR Legacy Dashboard Stack has been completely removed."
echo "Thank you for using the framework by dattrangia."
echo "--------------------------------------------------------"
