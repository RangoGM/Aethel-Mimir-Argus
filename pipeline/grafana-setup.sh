#!/bin/bash
# --- Full Automated Setup ---
# Stack: Grafana + Loki + Promtail + rsyslog + Prometheus v2.53.0 + SNMP Exporter
# Author: dattrangia
# ---
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
section() { echo -e "\n${GREEN}---> $1 <---${NC}"; }

# 1. SYSTEM UPDATE & GRAFANA
section "Installing Grafana"
sudo apt-get update && sudo apt-get install -y wget unzip gpg apt-transport-https software-properties-common curl jq
sudo mkdir -p /etc/apt/keyrings/

wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list

sudo apt-get update && sudo apt-get install grafana -y
sudo systemctl enable --now grafana-server
info "Grafana installed and started"

# 2. INSTALL LOKI & PROMTAIL (v2.9.3)
section "Installing Loki & Promtail (v2.9.3)"
cd /tmp
wget -q "https://github.com/grafana/loki/releases/download/v2.9.3/loki-linux-amd64.zip"
wget -q "https://github.com/grafana/loki/releases/download/v2.9.3/promtail-linux-amd64.zip"
unzip -q -o loki-linux-amd64.zip && sudo mv loki-linux-amd64 /usr/local/bin/loki
unzip -q -o promtail-linux-amd64.zip && sudo mv promtail-linux-amd64 /usr/local/bin/promtail
sudo chmod a+x /usr/local/bin/loki /usr/local/bin/promtail
rm -f *.zip
info "Loki & Promtail binaries installed"

# 3. INSTALL PROMETHEUS (v2.53.0) & SNMP EXPORTER
section "Installing Prometheus & SNMP Exporter"
cd /tmp
wget -q "https://github.com/prometheus/prometheus/releases/download/v2.53.0/prometheus-2.53.0.linux-amd64.tar.gz"
tar -xzf prometheus-2.53.0.linux-amd64.tar.gz
sudo cp prometheus-2.53.0.linux-amd64/{prometheus,promtool} /usr/local/bin/
sudo chmod a+x /usr/local/bin/prometheus /usr/local/bin/promtool

# SNMP Exporter (v0.26.0)
wget -q "https://github.com/prometheus/snmp_exporter/releases/download/v0.26.0/snmp_exporter-0.26.0.linux-amd64.tar.gz"
tar -xzf snmp_exporter-0.26.0.linux-amd64.tar.gz
sudo cp snmp_exporter-0.26.0.linux-amd64/snmp_exporter /usr/local/bin/
sudo chmod a+x /usr/local/bin/snmp_exporter

info "Prometheus (v2.53.0) & SNMP Exporter binaries installed"

# 4. CONFIGURING LOKI & PROMTAIL
section "Configuring Loki & Promtail"
sudo mkdir -p /etc/loki /var/lib/loki /var/lib/promtail /var/log/ai-report
sudo chown -R nobody:nogroup /var/lib/loki /var/lib/promtail
sudo touch /var/log/ai-report/ai_summary.log

# Loki Config
sudo tee /etc/loki/loki-config.yaml > /dev/null << 'EOF'
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096

common:
  instance_addr: 127.0.0.1
  path_prefix: /var/lib/loki
  storage:
    filesystem:
      chunks_directory: /var/lib/loki/chunks
      rules_directory: /var/lib/loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

query_range:
  results_cache:
    cache:
      embedded_cache:
        enabled: true
        max_size_mb: 100

schema_config:
  configs:
    - from: 2020-10-24
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

ruler:
  alertmanager_url: http://localhost:9093

analytics:
  reporting_enabled: false
EOF

# Promtail Config 
sudo tee /etc/loki/promtail-config.yaml > /dev/null << 'PROMTAILEOF'
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /var/lib/promtail/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:
  - job_name: cisco
    static_configs:
      - targets:
          - localhost
        labels:
          job: cisco
          # Optional Grafana Geomap labels. Uncomment and set string values
          # if you want this log stream to appear on a map panel.
          # location: "Lab Edge"
          # latitude: "<YOUR_LATITUDE>"
          # longitude: "<YOUR_LONGITUDE>"
          # src_lat: "<YOUR_SOURCE_LATITUDE>"
          # src_lon: "<YOUR_SOURCE_LONGITUDE>"
          # dst_lat: "<YOUR_DESTINATION_LATITUDE>"
          # dst_lon: "<YOUR_DESTINATION_LONGITUDE>"
          __path__: /var/log/network.log
    pipeline_stages:
      - regex:
          expression: '^\S+\s+(?P<device_source>[\d\.]+)\s+'
      - labels:
          device_source:
      - drop:
          expression: '\w+\[\d+\]:'
      - regex:
          expression: '%(?P<facility>[A-Z0-9_]+)-(?P<severity>[0-7])-(?P<mnemonic>[A-Z0-9_]+)'
      - template:
          source: severity_name
          template: '{{- if eq .severity "0" -}}EMERGENCY{{- else if eq .severity "1" -}}ALERT{{- else if eq .severity "2" -}}CRITICAL{{- else if eq .severity "3" -}}ERROR{{- else if eq .severity "4" -}}WARNING{{- else if eq .severity "5" -}}NOTICE{{- else if eq .severity "6" -}}INFORMATIONAL{{- else if eq .severity "7" -}}DEBUG{{- else -}}DEBUG{{- end -}}'
      - regex:
           expression: '(?:%[A-Z0-9_]+-[0-7]-[A-Z0-9_]+:|\.\d{3}:).*?(?P<ip_address>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)'
      - regex:
           expression: '(?P<mac_address>\b(?:[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\b)'
      - template:
          source: mac_address
          template: '{{ if or (eq .Value "0000.0000.0000") (eq .Value "ffff.ffff.ffff") (eq .Value "FFFF.FFFF.FFFF") }}{{ "" }}{{ else }}{{ .Value }}{{ end }}'
      - template:
          source: level
          template: '{{- if eq .severity "0" -}}emergency{{- else if eq .severity "1" -}}alert{{- else if eq .severity "2" -}}critical{{- else if eq .severity "3" -}}error{{- else if eq .severity "4" -}}warning{{- else if eq .severity "5" -}}notice{{- else if eq .severity "6" -}}info{{- else if eq .severity "7" -}}debug{{- else -}}debug{{- end -}}'
      - template:
          source: output
          template: '{{ .Entry }}'
      - output:
          source: output
      - labels:
          facility:
          severity:
          mnemonic:
          severity_name:
          level:
          ip_address:  
          mac_address: 
          device_source: 
          framework_author: "dattrangia"

  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: varlogs
          # Optional Grafana Geomap labels.
          # location: "Ubuntu Server"
          # latitude: "<YOUR_LATITUDE>"
          # longitude: "<YOUR_LONGITUDE>"
          __path__: /var/log/*.log

  - job_name: syslog
    static_configs:
      - targets:
          - localhost
        labels:
          job: syslog
          # Optional Grafana Geomap labels.
          # location: "Ubuntu Syslog"
          # latitude: "<YOUR_LATITUDE>"
          # longitude: "<YOUR_LONGITUDE>"
          __path__: /var/log/syslog

  - job_name: auth
    static_configs:
      - targets:
          - localhost
        labels:
          job: auth
          # Optional Grafana Geomap labels.
          # location: "Ubuntu Auth"
          # latitude: "<YOUR_LATITUDE>"
          # longitude: "<YOUR_LONGITUDE>"
          __path__: /var/log/auth.log

  - job_name: nginx
    static_configs:
      - targets:
          - localhost
        labels:
          job: nginx
          # Optional Grafana Geomap labels.
          # location: "Nginx"
          # latitude: "<YOUR_LATITUDE>"
          # longitude: "<YOUR_LONGITUDE>"
          __path__: /var/log/nginx/*.log
    pipeline_stages:
      - regex:
          expression: '^(?P<remote_addr>[\w\.]+) - (?P<remote_user>[^ ]*) \[(?P<time_local>[^\]]*)\] "(?P<method>\w+) (?P<request>[^ ]*) (?P<protocol>[^"]*)" (?P<status>\d+) (?P<body_bytes_sent>\d+) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
      - labels:
          method:
          status:

  - job_name: ai-report
    static_configs:
      - targets:
          - localhost
        labels:
          job: ai-report
          # Optional Grafana Geomap labels.
          # location: "AI Report Host"
          # latitude: "<YOUR_LATITUDE>"
          # longitude: "<YOUR_LONGITUDE>"
          __path__: /var/log/ai-report/ai_summary.log
    pipeline_stages:
      - regex:
          expression: 'level=(?P<level>\w+)'
      - labels:
          level:
PROMTAILEOF

# 5. CONFIGURING PROMETHEUS & SNMP EXPORTER
section "Configuring Prometheus & SNMP Exporter"
sudo mkdir -p /etc/prometheus /var/lib/prometheus
sudo chown -R nobody:nogroup /var/lib/prometheus

# Prometheus Config
sudo tee /etc/prometheus/prometheus.yml > /dev/null << 'EOF'
global:
  scrape_interval: 30s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'snmp'
    scrape_interval: 60s
    static_configs:
      - targets:
          - <IP_SWITCH_2960>
          - <IP_ROUTER_2811>
    metrics_path: /snmp
    params:
      auth: ['nckh_v3']
      module: ['if_mib']
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9116

  - job_name: 'snmp-system'
    scrape_interval: 60s
    static_configs:
      - targets:
          - <IP_SWITCH_2960>
          - <IP_ROUTER_2811>
    metrics_path: /snmp
    params:
      auth: ['nckh_v3']
      module: ['hrSystem']
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9116

  - job_name: 'snmp-cisco'
    scrape_interval: 5s
    static_configs:
      - targets:
          - <IP_SWITCH_2960>
          - <IP_ROUTER_2811>
    metrics_path: /snmp
    params:
      auth: ['nckh_v3']
      module: ['cisco_all']
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9116

  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
EOF

# SNMP Exporter Config
info "Injecting custom V3 auth and OIDs into snmp.yml..."
sudo awk '
/public_v2:/ { print; flag=1; next }
flag && /version: 2/ {
    print
    print "  nckh_v3:\n    security_level: authPriv\n    username: CHANGE_ME_USER\n    password: CHANGE_ME_PASS\n    auth_protocol: SHA\n    priv_password: CHANGE_ME_PRIV\n    priv_protocol: AES\n    version: 3"
    flag=0
    next
}
{ print }
' /tmp/snmp_exporter-0.26.0.linux-amd64/snmp.yml | sudo tee /tmp/snmp_exporter_custom.yml > /dev/null

sudo bash -c 'cat >> /tmp/snmp_exporter_custom.yml' << 'EOF'
  cisco_all:
    walk:
    - 1.3.6.1.4.1.9.9.109.1.1.1.1.6
    - 1.3.6.1.4.1.9.9.109.1.1.1.1.7
    - 1.3.6.1.4.1.9.9.109.1.1.1.1.8
    - 1.3.6.1.4.1.9.9.48.1.1.1.5
    - 1.3.6.1.4.1.9.9.48.1.1.1.6
    - 1.3.6.1.4.1.9.9.48.1.1.1.7
    - 1.3.6.1.4.1.9.9.13.1.5.1.3
    ###### Add more Proccess ID for SNMP_Exporter ######
    - 1.3.6.1.4.1.9.9.109.1.2.1.1.2
    - 1.3.6.1.4.1.9.9.109.1.2.3.1.5
    - 1.3.6.1.4.1.9.9.109.1.2.3.1.6
    - 1.3.6.1.4.1.9.9.109.1.2.3.1.7
    metrics:
    - name: cpmCPUTotal5secRev
      oid: 1.3.6.1.4.1.9.9.109.1.1.1.1.6
      type: gauge
      help: Cisco CPU 5sec average
      indexes:
      - labelname: cpmCPUTotalIndex
        type: gauge
    - name: cpmCPUTotal1minRev
      oid: 1.3.6.1.4.1.9.9.109.1.1.1.1.7
      type: gauge
      help: Cisco CPU 1min average
      indexes:
      - labelname: cpmCPUTotalIndex
        type: gauge
    - name: cpmCPUTotal5minRev
      oid: 1.3.6.1.4.1.9.9.109.1.1.1.1.8
      type: gauge
      help: Cisco CPU 5min average
      indexes:
      - labelname: cpmCPUTotalIndex
        type: gauge
    - name: ciscoMemoryPoolUsed
      oid: 1.3.6.1.4.1.9.9.48.1.1.1.5
      type: gauge
      help: Memory pool used bytes
      indexes:
      - labelname: ciscoMemoryPoolIndex
        type: gauge
    - name: ciscoMemoryPoolFree
      oid: 1.3.6.1.4.1.9.9.48.1.1.1.6
      type: gauge
      help: Memory pool free bytes
      indexes:
      - labelname: ciscoMemoryPoolIndex
        type: gauge
    - name: ciscoMemoryPoolLargestFree
      oid: 1.3.6.1.4.1.9.9.48.1.1.1.7
      type: gauge
      help: Memory pool largest free block
      indexes:
      - labelname: ciscoMemoryPoolIndex
        type: gauge
    - name: ciscoEnvMonSupplyState
      oid: 1.3.6.1.4.1.9.9.13.1.5.1.3
      type: gauge
      help: Power supply status (1=normal)
      indexes:
      - labelname: ciscoEnvMonSupplyIndex
        type: gauge
    ##### 302 Processes ######
    - name: cpmProcessName
      oid: 1.3.6.1.4.1.9.9.109.1.2.1.1.2
      type: DisplayString
      help: The name of the Cisco process
      indexes:
      - labelname: cpmCPUTotalIndex
        type: gauge
      - labelname: cpmProcessPID
        type: gauge
    - name: cpmProcExtUtil5SecRev
      oid: 1.3.6.1.4.1.9.9.109.1.2.3.1.5
      type: gauge
      help: Cisco Process CPU 5sec average utilization
      indexes:
      - labelname: cpmCPUTotalIndex
        type: gauge
      - labelname: cpmProcessPID
        type: gauge
      lookups:
      - labels:
        - cpmCPUTotalIndex
        - cpmProcessPID
        labelname: cpmProcessName
        oid: 1.3.6.1.4.1.9.9.109.1.2.1.1.2
        type: DisplayString
    - name: cpmProcExtUtil1MinRev
      oid: 1.3.6.1.4.1.9.9.109.1.2.3.1.6
      type: gauge
      help: Cisco Process CPU 1min average utilization
      indexes:
      - labelname: cpmCPUTotalIndex
        type: gauge
      - labelname: cpmProcessPID
        type: gauge
      lookups:
      - labels:
        - cpmCPUTotalIndex
        - cpmProcessPID
        labelname: cpmProcessName
        oid: 1.3.6.1.4.1.9.9.109.1.2.1.1.2
        type: DisplayString
    - name: cpmProcExtUtil5MinRev
      oid: 1.3.6.1.4.1.9.9.109.1.2.3.1.7
      type: gauge
      help: Cisco Process CPU 5min average utilization
      indexes:
      - labelname: cpmCPUTotalIndex
        type: gauge
      - labelname: cpmProcessPID
        type: gauge
      lookups:
      - labels:
        - cpmCPUTotalIndex
        - cpmProcessPID
        labelname: cpmProcessName
        oid: 1.3.6.1.4.1.9.9.109.1.2.1.1.2
        type: DisplayString
EOF
sudo mv /tmp/snmp_exporter_custom.yml /etc/snmp_exporter.yml

# 6. CONFIGURING RSYSLOG
section "Configuring Rsyslog"
sudo sed -i '/^#module(load="imudp")/s/^#//' /etc/rsyslog.conf
sudo sed -i '/^#input(type="imudp"/s/^#//' /etc/rsyslog.conf

if ! grep -q 'imudp' /etc/rsyslog.conf; then
    sudo bash -c 'cat >> /etc/rsyslog.conf << EOF
module(load="imudp")
input(type="imudp" port="514")
EOF'
fi

sudo tee /etc/rsyslog.d/10-network.conf > /dev/null << 'EOF'
if $fromhost-ip != '127.0.0.1' then /var/log/network.log
EOF

sudo touch /var/log/network.log
sudo chown syslog:adm /var/log/network.log
sudo chmod 644 /var/log/network.log
sudo systemctl restart rsyslog

# 7. SYSTEMD SERVICES
section "Creating Systemd services"

sudo tee /etc/systemd/system/loki.service > /dev/null << 'EOF'
[Unit]
Description=Loki Log Aggregation System
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/loki -config.file=/etc/loki/loki-config.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/promtail.service > /dev/null << 'EOF'
[Unit]
Description=Promtail Log Collector
After=network.target loki.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/promtail -config.file=/etc/loki/promtail-config.yaml 
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/prometheus.service > /dev/null << 'EOF'
[Unit]
Description=Prometheus
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/prometheus --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/var/lib/prometheus --storage.tsdb.retention.time=30d --web.listen-address=:9090
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/snmp-exporter.service > /dev/null << 'EOF'
[Unit]
Description=SNMP Exporter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snmp_exporter --config.file=/etc/snmp_exporter.yml 
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now loki promtail prometheus snmp-exporter
info "All Systemd services created and started"

# 8. FIREWALL (UFW)
section "Configuring Firewall"
if command -v ufw &>/dev/null && sudo ufw status | grep -q "active"; then
    sudo ufw allow 514/udp  comment 'Syslog'
    sudo ufw allow 3000/tcp comment 'Grafana'
    sudo ufw allow 3100/tcp comment 'Loki'
    sudo ufw allow 9090/tcp comment 'Prometheus'
    sudo ufw allow 9116/tcp comment 'SNMP Exporter'
    info "Firewall ports opened"
fi

# 9. SUMMARY & NEXT STEPS
SERVER_IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}MIMIR Legacy Dashboard Stack is RUNNING!${NC}"
echo "---------------------------------------------------"
echo "Grafana:        http://${SERVER_IP}:3000 (admin/admin)"
echo "Prometheus:     http://${SERVER_IP}:9090"
echo "SNMP Exporter:  http://${SERVER_IP}:9116"
echo "Loki:           http://${SERVER_IP}:3100"
echo "---------------------------------------------------"
echo -e "${YELLOW}IMPORTANT: ACTION REQUIRED BEFORE USE:${NC}"
echo "1. Edit /etc/prometheus/prometheus.yml to replace <IP_SWITCH_2960> and <IP_ROUTER_2811>"
echo "2. Edit /etc/snmp_exporter.yml to replace CHANGE_ME_USER and CHANGE_ME_PASS in nckh_v3"
echo "3. Restart services after edit: sudo systemctl restart prometheus snmp-exporter"
echo ""
