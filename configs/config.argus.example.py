# Copy this file to config.argus.py and replace the placeholder values locally.
LOKI_URL = "http://loki_ip:3100/loki/api/v1/query_range"
PROMETHEUS_URL = "http://prometheus_ip:9090/api/v1/query"

# Labels used by the Loki and Prometheus queries inside ARGUS.
# Match these to your own Promtail and SNMP exporter labels.
DEVICE_SOURCE = "switch_log_source_label"
PROMETHEUS_INSTANCE = "switch_prometheus_instance_label"

ROUTER_CONFIG = {
    "device_type": "cisco_ios",
    "host": "router_ip_or_hostname",
    "username": "router_username",
    "password": "router_password",
    "secret": "router_enable_secret",
    "conn_timeout": 15,
}

UBUNTU_CONFIG = {
    "device_type": "linux",
    "host": "ubuntu_ip_or_hostname",
    "port": 22,  # Use another port if your VPN/SSH tunnel forwards SSH elsewhere.
    "username": "ubuntu_username",
    "password": "ubuntu_password",
    "conn_timeout": 15,
}

AI_REPORT_LOG_PATH = "/var/log/ai-report/ai_summary.log"

# Leave as None for modern devices.
# Only set legacy SSH compatibility options if your older equipment requires them.
SSH_LEGACY = None
# Example for legacy environments:
# SSH_LEGACY = "-o KexAlgorithms=+diffie-hellman-group1-sha1 ..."

SWITCH_IP = "switch_ip_or_hostname"
PASS_VTY = "switch_vty_password"
PASS_EN = "switch_enable_secret"
