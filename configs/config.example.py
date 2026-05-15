# Copy this file to config.py and replace the placeholder values locally.
# Keep config.py private; commit only this example file.

ROUTER_CONFIG = {
    "device_type": "cisco_ios",
    "host": "router_ip_or_hostname",
    "username": "router_username",
    "password": "router_password",
    "secret": "router_enable_secret",
    "conn_timeout": 15,
}

# Leave as None for modern devices.
# Only set legacy SSH compatibility options if your older equipment requires them.
SSH_LEGACY = None
# Example for legacy environments:
# SSH_LEGACY = "-o KexAlgorithms=+diffie-hellman-group1-sha1 ..."

SWITCH_IP = "switch_ip_or_hostname"
PASS_VTY = "switch_vty_password"
PASS_EN = "switch_enable_secret"

ADMIN_USERS = {
    "admin_username": "admin_password",
}
