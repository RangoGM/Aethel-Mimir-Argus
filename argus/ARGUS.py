import requests
import time
import re
import os
import sys
import threading
import json
import datetime
from netmiko import ConnectHandler, redispatch

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WHITELIST_FILE = os.path.join(SCRIPT_DIR, "scan_whitelist.json")
RA_DEDUPE_WINDOW_S = 10
RA_RESET_QUIET_SECONDS = 30
DAI_RATE_THRESHOLD_PER_MIN = 5
NOTCONNECT_COUNTDOWN_S = 60

def parse_switch_time(raw_log, current_year=None):
    """Parse Cisco timestamp 'Apr 28 20:24:04.019' → epoch seconds"""
    m = re.search(r'(\w{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\.(\d{3})', raw_log)
    if not m:
        return None
    
    months = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
              'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
    
    try:
        if current_year is None:
            current_year = datetime.datetime.now().year

        dt = datetime.datetime(
            year=current_year,
            month=months[m.group(1)],
            day=int(m.group(2)),
            hour=int(m.group(3)),
            minute=int(m.group(4)),
            second=int(m.group(5)),
            microsecond=int(m.group(6)) * 1000
        )
        if dt - datetime.datetime.now() > datetime.timedelta(days=30):
            try:
                dt = dt.replace(year=dt.year - 1)
            except ValueError:
                dt = dt.replace(year=dt.year - 1, day=28)
        return dt.timestamp()
    except Exception:
        return None


def parse_loki_time(raw_log):
    """Parse Loki timestamp '2026-04-28T20:24:05.028778+07:00' → epoch seconds"""
    m = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)', raw_log)
    if not m:
        return None
    
    try:
        ts_str = m.group(1)[:26]
        dt = datetime.datetime.fromisoformat(ts_str)
        return dt.timestamp()
    except Exception:
        return None

def save_security_dataset(instruction, output):
    with open("security_dataset.json", "a", encoding="utf-8") as f:
        f.write(json.dumps({"instruction": instruction, "output": output}) + ",\n")

# --- LOADING SPINNIER ---
class LoadingSpinner:
    def __init__(self, message="Loading"):
        self.message = message
        self.running = False
        self.thread = None
        self.color = "\033[1;32m" # Green for Eyesight
        self.reset = "\033[0m"
    
    def _spin(self):
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        i = 0
        while self.running:
            sys.stdout.write(f"\r {self.color}{frames[i % len(frames)]}{self.reset} {self.message}...")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        sys.stdout.write(f"\r{' ' * (len(self.message) + 15)}\r")
        sys.stdout.flush()
 
    def __enter__(self):
        self.running = True
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()
        return self
 
    def __exit__(self, *args):
        self.running = False
        if self.thread:
            self.thread.join()


# --- [1] CONFIG ---
# Public repo note: deployment values are intentionally omitted here.
# Copy configs/config.argus.example.py locally, replace the placeholders with
# private values, and keep the real config out of version control.
# --- [2] THE BRAIN (OLLAMA API) ---
def ask_ai(prompt):
    url = "http://localhost:11434/api/generate"
    try:
        r = requests.post(url, json={"model": "ARGUS", "prompt": prompt, "stream": False}, timeout=15)
        return r.json()['response'].strip()
    except Exception as e:
        return f"ERROR: AI_CONNECTION_FAILED ({e})"
 
def ask_report_ai(prompt):
    url = "http://localhost:11434/api/generate"
    try:
        r = requests.post(url, json={"model": "llama-report", "prompt": prompt, "stream": False}, timeout=30)
        return r.json()['response'].strip()
    except Exception as e:
        return f"ERROR: AI_CONNECTION_FAILED ({e})"
 
# --- [3] THE EXECUTOR (NETMIKO) ---
def netmiko_execute(command, is_config=False):
    clean_command = command.replace("\\n", "\n")
    raw_cmd_list = [c.strip() for c in clean_command.split("\n") if c.strip()]

    cmd_list = []
    if is_config:
        for c in raw_cmd_list:
            if c.lower().startswith("show ") or c.lower().startswith("ping "):
                cmd_list.append(f"do {c}")
            else:
                cmd_list.append(c)
    else:
        cmd_list = raw_cmd_list

    try:
        conn_params = ROUTER_CONFIG.copy()
        if SSH_LEGACY:
            try:
                conn_params['ssh_extra_args'] = SSH_LEGACY
                jump = ConnectHandler(**conn_params)
            except Exception:
                if 'ssh_extra_args' in conn_params:
                    del conn_params['ssh_extra_args']
                jump = ConnectHandler(**conn_params)
        else:
            jump = ConnectHandler(**conn_params)
        jump.write_channel(f"ssh {SWITCH_IP}\n")
        time.sleep(2)
        output_login = jump.read_channel()
        if "assword" in output_login or "Password" in output_login:
            jump.write_channel(f"{PASS_VTY}\n")
            time.sleep(2)

        redispatch(jump, device_type='cisco_ios')
 
        jump.secret = PASS_EN
        jump.enable()

        output = ""
        if is_config:
            output = jump.send_config_set(cmd_list)
        else:
            for c in cmd_list:
                output += f"--- {c} ---\n"
                output += jump.send_command(c, read_timeout=15) + "\n\n"
 
        jump.disconnect()
        return output
 
    except Exception as e:
        print(f"[!] Auditor Netmiko Error: {e}")
        return f"EXECUTION_ERROR: {str(e)}"
    
def verify_trunk_cdp_identity(port, expected_name=""):
    try:
        with LoadingSpinner(f"Verifying CDP identity on {port}"):
            cdp_out = netmiko_execute("show cdp neighbors", is_config=False)
        
        port_suffix = re.search(r'(\d+/\d+)', port)
        port_short = port_suffix.group(1) if port_suffix else port
        
        for line in cdp_out.splitlines():
            if port_short in line:
                neighbor_name = line.split()[0].strip()
                if expected_name:
                    if neighbor_name.lower() == expected_name.lower():
                        return True, neighbor_name
                    else:
                        return False, neighbor_name
                else:
                    return True, neighbor_name
        
        return False, None
    except Exception:
        return False, None
 
# --- [3.5] PORT SCANNER + DAI TRACKER + COUNTER MEMORY + ROLLBACK ---
 
port_down_since = {}
SCAN_INTERVAL = 60
last_scan_time = 0

MONITORED_PORTS = []

def extract_ports_from_input(user_input):
    ports = []
    matches = re.findall(r'\b(Fa|Gi|Te|Et)\s*(\d+(?:/\d+)?)/(\d+)(?:\s*(?:-|to)\s*(?:(?:Fa|Gi|Te|Et)\s*\d+(?:/\d+)?/)?(\d+))?', user_input, re.IGNORECASE)
    for match in matches:
        prefix, slot, start_port = match[0].capitalize(), match[1], int(match[2])
        if match[3]:
            for p in range(start_port, int(match[3]) + 1):
                ports.append(f"{prefix}{slot}/{p}")
        else:
            ports.append(f"{prefix}{slot}/{start_port}")
    return list(dict.fromkeys(ports))

def is_trunk_port(port_name):
    try:
        out = netmiko_execute(f"show interfaces {port_name} switchport", is_config=False)
        return "Administrative Mode: trunk" in out
    except Exception: return False
 
def scan_ports():
    with LoadingSpinner("\033[1;32m[ARGUS]\033[0m Scanning interfaces status"):
        status_output = netmiko_execute("show interfaces status", is_config=False)
    print("\033[1;32m[ARGUS]\033[0m Scan complete. Analyzing threats...\n")
    return status_output
 
def parse_port_status(output):
    result = {}
    for line in output.splitlines():
        match = re.match(r'^(Fa|Gi|Te|Et)(\d+/\d+(/\d+)?)\s+', line.strip())
        if match:
            port = match.group(0).strip()
            if "trunk" in line.lower():
                result[port] = "trunk"
            elif "disabled" in line:
                result[port] = "disabled"
            elif "notconnect" in line:
                result[port] = "notconnect"
            elif "connected" in line:
                result[port] = "connected"
    return result
 
def build_range_cmd(ports):
    """Total ports in prefix"""
    from collections import defaultdict
    groups = defaultdict(list)
 
    for p in ports:
        prefix, num = p.rsplit("/", 1)
        groups[prefix].append(int(num))
 
    ranges = []
    for prefix in sorted(groups):
        nums = sorted(groups[prefix])
        start = nums[0]
        end = nums[0]
        for n in nums[1:]:
            if n == end + 1:
                end = n
            else:
                if start == end:
                    ranges.append(f"{prefix}/{start}")
                else:
                    ranges.append(f"{prefix}/{start}-{end}")
                start = n
                end = n
        if start == end:
            ranges.append(f"{prefix}/{start}")
        else:
            ranges.append(f"{prefix}/{start}-{end}")
 
    return "interface range " + ",".join(ranges)

def sanitize_log(raw_log):
    clean = re.sub(r'STEP:.*', '', raw_log)
    clean = re.sub(r'EXECUTE:.*', '', clean)
    clean = re.sub(r'ACTION:.*', '', clean)
    clean = re.sub(r'CMD:.*', '', clean)
    return clean.strip()
 
# --- DAI TRACKER ---
dai_first_seen = {}
dai_ignored_ports = set()
BOOT_GRACE = 180
 
def check_dai_attack(port, real_binding):
    now = time.time()
 
    if port in dai_ignored_ports:
        return 'ignored'
 
    # Normalize port name for binding match
    port_num = re.search(r'(\d+/\d+(/\d+)?)', port)
    port_suffix = port_num.group(1) if port_num else port
 
    if port_suffix in real_binding:
        return 'verify'
 
    if port not in dai_first_seen:
        dai_first_seen[port] = now
        return 'boot'
 
    if now - dai_first_seen[port] < BOOT_GRACE:
        return 'boot'
 
    return 'stuck'
 
# --- COUNTER MEMORY ---
prev_counters = {}
 
def save_counter(port, category, value):
    key = f"{port}_{category}"
    prev_counters[key] = value
 
def get_prev_counter(port, category):
    key = f"{port}_{category}"
    return prev_counters.get(key, None)
 
# --- ROLLBACK ---
shutdown_log = []  # -> NEVER cleared, full history
rollback_whitelist = set()  # -> Port admin rollback, scan will not touch

def _atomic_json_write(path, data):
    """Write JSON atomically: per-writer tmp + fsync + os.replace.
    The tmp filename includes PID + thread id so concurrent writers
    (MIMIR + ARGUS, or multiple threads) never collide on the staging file.
    Final-file semantics are still last-writer-wins on os.replace; this
    helper guarantees no torn/half-written JSON, not lost-update protection."""
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        # Best-effort cleanup if write/replace failed partway
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass
        raise

def load_maintenance_whitelist():
    """Load whitelist entries from JSON shared with admin script"""
    if not os.path.exists(WHITELIST_FILE):
        return []
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []
 
def save_maintenance_whitelist(entries):
    """Save updated whitelist (atomic write)"""
    _atomic_json_write(WHITELIST_FILE, entries)
 
def cleanup_expired_whitelist():
    """Remove expired entries, return active ones"""
    entries = load_maintenance_whitelist()
    now = time.time()
    active = []
    expired_ports = []
    
    for entry in entries:
        if entry["expire"] == 0:
            active.append(entry)
        elif entry["expire"] > now:
            remaining = int((entry["expire"] - now) / 60)
            active.append(entry)
        else:
            expired_ports.append(entry["port"])
            print(f"\033[1;31m[WHITELIST] {entry['port']} maintenance EXPIRED. Removing protection.\033[0m")
    
    if expired_ports:
        save_maintenance_whitelist(active)
    
    return active, expired_ports
 
def check_dot1x_auth_in_logs(port):
    """Query Loki for 802.1X auth success on specific port"""
    port_suffix = re.search(r'(\d+/\d+)', port)
    if not port_suffix:
        return False
    p = port_suffix.group(1)
    
    try:
        start = str(int((time.time() - 300) * 1e9))
        res = requests.get(LOKI_URL, params={
            'query': '{job="cisco"} |~ "AUTHMGR-5-SUCCESS|MAB-5-SUCCESS"',
            'limit': 50,
            'start': start
        }, timeout=5).json()
        
        for stream in res['data']['result']:
            for _, line in stream['values']:
                if p in line:
                    return True
    except Exception:
        pass
    return False
 
def record_shutdown(port, reason):
    record = f"{time.strftime('%Y-%m-%d %H:%M:%S')} | SHUTDOWN {port} | {reason}"
    shutdown_log.append(record)
    print(f"\033[1;36m[HISTORY] {record}\033[0m")
 
# --- PERSISTENT TIMESTAMP ---
TS_FILE = "ai_defense_last_ts.txt"
seen_timestamps = set()
 
def load_seen_ts():
    try:
        with open(TS_FILE, 'r') as f:
            return set(f.read().strip().split("\n"))
    except Exception:
        return set()
 
def save_seen_ts():
    try:
        recent = sorted(seen_timestamps)[-200:]
        with open(TS_FILE, 'w') as f:
            f.write("\n".join(recent))
    except Exception:
        pass
 
seen_timestamps = load_seen_ts()
 
# --- [5] AI REPORT ---
event_buffer = []
REPORT_INTERVAL = 300
last_report_time = time.time()
 
def get_metrics():
    metrics = {}
    queries = {
        'cpu_5sec': f'avg(cpmCPUTotal5secRev{{instance="{PROMETHEUS_INSTANCE}"}})',
        'mem_processor': f'ciscoMemoryPoolUsed{{instance="{PROMETHEUS_INSTANCE}", ciscoMemoryPoolIndex="1"}} / (ciscoMemoryPoolUsed{{instance="{PROMETHEUS_INSTANCE}", ciscoMemoryPoolIndex="1"}} + ciscoMemoryPoolFree{{instance="{PROMETHEUS_INSTANCE}", ciscoMemoryPoolIndex="1"}}) * 100',
        'mem_io': f'ciscoMemoryPoolUsed{{instance="{PROMETHEUS_INSTANCE}", ciscoMemoryPoolIndex="2"}} / (ciscoMemoryPoolUsed{{instance="{PROMETHEUS_INSTANCE}", ciscoMemoryPoolIndex="2"}} + ciscoMemoryPoolFree{{instance="{PROMETHEUS_INSTANCE}", ciscoMemoryPoolIndex="2"}}) * 100',
        'top_in_bps': f'topk(5, rate(ifHCInOctets{{job="snmp_switch", instance="{PROMETHEUS_INSTANCE}"}}[5m]) * 8)',
        'top_out_bps': f'topk(5, rate(ifHCOutOctets{{job="snmp_switch", instance="{PROMETHEUS_INSTANCE}"}}[5m]) * 8)',
        'unicast_pps': f'sum(rate(ifInUcastPkts{{job="snmp_switch", instance="{PROMETHEUS_INSTANCE}"}}[5m]))',
        'multicast_pps': f'sum(rate(ifInMulticastPkts{{job="snmp_switch", instance="{PROMETHEUS_INSTANCE}"}}[5m]))',
        'broadcast_pps': f'sum(rate(ifInBroadcastPkts{{job="snmp_switch", instance="{PROMETHEUS_INSTANCE}"}}[5m]))',
        'uptime_sec': f'sysUpTime{{job="snmp_switch", instance="{PROMETHEUS_INSTANCE}"}} / 100',
    }
    for name, query in queries.items():
        try:
            r = requests.get(PROMETHEUS_URL, params={'query': query}, timeout=5).json()
            if r['data']['result']:
                val = r['data']['result'][0]['value'][1]
                metrics[name] = round(float(val), 2) if val != "N/A" else "N/A"
        except Exception as e:
            metrics[name] = "N/A"
            print(f"[!] Prometheus query failed ({name}): {e}")
    return metrics
 
def get_log_severity_counts():
    counts = {}
    try:
        r = requests.get(LOKI_URL.replace("query_range", "query"), params={
            'query': f'sum by(severity_name) (count_over_time({{job="cisco", device_source="{DEVICE_SOURCE}"}}[5m]))',
        }, timeout=5).json()
        for result in r['data']['result']:
            sev = result['metric'].get('severity_name', 'unknown')
            val = result['value'][1]
            counts[sev] = val
    except Exception as e:
        print(f"[!] Loki severity query failed: {e}")
    return counts
 
def get_recent_security_logs():
    logs = []
    try:
        start = str(int((time.time() - 300) * 1e9))
        res = requests.get(LOKI_URL, params={
            'query': LOKI_QUERY,
            'limit': 20,
            'start': start
        }, timeout=5).json()
        for stream in res['data']['result']:
            for ts, line in stream['values']:
                logs.append(line[:120])
    except Exception as e:
        print(f"[!] Loki security logs query failed: {e}")
    return logs
 
def ai_full_report():
    metrics = get_metrics()
    logs = get_recent_security_logs()
    severity = get_log_severity_counts()

    uptime_raw = metrics.get('uptime_sec', 0)
    if uptime_raw != "N/A":
        total_sec = float(uptime_raw)
        days = int(total_sec // 86400)
        hours = int((total_sec % 86400) // 3600)
        minutes = int((total_sec % 3600) // 60)
        uptime_str = f"{days}d {hours}h {minutes}m"
    else:
        uptime_str = "N/A"
 
    prompt = f"""You are ARGUS, a security analyst writing executive briefings for a Cisco 2960 switch.

=== INPUT DATA ===

PERFORMANCE:
- CPU: {metrics.get('cpu_5sec', 'N/A')}%
- Memory Processor: {metrics.get('mem_processor', 'N/A')}%
- Memory I/O: {metrics.get('mem_io', 'N/A')}%
- Top In/Out: {metrics.get('top_in_bps', 'N/A')}/{metrics.get('top_out_bps', 'N/A')} bps
- Traffic: {metrics.get('unicast_pps', 'N/A')}/{metrics.get('multicast_pps', 'N/A')}/{metrics.get('broadcast_pps', 'N/A')} pps (unicast/multicast/broadcast)
- Uptime: {uptime_str}

LOG SEVERITY (5min):
{severity if severity else 'None'}

RAW LOGS (5min):
{chr(10).join(logs) if logs else 'None'}

SYSTEM ACTIONS:
{chr(10).join([e for e in event_buffer if "stale" not in e.lower() and "cooldown" not in e.lower()]) if event_buffer else 'None'}

=== EVENT INTERPRETATION ===
- "SKIP - boot grace" = device booting, NORMAL
- "SKIP - Fake/stale log" = counter unchanged, NORMAL
- "RA baseline=N HW blocking" = first detection, NORMAL
- "RA WARNING delta=N HW drops=N" = sustained Rogue RA, WARNING
- "RA Reset baseline" = attack ended, INFO
- "AI SHUTDOWN [port]" = confirmed threat, WARNING
- "BLOCKED: already disabled" = redundant prevented, NORMAL
- "SCAN SHUTDOWN: [list]" = housekeeping, NORMAL
- "STUCK - no lease" = device issue, WARNING

=== STRICT OUTPUT FORMAT ===

Write EXACTLY 6-8 lines. NO markdown headers, NO bullet points except where shown.
Use this template:

[1 line: Overall posture summary - 1 sentence max]
[1 line: Performance highlight - CPU N%, Memory N%, traffic pattern]
[1 line: Security events - what was detected/filtered, exact numbers]
[1 line: Hardware mitigation status - if applicable]
[1 line: Correlation insight - tie performance to security if relevant]
[1 blank line]
Uptime: {uptime_str}
FACILITY: NORMAL/WARNING/DANGER

=== ABSOLUTE RULES ===
- MAX 8 lines total. Do not exceed.
- NO section headers like "Performance Metrics:", "Security Events:" — these waste lines.
- NO repetition of input data — interpret it, don't echo it.
- DO NOT invent events not in SYSTEM ACTIONS.
- DO NOT mention shutdown unless explicitly in SYSTEM ACTIONS.
- Use exact numeric formats: "Nd Nh Nm" uptime, "N%" CPU/memory, "N pps", "N bps".
- DO NOT add commas in numbers (9527 not 9,527).
- DO NOT use "approximately" — use exact values from input.
- Quote exact baseline/delta/drops numbers from SYSTEM ACTIONS.

=== CORRELATION GUIDE ===
- All SKIP/boot/baseline → FACILITY: NORMAL
- RA WARNING delta>0 → FACILITY: WARNING
- CPU>60% + broadcast high → broadcast storm, FACILITY: WARNING
- CPU>70% + SHUTDOWN actions → confirmed attack, FACILITY: DANGER
- Memory>80% + DHCP events → DHCP starvation, FACILITY: WARNING
- Normal metrics + only baseline/skip → system stable, FACILITY: NORMAL"""
 
    return ask_report_ai(prompt)
 
def send_report(text):
    try:
        conn = ConnectHandler(**UBUNTU_CONFIG)
        
        if "FACILITY: DANGER" in text.upper():
            level = "ERROR"
        elif "FACILITY: WARNING" in text.upper():
            level = "WARN"
        else:
            level = "INFO"

        color_text = text
        color_text = re.sub(r'(Uptime: \d+d \d+h \d+m)', r'\\e[1;32m\1\\e[0m', color_text)
        color_text = re.sub(r'(drops=\d+|\d+(?:\.\d+)?(?:/\d+(?:\.\d+)?)*\s*(?:bps|Mbps|pps|packets per second)|\d+(?:\.\d+)?%)', r'\\e[1;37m\1\\e[0m', color_text, flags=re.IGNORECASE)
        
        green_words = ['stable', 'normal', 'secure', 'secured', 'verified', 'healthy']
        for word in green_words:
            color_text = re.sub(rf'\b({word})\b', r'\\e[1;32m\1\\e[0m', color_text, flags=re.IGNORECASE)
            
        cyan_words = ['mitigated', 'mitigating', 'blocked', 'blocking', 'filtered']
        for word in cyan_words:
            color_text = re.sub(rf'\b({word})\b', r'\\e[1;36m\1\\e[0m', color_text, flags=re.IGNORECASE)

        color_text = re.sub(r'(?i)\*?\bFACILITY\b\s*:\s*[A-Z\s/]+\*?\.?', '', color_text)
        color_text = re.sub(r'(\|\s*)+$', '', color_text.strip()).strip()
        
        if level == "ERROR":
            color_text += " | FACILITY: \\e[1;31mDANGER\\e[0m"
        elif level == "WARN":
            color_text += " | FACILITY: \\e[1;33mWARNING\\e[0m"
        else:
            color_text += " | FACILITY: \\e[1;32mNORMAL\\e[0m"
        
        safe_text = color_text.replace('"', '\\"').replace('\n', ' | ')
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        conn.send_command(f'echo -e "{timestamp} level={level} {safe_text}" >> {AI_REPORT_LOG_PATH}')
        conn.disconnect()
        
        print(f"\033[1;32m[REPORT]\033[0m Sent to Ubuntu (level={level})")
    except Exception as e:
        print(f"\033[1;31m[X] Report failed: {e}\033[0m")
 
# --- [4] MAIN LOOP ---
VALID_SHOW = re.compile(r'^show\s[\w\s\-/]+$')
VALID_CONFIG = re.compile(r'^interface\s+(Gi|Fa|GigabitEthernet|FastEthernet)\d+/\d+(/\d+)?\\n(shutdown|no shutdown)$')
 
def validate_cmd(cmd, is_config=False):
    cmd = cmd.strip()
    if is_config:
        return bool(VALID_CONFIG.match(cmd))
    else:
        return bool(VALID_SHOW.match(cmd))
 
LOKI_QUERY = f'{{job="cisco", device_source="{DEVICE_SOURCE}"}} |~ "DOT1X|AUTHMGR|MAB|SW_DAI|DHCP_SNOOPING|STORM_CONTROL|BPDUGUARD|SPANTREE|SISF|PM-4-ERR_DISABLE|IP_SOURCE_GUARD"'

def get_gradient_color(step, total_steps, start_rgb, end_rgb):
    r = int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * (step / max(1, total_steps)))
    g = int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * (step / max(1, total_steps)))
    b = int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * (step / max(1, total_steps)))
    return f"\033[38;2;{r};{g};{b}m"

def print_argus_banner():
    print("\033[1;32m" + "—" * 80 + "\033[0m")
    
    argus_logo = """
          █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
         ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
         ███████║██████╔╝██║  ███╗██║   ██║███████╗
         ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
         ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
         ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
         [ AUTONOMOUS PORT GUARDIAN & AUDIT SYSTEM ]
    """
    
    lines = argus_logo.strip("\n").split("\n")
    max_width = max(len(line) for line in lines) if lines else 1
    
    start_color = (100, 255, 100)  # Cyber Green
    end_color = (0, 100, 0)   # Light Blue
    
    for line in lines:
        for i, char in enumerate(line):
            color_code = get_gradient_color(i, max_width, start_color, end_color)
            
            if "[ AUTONOMOUS" in line:
                color_code += "\033[1m"
                
            sys.stdout.write(color_code + char)
        sys.stdout.write("\033[0m\n") 
    sys.stdout.flush()

    print("\033[1;37m" + "—" * 80 + "\033[0m\n")


def get_ra_drops(output):
    """Parse RA Guard counter output. Returns (status, drops).
    status: "PROTECTED" (drops>0) | "CLEAN" (drops=0) | "NO_POLICY" | "ERROR"
    """
    if "no ipv6 snooping policy attached" in output.lower():
        return ("NO_POLICY", None)
    
    ra_m = re.search(r'RA\s+guard\s+NDP\s+RA\s+\[(\d+)\]', output, re.IGNORECASE)
    if ra_m:
        drops = int(ra_m.group(1))
        return ("PROTECTED" if drops > 0 else "CLEAN", drops)
    
    if "Dropped messages on" in output and "Feature" in output:
        return ("CLEAN", 0)
    
    return ("ERROR", None)
 
 
def initialize_ra_baselines():
    """Bulk init RA Guard baselines using ONE persistent SSH session.
    Eliminates first-burst detection blind spot. Runs once at startup."""
    
    jump = None
    try:
        print()
        with LoadingSpinner("\033[1;36m[INIT]\033[0m Initializing RA Guard baselines (persistent SSH)"):
            conn_params = ROUTER_CONFIG.copy()
            if SSH_LEGACY:
                try:
                    conn_params['ssh_extra_args'] = SSH_LEGACY
                    jump = ConnectHandler(**conn_params)
                except Exception:
                    if 'ssh_extra_args' in conn_params:
                        del conn_params['ssh_extra_args']
                    jump = ConnectHandler(**conn_params)
            else:
                jump = ConnectHandler(**conn_params)
            
            jump.write_channel(f"ssh {SWITCH_IP}\n")
            time.sleep(2)
            output = jump.read_channel()
            if "assword" in output or "Password" in output:
                jump.write_channel(f"{PASS_VTY}\n")
                time.sleep(2)
            
            from netmiko import redispatch
            redispatch(jump, device_type='cisco_ios')
            jump.secret = PASS_EN
            jump.enable()
            config_out = jump.send_command(
                "show ipv6 snooping policies | include Target|RA guard",
                read_timeout=10
            )
            
            ra_ports = []
            for line in config_out.splitlines():
                m = re.match(r'^(Fa|Gi|Te)\d+/\d+\s+PORT\s+\S+\s+RA\s+guard', line.strip(), re.IGNORECASE)
                if m:
                    port = line.strip().split()[0]
                    if port not in ra_ports:
                        ra_ports.append(port)

        if not ra_ports:
            print("\033[1;33m[INIT]\033[0m No RA Guard policies found. Skipping baseline init.")
            return
        
        print(f"\033[1;36m[INIT]\033[0m Found \033[1m{len(ra_ports)}\033[0m RA Guard ports: \033[36m{ra_ports}\033[0m")
        
        baseline_count = 0
        no_policy_count = 0
        for port in ra_ports:
            try:
                output = jump.send_command(
                    f"show ipv6 snooping counters interface {port}",
                    read_timeout=10
                )
                status, drops = get_ra_drops(output)
                
                if status == "NO_POLICY":
                    print(f"\033[1;31m[INIT]\033[0m {port}: \033[1;31mNO POLICY ATTACHED\033[0m — port unprotected!")
                    event_buffer.append(f"{time.strftime('%H:%M:%S')} | {port} | NO RA POLICY at startup")
                    no_policy_count += 1
                    continue
                
                if status == "ERROR":
                    print(f"\033[1;33m[INIT]\033[0m {port}: parse failed, will lazy-init on first log")
                    continue
                
                save_counter(port, "RA_GUARD", str(drops))
                save_counter(port, "RA_GUARD_TIME", str(time.time()))
                
                if status == "PROTECTED":
                    print(f"\033[1;33m[INIT]\033[0m {port}: pre-existing drops: \033[1;31m{drops}\033[0m \033[3m(silent baseline)\033[0m")
                else:
                    print(f"\033[1;36m[INIT]\033[0m {port}: \033[3mclean (baseline=0)\033[0m")
                
                baseline_count += 1
            except Exception as e:
                print(f"\033[1;31m[INIT]\033[0m {port} failed: {e}")
        
        if no_policy_count > 0:
            print(f"\033[1;31m[INIT]\033[0m \033[1m{no_policy_count}\033[0m port(s) had NO POLICY attached!")
        print(f"\033[1;32m[INIT]\033[0m Captured \033[1m{baseline_count}\033[0m RA Guard baselines.\n")
    
    except Exception as e:
        print(f"\033[1;31m[INIT]\033[0m Error: {e}")
        print("\033[1;33m[INIT]\033[0m ARGUS will use lazy baseline (first-burst detection limited).")
    
    finally:
        if jump:
            try:
                jump.disconnect()
            except Exception:
                pass

POLICY_RESCAN_INTERVAL = 300
last_policy_check = 0
baseline_ra_ports = set()
drift_alert_count = {}

def get_known_ra_ports():
    """Extract RA Guard port list from prev_counters (ports that have RA_GUARD baseline)"""
    ports = set()
    for key in prev_counters:
        if key.endswith("_RA_GUARD"):
            port = key.replace("_RA_GUARD", "")
            ports.add(port)
    return ports

def rescan_ra_policies():
    """Periodic rescan: detect removed/added RA Guard policies"""
    global baseline_ra_ports
    
    try:
        config_out = netmiko_execute(
            "show ipv6 snooping policies | include Target|RA guard", 
            is_config=False
        )
        
        current_ports = set()
        for line in config_out.splitlines():
            m = re.match(r'^(Fa|Gi|Te)\d+/\d+\s+PORT\s+\S+\s+RA\s+guard', line.strip(), re.IGNORECASE)
            if m:
                port = line.strip().split()[0]
                current_ports.add(port)
        
        missing = baseline_ra_ports - current_ports
        if missing:
            for port in sorted(missing):
                count = drift_alert_count.get(port, 0)
                if count < 2:
                    print(f"\n\033[1;41m[POLICY DRIFT]\033[0m RA Guard REMOVED from \033[1m{port}\033[0m — port unprotected! (alert {count+1}/2)")
                    event_buffer.append(f"{time.strftime('%H:%M:%S')} | POLICY DRIFT REMOVED {port} (rescan)")
                    try:
                        send_report(f"CRITICAL: RA Guard policy removed from {port} (detected by periodic rescan) | FACILITY: DANGER")
                    except Exception:
                        pass
                    drift_alert_count[port] = count + 1
        
        new_ports = current_ports - baseline_ra_ports
        if new_ports:
            for port in sorted(new_ports):
                print(f"\n\033[1;32m[POLICY UPDATE]\033[0m RA Guard added on \033[1m{port}\033[0m")
                try:
                    counter_out = netmiko_execute(
                        f"show ipv6 snooping counters interface {port}",
                        is_config=False
                    )
                    status, drops = get_ra_drops(counter_out)
                    
                    if status in ("PROTECTED", "CLEAN"):
                        drops = drops or 0
                        save_counter(port, "RA_GUARD", str(drops))
                        save_counter(port, "RA_GUARD_TIME", str(time.time()))
                        print(f"  \033[1;36m[INIT]\033[0m {port} baseline counter = {drops} (live)")
                    else:
                        print(f"  \033[1;33m[WARN]\033[0m {port}: {status} — will lazy-init on first log")
                    
                    event_buffer.append(f"{time.strftime('%H:%M:%S')} | POLICY ADDED {port} (rescan, baseline={drops})")
                except Exception as e:
                    print(f"  \033[1;31m[WARN]\033[0m Could not init {port}: {e}")
        
        if not missing and not new_ports:
            print(f"\033[1;36m[RESCAN]\033[0m All {len(current_ports)} RA Guard policies intact.")
        
        for port in new_ports:
            if port in drift_alert_count:
                del drift_alert_count[port]
        
        still_tracking = set()
        for port in missing:
            if drift_alert_count.get(port, 0) < 2:
                still_tracking.add(port)
        
        baseline_ra_ports = current_ports | still_tracking
        
    except Exception as e:
        print(f"\033[1;31m[RESCAN ERROR]\033[0m {e}")

def main():
    global baseline_ra_ports, drift_alert_count, last_policy_check, last_report_time, last_scan_time
    print_argus_banner()
    initialize_ra_baselines()
    last_policy_check = time.time()
    baseline_ra_ports = get_known_ra_ports()
    drift_alert_count = {}
    if baseline_ra_ports:
        print(f"\033[1;36m[RESCAN]\033[0m Tracking {len(baseline_ra_ports)} RA Guard ports for drift detection: {sorted(baseline_ra_ports)}")

    while True:
        try:
            res = requests.get(LOKI_URL, params={
                'query': LOKI_QUERY,
                'limit': 20,
                'start': str(int((time.time() - 30) * 1e9))
            }, timeout=5).json()
 
            if res['data']['result']:
                cached_binding = None
                cached_counters = {}
 
                for stream in res['data']['result']:
                    for current_ts, raw_log in stream['values']:
                        if current_ts in seen_timestamps:
                            continue
                        seen_timestamps.add(current_ts)
                        save_seen_ts()
 
                        print(f"\n[!] LOG DETECTED: {raw_log[:100]}...")

                        if "AUTHMGR-5-SUCCESS" in raw_log or "MAB-5-SUCCESS" in raw_log:
                            maint_entries = load_maintenance_whitelist()
                            for entry in maint_entries:
                                if entry["mode"] == "access" and not entry["verified"]:
                                        if check_dot1x_auth_in_logs(entry["port"]):
                                            print(f"\n[802.1X] [SUCCESS] {entry['port']} — Admin authenticated via 802.1X!")
                                            print(f"[802.1X] Port verified. Maintenance continues.")
                                            entry["verified"] = True
                                            save_maintenance_whitelist(maint_entries)
                                            event_buffer.append(f"{time.strftime('%H:%M:%S')} | 802.1X VERIFIED: {entry['port']}")
                                            break
                    
                        if "SISF-4-PAK_DROP" in raw_log and "NDP::RA" in raw_log:
                            ra_port = ""
                            ra_m = re.search(r'I=(Fa|Gi)\d+/\d+', raw_log, re.IGNORECASE)
                            if ra_m:
                                ra_port = ra_m.group(0).replace("I=", "")
                        
                            if ra_port:
                                last_check = get_prev_counter(ra_port, "RA_LAST_CHECK")
                                if last_check and (time.time() - float(last_check)) < RA_DEDUPE_WINDOW_S:
                                    continue
                                save_counter(ra_port, "RA_LAST_CHECK", str(time.time()))
                            
                                vlan_m = re.search(r'V=(\d+)', raw_log)
                                vlan_id = vlan_m.group(1) if vlan_m else "10"
                            
                                ra_counter_out = netmiko_execute(f"show ipv6 snooping counters interface {ra_port}", is_config=False)
                            
                                if "no ipv6 snooping policy attached" in ra_counter_out.lower():
                                    print(f"\033[1;31m[POLICY DRIFT]\033[0m RA Guard {ra_port} | Policy REMOVED — port unprotected!")
                                    event_buffer.append(f"{time.strftime('%H:%M:%S')} | POLICY DRIFT REMOVED {ra_port}")
                                    save_security_dataset(f"NEW_LOG: {raw_log}", f"STEP: ESCALATE | ACTION: none | MSG: RA Guard policy removed from {ra_port}. Port unprotected. Admin attention required.")
                                    try:
                                        send_report(f"⚠️ RA Guard policy removed from {ra_port} — port unprotected!")
                                    except Exception:
                                        pass
                                    continue
                            
                                drop_match = re.search(r'RA\s+guard\s+NDP\s+RA\s+\[(\d+)\]', ra_counter_out, re.IGNORECASE)
                                current_drops = int(drop_match.group(1)) if drop_match else 0
                            
                                prev_ra = get_prev_counter(ra_port, "RA_GUARD")
                                prev_time = get_prev_counter(ra_port, "RA_GUARD_TIME")
                            
                                if prev_ra is None:
                                    save_counter(ra_port, "RA_GUARD", str(current_drops))
                                    save_counter(ra_port, "RA_GUARD_TIME", str(time.time()))
                                    print(f"[FILTER] RA Guard {ra_port} | VLAN {vlan_id} | Baseline={current_drops}. Hardware blocking.")
                                    event_buffer.append(f"{time.strftime('%H:%M:%S')} | RA {ra_port} | baseline={current_drops} | HW blocking")
                                    save_security_dataset(f"NEW_LOG: {raw_log}", f"STEP: MITIGATE | ACTION: none | MSG: RA Guard baseline={current_drops}. Hardware blocking. Monitor.")
                                else:
                                    delta = current_drops - int(prev_ra)
                                    elapsed = time.time() - float(prev_time) if prev_time else 0

                                    sw_time = parse_switch_time(raw_log)
                                    loki_time = parse_loki_time(raw_log)
                                    latency_ms = None
                                    if sw_time and loki_time:
                                        latency_ms = (loki_time - sw_time) * 1000
                                
                                    if delta == 0 and elapsed > RA_RESET_QUIET_SECONDS:
                                        save_counter(ra_port, "RA_GUARD", str(current_drops))
                                        save_counter(ra_port, "RA_GUARD_TIME", str(time.time()))
                                        print(f"[FILTER] RA Guard {ra_port} | Reset baseline={current_drops} (attack quiet >{RA_RESET_QUIET_SECONDS}s).")
                                        event_buffer.append(f"{time.strftime('%H:%M:%S')} | RA {ra_port} | Reset baseline")
                                        continue
                                
                                    if delta >= 1:
                                        latency_str = f" | latency={latency_ms:.0f}ms" if latency_ms else ""
                                        print(f"[WARNING] RA Guard {ra_port} | VLAN {vlan_id} | delta={delta} | Sustained Rogue RA!")
                                        print(f"[CORRELATION] Syslog vs HW counter: drops={current_drops}, delta={delta}{latency_str}")
                                        print(f"[INFO] RA Guard hardware blocking. No shutdown needed.")

                                        try:
                                            with open("latency_log.csv", "a") as f:
                                                f.write(f"{time.time()},{ra_port},{delta},{current_drops},{latency_ms or 'NA'}\n")
                                        except Exception:
                                            pass

                                        event_buffer.append(f"{time.strftime('%H:%M:%S')} | RA WARNING {ra_port} | delta={delta} | HW drops={current_drops}")
                                        save_security_dataset(f"NEW_LOG: {raw_log}", f"STEP: MITIGATE | ACTION: none | MSG: RA Guard HW blocking. Delta={delta}, drops={current_drops}.")
                                        save_counter(ra_port, "RA_GUARD_TIME", str(time.time()))
                                    else:
                                        save_counter(ra_port, "RA_GUARD", str(current_drops))
                                        save_counter(ra_port, "RA_GUARD_TIME", str(time.time()))
                                        print(f"[FILTER] RA Guard {ra_port} | delta={delta}. Stale log.")
                            continue
 
                        dai_match = re.search(r'Invalid ARPs', raw_log)
                        if dai_match:
                            if cached_binding is None:
                                cached_binding = netmiko_execute("show ip dhcp snooping binding", is_config=False)
                            port_dai = ""
                            pm = re.search(r'(Gi|Fa)\d+/\d+', raw_log, re.IGNORECASE)
                            if pm:
                                port_dai = pm.group(0)
 
                            dai_result = check_dai_attack(port_dai, cached_binding)
 
                            if dai_result == 'ignored':
                                print(f"[FILTER] DAI {port_dai} | Already flagged to admin. Skip.")
                                continue
                            elif dai_result == 'boot':
                                elapsed = time.time() - dai_first_seen.get(port_dai, time.time())
                                print(f"[FILTER] DAI {port_dai} | No lease, {elapsed:.0f}s/{BOOT_GRACE}s grace. Skip.")
                                event_buffer.append(f"{time.strftime('%H:%M:%S')} | DAI {port_dai} | SKIP - boot grace")
                                save_security_dataset(f"NEW_LOG: {raw_log}", "STEP: MITIGATE | ACTION: none | MSG: No lease, boot grace period. Monitor.")
                                continue
                            elif dai_result == 'stuck':
                                print(f"[FILTER] DAI {port_dai} | No lease after 3min. Device stuck. Notify admin.")
                                event_buffer.append(f"{time.strftime('%H:%M:%S')} | DAI {port_dai} | STUCK - no lease after 3min, possible device issue. Admin check required.")
                                save_security_dataset(f"NEW_LOG: {raw_log}", "STEP: MITIGATE | ACTION: none | MSG: No lease after 3min. Device stuck. Notify admin.")
                                dai_ignored_ports.add(port_dai)
                                if port_dai in dai_first_seen:
                                    del dai_first_seen[port_dai]
                                continue
                            elif dai_result == 'verify':
                                vlan_match = re.search(r'vlan (\d+)', raw_log)
                                vlan_id = vlan_match.group(1) if vlan_match else "10"

                                if vlan_id not in cached_counters:
                                    cached_counters[vlan_id] = netmiko_execute(f"show ip arp inspection statistics vlan {vlan_id}", is_config=False)
                                counter_output = cached_counters[vlan_id]

                                drop_match = re.search(r'\d+\s+\d+\s+(\d+)\s+\d+\s+\d+', counter_output)
                                current_drop = int(drop_match.group(1)) if drop_match else 0

                                prev_drop = get_prev_counter(port_dai, "ARP_SPOOF")
                                prev_time = get_prev_counter(port_dai, "ARP_SPOOF_TIME")

                                if prev_drop is not None:
                                    delta = current_drop - int(prev_drop)
                                    elapsed = time.time() - float(prev_time) if prev_time else 1

                                    # Rate = delta per minute
                                    rate = (delta / elapsed) * 60 if elapsed > 0 else 0

                                    save_counter(port_dai, "ARP_SPOOF", str(current_drop))
                                    save_counter(port_dai, "ARP_SPOOF_TIME", str(time.time()))
                                    if vlan_id in cached_counters:
                                        del cached_counters[vlan_id]

                                    if delta <= 0:
                                        print(f"[FILTER] DAI {port_dai} | delta={delta}. Stale log. Skip.")
                                        save_counter(port_dai, "ARP_SPOOF", str(current_drop))
                                        if vlan_id in cached_counters:
                                            del cached_counters[vlan_id]
                                        event_buffer.append(f"{time.strftime('%H:%M:%S')} | DAI {port_dai} | SKIP - stale (delta={delta})")
                                        save_security_dataset(f"NEW_LOG: {raw_log}", f"STEP: MITIGATE | ACTION: none | MSG: Counter delta={delta}. Stale log.")
                                        continue
                                    elif rate < DAI_RATE_THRESHOLD_PER_MIN:
                                        # Below threshold = boot or renewal
                                        print(f"[FILTER] DAI {port_dai} | delta={delta}, rate={rate:.1f}/min. Normal ARP. Skip.")
                                        event_buffer.append(f"{time.strftime('%H:%M:%S')} | DAI {port_dai} | SKIP - low rate ({rate:.1f}/min)")
                                        continue
                                    else:
                                        print(f"[FILTER] DAI {port_dai} | delta={delta}, rate={rate:.1f}/min. ATTACK -> AI.")
                                else:
                                    print(f"[FILTER] DAI {port_dai} | First baseline={current_drop}. Monitor.")
                                    save_counter(port_dai, "ARP_SPOOF", str(current_drop))
                                    save_counter(port_dai, "ARP_SPOOF_TIME", str(time.time()))
                                    if vlan_id in cached_counters:
                                        del cached_counters[vlan_id]
                                    event_buffer.append(f"{time.strftime('%H:%M:%S')} | DAI {port_dai} | First baseline={current_drop}. Monitor.")
                                    continue
 
                        # --- AI INVESTIGATE ---
                        investigate_prompt = f"NEW_LOG: {sanitize_log(raw_log)}. Request investigation command."
                        ai_req = ask_ai(investigate_prompt)
 
                        if "INVESTIGATE" in ai_req:
                            if "| CMD: " not in ai_req:
                                print(f"[X] AI format error, skip: {ai_req}")
                                continue
                            save_security_dataset(investigate_prompt, ai_req)
 
                            cmd = ai_req.split("| CMD: ")[1].split("|")[0].strip()

                            cmds = [c.strip() for c in cmd.split(";") if c.strip()]
                            real_status_parts = []
                            blocked = False
                            for single_cmd in cmds:
                                if not validate_cmd(single_cmd, is_config=False):
                                    print(f"[X] CMD blocked: {single_cmd}")
                                    blocked = True
                                    break
                                real_status_parts.append(netmiko_execute(single_cmd, is_config=False))
 
                            if blocked:
                                continue
 
                            real_status = "\n".join(real_status_parts)
 
                            # --- COUNTER MEMORY + AI DECISION ---
                            category = ""
                            if "CATEGORY: " in ai_req:
                                category = ai_req.split("CATEGORY: ")[1].split(" |")[0].strip()
 
                            port_from_log = ""
                            port_m = re.search(r'(Gi|Fa|GigabitEthernet|FastEthernet)\d+/\d+(/\d+)?', raw_log, re.IGNORECASE)
                            if port_m:
                                port_from_log = port_m.group(0)
 
                            prev = get_prev_counter(port_from_log, category)
                            prev_str = f" | PREV_COUNTERS: {prev}" if prev else ""
 
                            final_query = f"LOG: {raw_log} | REAL_STATUS: {real_status}{prev_str}. What is your final action?"
                            decision = ask_ai(final_query)

                            if "ACTION:" in decision:
                                save_security_dataset(final_query, decision)
 
                            counter_match = re.search(r'(?:Dropped|Total dropped)\D*(\d+)', real_status)
                            if counter_match and port_from_log and category:
                                save_counter(port_from_log, category, counter_match.group(1))
 
                            print(f"\n[AI DECISION]: {decision}")

                            # Caution: an LLM "ACTION: shutdown" becomes a real Netmiko config action here.
                            # Keep this path enabled only when threat confirmation is strong enough to justify
                            # the risk of a false-positive port shutdown.
                            if "ACTION: shutdown" in decision:
                                port_match = re.search(r'(Gi|Fa|GigabitEthernet|FastEthernet)\d+/\d+(/\d+)?', decision, re.IGNORECASE)
                                if port_match:
                                    port_name = port_match.group(0)
                                    port_check = netmiko_execute(f"show interfaces {port_name} status", is_config=False)
                                    check_lower = port_check.lower()
                                    if any(x in check_lower for x in ["disabled", "err-disabled"]):
                                        print(f"[V] Python Block: {port_name} already disabled. Skip.")
                                        event_buffer.append(f"{time.strftime('%H:%M:%S')} | BLOCKED: {port_name} already disabled")
                                    else:
                                        if "| CMD: " not in decision:
                                            print(f"[X] AI format error, skip: {decision}")
                                            continue
                                        config_cmd = decision.split("| CMD: ")[1].split("|")[0].strip()
                                        if not validate_cmd(config_cmd, is_config=True):
                                            print(f"[X] CONFIG blocked: {config_cmd}")
                                            continue
                                        result = netmiko_execute(config_cmd, is_config=True)
                                        print(f"[V] RESULT: {result}")
                                        record_shutdown(port_name, raw_log[:80])
                                        event_buffer.append(f"{time.strftime('%H:%M:%S')} | AI SHUTDOWN {port_name} | {raw_log[:80]}")
 
                                        # POSTCMD (clear counters after RA Guard shutdown)
                                        if "POSTCMD: " in decision:
                                            post_cmd = decision.split("POSTCMD: ")[1].split("|")[0].strip()
                                            if post_cmd.startswith("clear "):
                                                netmiko_execute(post_cmd, is_config=False)
                                                print(f"[V] POST: {post_cmd}")
                                else:
                                    print("[X] Cannot extract port. Skip.")
                            else:
                                print("[V] NO ACTION REQUIRED: System is already secure.")
                                event_buffer.append(f"{time.strftime('%H:%M:%S')} | {raw_log[:80]} | NO ACTION")
                        else:
                            print(f"[*] AI Info: {ai_req}")
 
            now = time.time()
            if now - last_scan_time >= SCAN_INTERVAL:
                last_scan_time = now
                raw_status = scan_ports()
                ports = parse_port_status(raw_status)

                maintenance_entries, expired_ports = cleanup_expired_whitelist()
                maintenance_ports = {e["port"]: e for e in maintenance_entries}
 
                if expired_ports:
                    ports_to_shut = []
                    for p in expired_ports:
                        if p in ports and ports[p] in ["connected", "trunk"]:
                            print(f"[MAINTENANCE] {p} timer expired but port is UP. Releasing to normal operation.")
                        else:
                            ports_to_shut.append(p)
                
                    if ports_to_shut:
                        range_cmd = build_range_cmd(ports_to_shut)
                        shut_cmd = range_cmd + "\\n" + "shutdown"
                        print(f"[MAINTENANCE EXPIRED] Shutting down unused: {ports_to_shut}")
                        result = netmiko_execute(shut_cmd, is_config=True)
                        print(f"[SCAN] EXPIRED SHUTDOWN: {result}")
                        event_buffer.append(f"{time.strftime('%H:%M:%S')} | MAINTENANCE EXPIRED SHUTDOWN: {ports_to_shut}")
                        for p in ports_to_shut:
                            record_shutdown(p, "maintenance timer expired")
                    
                ready_to_shutdown = []
                now = time.time()
 
                for port, status in ports.items():
                    # --- [1] Processing Port in WHITELIST (MAINTENANCE) ---
                    if port in maintenance_ports:
                        entry = maintenance_ports[port]
                        mode = entry.get("mode", "unknown")
                        verified = entry.get("verified", False)
                        expire = entry.get("expire", 0)
                        open_at = entry.get("open_at", now)
                    
                        if status in ["connected", "trunk"]:
                            if port in port_down_since: del port_down_since[port]

                            # A. TRUNK FLOW: Check CDP Identity (7s)
                            if mode == "trunk" and not verified:
                                print(f"[MAINTENANCE] {port} (trunk) UP — Waiting 7s for CDP verification...")
                                time.sleep(7)
                                expected = entry.get("expected_device", "")
                                found, actual_name = verify_trunk_cdp_identity(port, expected)
                                if found:
                                    print(f"[CDP] [SUCCESS] {port} Identity Verified: {actual_name}")
                                    entry["verified"] = True
                                    save_maintenance_whitelist(maintenance_entries)
                                else:
                                    print(f"[CDP] [FAIL] {port} — No trusted identity found!")
                                    ready_to_shutdown.append(port)
                    
                            # B. FLOW ACCESS: Check 802.1X (RADIUS)
                            elif mode == "access" and not verified:
                                if check_dot1x_auth_in_logs(port): 
                                    print(f"[802.1X] [SUCCESS] {port} Authenticated via Radius.")
                                    entry["verified"] = True
                                    save_maintenance_whitelist(maintenance_entries)
                                else:
                                    # If open after 5min but not Auth Success -> Shutdown
                                    if now - open_at > 300:
                                        print(f"[802.1X] [FAIL] {port} Authentication Timeout (5 mins).")
                                        ready_to_shutdown.append(port)
                                    else:
                                        print(f"[MAINTENANCE] {port} (access) UP — Waiting for 802.1X auth...")

                            # C. VERIFIED → maintenance complete, remove from whitelist
                            elif verified:
                                if expire > 0 and now < expire:
                                    remaining = int((expire - now) / 60)
                                    if remaining > 0:
                                        print(f"[MAINTENANCE] {port} ({mode}) VERIFIED + protected. {remaining}m remaining.")
                                else:
                                    print(f"[MAINTENANCE] {port} ({mode}) UP + VERIFIED. Maintenance complete.")
                                    new_maint = [e for e in maintenance_entries if e["port"] != port]
                                    save_maintenance_whitelist(new_maint)
                                    print(f"[WHITELIST] {port} removed. Now a normal port.")

                        elif status == "notconnect":
                            if expire > 0 and now < expire:
                                remaining = int((expire - now) / 60)
                                print(f"[MAINTENANCE] {port} is DOWN. Window: {remaining}m left.")
                            elif expire > 0 and now >= expire:
                                print(f"[MAINTENANCE] {port} window CLOSED (Expired).")
                                ready_to_shutdown.append(port)
                            elif expire == 0:
                                if port not in port_down_since:
                                    port_down_since[port] = now
                                    print(f"[SCAN] {port} notconnect (no timer) - starting {NOTCONNECT_COUNTDOWN_S}s countdown")
                                elif now - port_down_since[port] >= NOTCONNECT_COUNTDOWN_S:
                                    ready_to_shutdown.append(port)
                    
                        elif status == "disabled":
                            if port in port_down_since:
                                del port_down_since[port]
                            new_maint = [e for e in maintenance_entries if e["port"] != port]
                            save_maintenance_whitelist(new_maint)
                            print(f"\033[1;33m[MAINTENANCE]\033[0m \033[1m{port}\033[0m err-disabled by switch. Removed from whitelist.")
                        continue

                    # --- [2] Processing ports outside WHITELIST ---
                    if port in rollback_whitelist: continue

                    if status == "notconnect":
                        if port not in port_down_since:
                            port_down_since[port] = now
                        elif now - port_down_since[port] >= NOTCONNECT_COUNTDOWN_S:
                            ready_to_shutdown.append(port)
                
                    elif status == "connected" or status == "trunk":
                        if port in port_down_since:
                            del port_down_since[port]
                
                    elif status == "disabled":
                        if port in port_down_since:
                            del port_down_since[port]
                        if port in maintenance_ports:
                            new_maint = [e for e in maintenance_entries if e["port"] != port]
                            save_maintenance_whitelist(new_maint)
                            print(f"[MAINTENANCE] {port} err-disabled by switch. Removed from whitelist.")

                # --- [3] BREAKDOWN: BATCH SHUTDOWN & CLEANUP JSON---
                if ready_to_shutdown:
                    range_cmd = build_range_cmd(ready_to_shutdown)
                    result = netmiko_execute(range_cmd + "\\nshutdown", is_config=True)
                    print(f"\033[1;31m[SCAN] BATCH SHUTDOWN:\033[0m \033[1m {result}\033[0m")

                    event_buffer.append(f"{time.strftime('%H:%M:%S')} | SCAN BATCH SHUTDOWN: {ready_to_shutdown}")
            
                    new_maintenance = [e for e in maintenance_entries if e["port"] not in ready_to_shutdown]
                    save_maintenance_whitelist(new_maintenance)
            
                    for p in ready_to_shutdown:
                        record_shutdown(p, "security audit / maintenance expired")
                        if p in port_down_since: del port_down_since[p]
 
            if time.time() - last_policy_check > POLICY_RESCAN_INTERVAL:
                print(f"\n\033[1;36m[RESCAN]\033[0m Running periodic RA Guard policy check...")
                rescan_ra_policies()
                last_policy_check = time.time()
 
            if time.time() - last_report_time >= REPORT_INTERVAL:
                print("\033[1;35m[REPORT]\033[0m Generating...")
                report = ai_full_report()
                print(f"\033[1;35m[REPORT]\033[0m \033[3m {report[:200]}\033[0m")
                send_report(report)
                event_buffer.clear()
                last_report_time = time.time()
                pass
 
        except Exception as e:
            print(f"\n[X] Loop error: {e}")
 
        time.sleep(10)


if __name__ == "__main__":
    main()
