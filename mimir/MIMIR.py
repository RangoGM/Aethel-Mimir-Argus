import requests
import re
import time
import sys
import threading
import getpass
import json
import os
import textwrap
import traceback
from netmiko import ConnectHandler, redispatch

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WHITELIST_FILE = os.path.join(SCRIPT_DIR, "scan_whitelist.json")

def save_qa_dataset(instruction, expected_output): # Keep the original formatting but strip leading/trailing whitespace
    clean_output = expected_output.strip()
    clean_instr = instruction.strip()
    
    if "EXECUTE:" in clean_output and "\nEXECUTE:" not in clean_output: # Optional: If you want to force EXECUTE to always be on a new line
        clean_output = clean_output.replace("EXECUTE:", "\n\nEXECUTE:")
    
    if os.path.exists("admin_dataset.json"):
        with open("admin_dataset.json", "r", encoding="utf-8") as f:
            content = f.read()
            instr_serialized = json.dumps(clean_instr, ensure_ascii=False) # Force instruction go back to JSON format 
            if instr_serialized in content:
                print(f"\033[1;33m[!] WARNING:\033[0m \033[1;37mTHIS EXAMPLE HAS BEEN SAVED.\033[0m \033[1;31mBLOCK DUE TO DUPLICATED!\033[0m")
                return
    # --- COLLECTING DATA ---
    data = {"instruction": clean_instr, "output": clean_output}
    with open("admin_dataset.json", "a", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=2, ensure_ascii=False) + ",\n") # json.dumps will automatically turn real newlines into \n characters

# --- LOADING SPINNIER ---
class LoadingSpinner:
    def __init__(self, message="MIMIR is thinking"):
        self.message = message
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._spin)
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

    def _spin(self):
        idx = 0
        while not self.stop_event.is_set():
            sys.stdout.write(f"\r \033[1;36m{self.spinner_chars[idx]}\033[0m \033[3m\033[1;37m{self.message}...\033[0m")
            sys.stdout.flush()
            idx = (idx + 1) % len(self.spinner_chars)
            time.sleep(0.08)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_event.set()
        self.thread.join()
        sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")
        sys.stdout.flush()

# --- CONFIG ---
# Public repo note: deployment values are intentionally omitted here.
# Copy configs/config.example.py locally, replace the placeholders with private values,
# and keep the real config out of version control.
# --- SECURITY POLICY ---
authenticated = False
chat_history = []
AI_MODEL = "mimir-finetuned"
AI_PLANNER_MODEL = "mimir-finetuned-planner"
AI_USE_CHAT_HISTORY = False
 
CRITICAL_FORBIDDEN_COMMANDS = [
    "no ipv6 nd raguard",
    "no ipv6 snooping",
    "no dot1x",
    "no authentication",
]
 
RISKY_COMMAND_WARNINGS = {
    "switchport protected": "WARNING: Port Isolation detected. Potential Tromboning effect on Gateway.",
    "no spanning-tree portfast": "NOTE: STP reconvergence will occur on this port."
}
 
def validate_security_policy(ai_response):
    response_lower = ai_response.lower()
    for forbidden in CRITICAL_FORBIDDEN_COMMANDS:
        if forbidden in response_lower:
            return False, f"\033[1;41m[SECURITY VIOLATION]\033[0m \033[1;31m'{forbidden}' is restricted.\033[0m"
    for risky, msg in RISKY_COMMAND_WARNINGS.items():
        if risky in response_lower:
            return True, f"\033[1;33m[RISK ALERT]\033[0m \033[1;37m{msg}\033[0m"
    return True, "Safe"
 
# --- SAFETY FILTER PORTS ---
CRITICAL_KEYWORDS = ["server", "printer", "camera", "voip", "phone", "iot", "critical", "infra"]

def parse_safe_shutdown(switchport_output, run_output, status_output=""):
    # Step 1: Parse switchport — non-trunk
    lines = switchport_output.splitlines()
    non_trunk_ports = []
    for i, line in enumerate(lines):
        if "Name:" in line:
            port = line.split("Name:")[1].strip()
            if i + 1 < len(lines) and "Administrative Mode:" in lines[i + 1]:
                mode = lines[i + 1].split("Administrative Mode:")[1].strip()
                if "trunk" not in mode.lower():
                    non_trunk_ports.append(port)

    # Step 2: Parse portfast
    portfast_ports = []
    current_intf = None
    for line in run_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface "):
            current_intf = stripped.split("interface ")[1].strip()
        elif "spanning-tree portfast" in stripped and current_intf:
            portfast_ports.append(current_intf)
            current_intf = None

    # Step 3: Parse description — port has description = critical, no shutdown
    critical_ports = set()
    if status_output:
        for line in status_output.splitlines():
            match = re.match(r'^(Fa|Gi|Te|Et)(\d+/\d+(/\d+)?)\s+', line.strip())
            if match:
                port = match.group(0).strip()
                # Has description (Does not blank between Port - Name - Status)
                rest = line[match.end():].strip()
                if rest and not rest.startswith(("connected", "notconnect", "disabled")):
                    desc_lower = rest.lower()
                    if any(kw in desc_lower for kw in CRITICAL_KEYWORDS):
                        critical_ports.add(port)

    # Step 4: Normalize
    def normalize(port):
        return port.replace("TenGigabitEthernet", "Te").replace("GigabitEthernet", "Gi").replace("FastEthernet", "Fa").replace("Ethernet", "Et")

    norm_non_trunk = set(normalize(p) for p in non_trunk_ports)
    norm_portfast = set(normalize(p) for p in portfast_ports)

    safe_ports = sorted((norm_non_trunk & norm_portfast) - critical_ports)
    return safe_ports, critical_ports

def summarize_ipv6_snooping_counters(cli_output):
    target_match = re.search(r'Received messages on ([^:]+):', cli_output, re.IGNORECASE)
    target = target_match.group(1).strip() if target_match else "target"

    def section_between(start_pattern, end_pattern=None):
        start = re.search(start_pattern, cli_output, re.IGNORECASE)
        if not start:
            return ""
        section_start = start.end()
        if end_pattern:
            end = re.search(end_pattern, cli_output[section_start:], re.IGNORECASE)
            if end:
                return cli_output[section_start:section_start + end.start()]
        return cli_output[section_start:]

    def count_msg(section, msg):
        match = re.search(rf'\b{re.escape(msg)}\[(\d+)\]', section)
        return int(match.group(1)) if match else 0

    received = section_between(r'Received messages on [^:]+:', r'Bridged messages from')
    bridged = section_between(r'Bridged messages from [^:]+:', r'Dropped messages on')
    dropped = section_between(r'Dropped messages on [^:]+:')

    received_rs = count_msg(received, "RS")
    received_ra = count_msg(received, "RA")
    bridged_rs = count_msg(bridged, "RS")
    bridged_ra = count_msg(bridged, "RA")
    dropped_ra_match = re.search(r'\bRA\s+\[(\d+)\]', dropped)
    dropped_ra = int(dropped_ra_match.group(1)) if dropped_ra_match else count_msg(dropped, "RA")

    reason_match = re.search(r'reason:\s*(.+?)(?:\s*\[\d+\])?\s*$', dropped, re.IGNORECASE | re.MULTILINE)
    reason = reason_match.group(1).strip() if reason_match else "not shown"

    return (
        f"{target}: received RS={received_rs}, RA={received_ra}; bridged RS={bridged_rs}, RA={bridged_ra}.\n"
        f"RA Guard dropped {dropped_ra} RA messages.\n"
        f"Reason: {reason}. RA Guard is actively blocking unauthorized Router Advertisements."
    )

def local_cli_summary(cmd, cli_output, pre_summary=""):
    if "ipv6 snooping counters" in cmd.lower():
        return summarize_ipv6_snooping_counters(cli_output)

    if "% Invalid input" in cli_output:
        return "Cisco IOS rejected the command with an invalid-input marker (^). Verify the command syntax for this platform before retrying."

    if pre_summary.strip():
        return pre_summary.strip()

    useful_lines = [
        line.strip()
        for line in cli_output.splitlines()
        if line.strip() and not line.strip().startswith("---")
    ][:5]
    if useful_lines:
        return "Command completed. Key output lines:\n" + "\n".join(f"- {line}" for line in useful_lines)

    return "Command completed, but no useful output was returned."

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
 
# --- AI BRAIN (STREAMING + BLOCK CURSOR) ---
def ask_ai(prompt, silent=False, spinner_text="MIMIR is analyzing and checking Policy", model=None, use_history=None, record_history=True):
    url = "http://localhost:11434/api/chat"
    model_name = model or AI_MODEL
    history_enabled = AI_USE_CHAT_HISTORY if use_history is None else use_history
    if record_history:
        chat_history.append({"role": "user", "content": prompt})
    active_messages = chat_history[-10:] if history_enabled else [{"role": "user", "content": prompt}]

    try:
        spinner = LoadingSpinner(spinner_text)
        spinner.__enter__()

        r = requests.post(url, json={
            "model": model_name,
            "messages": active_messages,
            "stream": True,
            "keep_alive": "1h",
            "options": {
                "num_ctx": 4096,
                "num_predict": 2048,
            }
        }, stream=True, timeout=60)
        r.raise_for_status()

        response_text = ""
        first_token = True
        block_printed = False
        bold_mode = False

        for line in r.iter_lines():
            if line:
                chunk = json.loads(line)
                content = chunk.get('message', {}).get('content', '')

                if content:
                    if first_token:
                        if not silent:
                            spinner.__exit__(None, None, None)
                            sys.stdout.write("\r\033[K\033[1;36m[MIMIR]\033[0m \033[1;36m")
                        first_token = False
 
                    response_text += content

                    if not silent:
                        if block_printed:
                            sys.stdout.write('\b \b')
                        display_content = content
                        while "**" in display_content:
                            if not bold_mode:
                                display_content = display_content.replace("**", "\033[1m", 1)
                                bold_mode = True
                            else:
                                display_content = display_content.replace("**", "\033[0m\033[1;37m", 1) 
                                bold_mode = False
                        
                        display_content = display_content.replace("\\n", "\n    ")
                        display_content = display_content.replace("EXECUTE:", "\033[1;32mEXECUTE:\033[0m\033[1;37m")
                        sys.stdout.write(display_content)

                        if not content.endswith('\n'):
                            sys.stdout.write('\u2588')
                            block_printed = True
                        else:
                            block_printed = False
                        
                        sys.stdout.flush()
        
        if silent:
            spinner.__exit__(None, None, None)
            sys.stdout.write("\r\033[K")

        if not silent:
            if block_printed:
                sys.stdout.write('\b \b')
            sys.stdout.write("\033[0m\n")
            sys.stdout.flush()
            print() 
        
        if record_history:
            chat_history.append({"role": "assistant", "content": response_text})
        return response_text
    
    except Exception as e:
        try:
            spinner.__exit__(None, None, None)
        except:
            pass
        print()
        return f"ERROR: AI_CONNECTION_FAILED ({e})"
    
# --- NETMIKO WITH REDISPATCH (Jump Host) ---
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
        
    jump = None
    try:
        with LoadingSpinner(f"Jumping to Switch {SWITCH_IP} via Netmiko "):
            conn_params = ROUTER_CONFIG.copy()
            if SSH_LEGACY:
                try:
                    conn_params['ssh_extra_args'] = SSH_LEGACY
                    jump = ConnectHandler(**conn_params)
                except:
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
            with LoadingSpinner(f"Pushing {len(cmd_list)} config commands"):
                output = jump.send_config_set(cmd_list)
            print(f"  \033[1;32m[OK]\033[0m \033[1;37m{len(cmd_list)} commands applied\033[0m")
        else:
            for c in cmd_list:
                with LoadingSpinner(f"Running: {c[:60]}"):
                    output += f"\033[1;36m--- {c} ---\033[0m\n"
                    output += jump.send_command(c, read_timeout=15) + "\n\n"
        return output
 
    except Exception as e:
        print(f"\033[1;31m[!] Netmiko Error: {e}\033[0m")
        return f"EXECUTION_ERROR: {str(e)}"
    
    finally:
        if jump:
            try:
                jump.disconnect()
            except:
                pass
    
# Keywords that trigger auto-audit before risky config
AUDIT_TRIGGER_KEYWORDS = [
    "ip dhcp snooping", "ip arp inspection", 
    "ip verify source", "storm-control", "storm control",
    "spanning-tree", "dot1x", 
    "authentication", "switchport protected", 
    "ipv6 nd raguard", "shutdown", "shut",
    "dhcp snooping", "arp inspection",
    "portfast", "ra guard", "raguard", "ipv6 snooping",
    "port-security", "port security", "sticky mac", "switchport mode", "vlan",
    "configure",
    "remove",
]

def detect_flags(user_input):
    """
    Detect --force and VERIFIED flags in admin input.
    Returns: (clean_input, has_force, has_verified)
    """
    has_force = "--force" in user_input.lower()
    has_verified = "verified" in user_input.lower() or "i have verified" in user_input.lower()
    
    clean = user_input.replace("--force", "").replace("--FORCE", "").strip()
    return clean, has_force, has_verified
 
def extract_ports_from_input(user_input):
    """Extract port names from admin request"""
    ports = []
    matches = re.findall(r'\b(f[a-z]*|g[a-z]*|t[a-z]*|e[a-z]*)\s*(\d+(?:/\d+)?)/(\d+)(?:\s*(?:-|to)\s*(?:(?:f[a-z]*|g[a-z]*|t[a-z]*|e[a-z]*)\s*\d+(?:/\d+)?/)?(\d+))?', user_input, re.IGNORECASE)
    for match in matches:
        prefix = match[0][:2].capitalize()
        slot = match[1]
        start_port = int(match[2])
        if match[3]:
            for p in range(start_port, int(match[3]) + 1):
                ports.append(f"{prefix}{slot}/{p}")
        else:
            ports.append(f"{prefix}{slot}/{start_port}")
    return list(dict.fromkeys(ports)) 
 
def run_edge_port_audit(ports):
    """
    Run automated 3-point audit on specified ports:
    1. Administrative Mode (trunk check)
    2. Spanning-tree portfast (edge port check)  
    3. Description (critical port check)
    Returns: audit_summary string to inject into AI prompt
    """
    if not ports:
        return ""
    
    print(f"\n\033[1;36m{'='*50}\033[0m")
    print(f"  \033[1;36mAUTO EDGE-PORT AUDIT ({len(ports)} ports)\033[0m")
    print(f"\033[1;36m{'='*50}\033[0m")
    
    sw_out = netmiko_execute("show interfaces switchport | include Name:|Administrative Mode:", is_config=False)
    status_out = netmiko_execute("show interfaces status", is_config=False)
    run_out = netmiko_execute("show run | include ^interface|spanning-tree portfast", is_config=False)
    
    safe_ports, critical_ports = parse_safe_shutdown(sw_out, run_out, status_out)
    requested_safe = [p for p in safe_ports if any(p.endswith(rp[2:]) for rp in ports)]
    requested_critical = [p for p in critical_ports if any(p.endswith(rp[2:]) for rp in ports)]
    
    audit_lines = []
    for port in ports:
        port_suffix = port[2:] if "/" in port else port

        desc_text = ""
        match = re.search(rf'^{port[:2]}[a-z]*{port[2:]}\s+(.*?)\s+(?:connected|notconnect|disabled)', status_out, re.MULTILINE | re.IGNORECASE)
        if match and match.group(1).strip():
            desc_text = f" ({match.group(1).strip()})"
        
        is_trunk = False
        lines = sw_out.splitlines()
        for i, line in enumerate(lines):
            if "Name:" in line:
                sw_port_name = line.split("Name:")[1].strip()
                sw_port_name = sw_port_name.replace("FastEthernet", "Fa").replace("GigabitEthernet", "Gi").replace("TenGigabitEthernet", "Te")
                
                if sw_port_name == port:
                    if i + 1 < len(lines) and "trunk" in lines[i + 1].lower():
                        is_trunk = True
                    break
        
        if is_trunk:
            audit_lines.append(f"  {port}: TRUNK{desc_text} - BLOCKED (never touch trunk ports)")
            print(f"  \033[1;37m{port}\033[0m: \033[1;31mTRUNK{desc_text} - BLOCKED\033[0m")
        elif port in requested_critical:
            audit_lines.append(f"  {port}: CRITICAL{desc_text} - BLOCKED")
            print(f"  \033[1;37m{port}\033[0m: \033[1;31mCRITICAL{desc_text} - BLOCKED\033[0m")
        elif port in requested_safe:
            audit_lines.append(f"  {port}: SAFE{desc_text} (static access + portfast + no description)")
            print(f"  \033[1;37m{port}\033[0m: \033[1;32mSAFE{desc_text}\033[0m")
        else:
            # Check if no portfast
            normalized_port = port[:2].capitalize() + port[2:]
            has_portfast = normalized_port in safe_ports
            if not has_portfast:
                audit_lines.append(f"  {port}: NO PORTFAST - CAUTION{desc_text}")
                print(f"  \033[1;37m{port}\033[0m: \033[1;33mNO PORTFAST - CAUTION{desc_text}\033[0m")
            else:
                audit_lines.append(f"  {port}: UNKNOWN STATUS{desc_text}")
                print(f"  \033[1;37m{port}\033[0m: \033[1;30mUNKNOWN{desc_text}\033[0m")
    
    print(f"\033[1;36m{'='*50}\033[0m")
    
    audit_summary = "SYSTEM_AUDIT_RESULT:\n" + "\n".join(audit_lines)
    return audit_summary
 
def should_trigger_audit(user_input, ai_response):
    """Check if the request involves risky config that needs auto-audit"""
    combined = (user_input + " " + ai_response).lower()
    if combined.strip().startswith("show "):
        return False
    
    words = combined.split()
    first_word = words[0] if words else ""
    
    pure_question = ["what", "why", "how", "is", "does", "has", "are", "do"]
    if first_word in pure_question:
        return False
    
    modal_verbs = ["can", "could", "should", "would"]
    action_verbs = ["shutdown", "shut", "configure", "config", "enable", 
                    "disable", "remove", "add", "set", "apply", "move", 
                    "migrate", "open", "close", "put", "place", "change",
                    "switch", "create", "delete", "clear"]
    
    if first_word in modal_verbs:
        remaining = words[1:]  # ALL words after "can"
        has_action = any(w in action_verbs for w in remaining)
        if not has_action:
            return False 

    if combined.endswith("?") and first_word not in modal_verbs:
        return False
    
    return any(kw in combined for kw in AUDIT_TRIGGER_KEYWORDS)

def normalize_interface_name(port):
    """Normalize Cisco interface names to short form, e.g. GigabitEthernet0/1 -> Gi0/1."""
    clean = port.strip().replace(" ", "")
    prefix_map = [
        (r"^tengigabitethernet", "Te"),
        (r"^gigabitethernet", "Gi"),
        (r"^fastethernet", "Fa"),
        (r"^ethernet", "Et"),
        (r"^te", "Te"),
        (r"^gi", "Gi"),
        (r"^fa", "Fa"),
        (r"^et", "Et"),
    ]

    for pattern, replacement in prefix_map:
        if re.match(pattern, clean, re.IGNORECASE):
            return re.sub(pattern, replacement, clean, count=1, flags=re.IGNORECASE)

    return clean

def is_trunk_port(cmd):
    """Check if command targets a trunk port — NEVER allow shutdown trunk"""
    port_match = []
    matches = re.findall(r'(fa[a-z]*|gi[a-z]*|te[a-z]*|et[a-z]*)\s*(\d+(?:/\d+)?)/(\d+)(?:\s*(?:-|to)\s*(?:(?:fa[a-z]*|gi[a-z]*|te[a-z]*|et[a-z]*)\s*\d+(?:/\d+)?/)?(\d+))?', cmd, re.IGNORECASE)

    for match in matches:
        prefix = match[0][:2].capitalize()
        slot = match[1]
        start_port = int(match[2])

        if match[3]:
            end_port = int(match[3])
            for p in range(start_port, end_port + 1):
                port_match.append(normalize_interface_name(f"{prefix}{slot}/{p}"))
        else:
            port_match.append(normalize_interface_name(f"{prefix}{slot}/{start_port}"))

    if not port_match:
        return False, []
    
    trunk_out = netmiko_execute("show interfaces switchport | include Name:|Administrative", is_config=False)
    trunk_ports = set()
    current_port = None

    for line in trunk_out.splitlines():
        line = line.strip()
        if line.startswith("Name:"):
            current_port = normalize_interface_name(line.split(":", 1)[1])
        elif "Administrative Mode:" in line and "trunk" in line.lower():
            if current_port:
                trunk_ports.add(current_port)
    
    flagged = [p for p in port_match if p in trunk_ports]
    return len(flagged) > 0, flagged
 
ACCESS_PORT_HARDENING = [
    "switchport mode access",
    "no cdp enable",
    "authentication order dot1x",
    "authentication priority dot1x",
    "authentication port-control auto",
    "authentication periodic",
    "authentication host-mode single-host",
    "authentication violation restrict",
    "authentication timer reauthenticate server",
    "authentication timer inactivity 600",
    "dot1x pae authenticator",
    "dot1x timeout tx-period 10",
    "no shutdown"
]

TRUNK_PORT_HARDENING = [
    "cdp timer 5",
    "cdp holdtime 15",
    "no shutdown"
]
 
def get_port_modes(ports):
    """
    Fetch Administrative Mode for each port from switch.
    Returns: dict {port: 'access'|'trunk'|'dynamic auto'|'unknown'}
    """
    sw_out = netmiko_execute("show interfaces switchport | include Name:|Administrative Mode:", is_config=False)
    
    modes = {}
    lines = sw_out.splitlines()
    for i, line in enumerate(lines):
        if "Name:" in line:
            port_name = line.split("Name:")[1].strip()
            port_name = port_name.replace("FastEthernet", "Fa").replace("GigabitEthernet", "Gi").replace("TenGigabitEthernet", "Te")
            if i + 1 < len(lines) and "Administrative Mode:" in lines[i + 1]:
                mode = lines[i + 1].split("Administrative Mode:")[1].strip().lower()
                modes[port_name] = mode
    
    result = {}
    for port in ports:
        if port in modes:
            result[port] = modes[port]
        else:
            result[port] = "unknown"
            
    return result
 
def write_maintenance_whitelist(port, mode, expire_ts, expected_device=""):
    """
    Write/update scan_whitelist.json with new format:
    [{"port": "Fa0/2", "mode": "access", "expire": 1713100000, "verified": false}]
    """
    entries = load_maintenance_whitelist()

    port = re.sub(r'^(fa|gi|te|et)', lambda m: m.group(1).capitalize(), port, flags=re.IGNORECASE)

    entries = [e for e in entries if e["port"] != port]
    entries.append({
        "port": port,
        "mode": mode,
        "expire": expire_ts,
        "open_at": time.time(), 
        "verified": False,
        "expected_device": expected_device
    })
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
 
def load_maintenance_whitelist():
    """Load whitelist entries from JSON"""
    if not os.path.exists(WHITELIST_FILE):
        return []
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return []
 
def mark_verified(port):
    """Mark port as verified (802.1X success or CDP confirmed)"""
    entries = load_maintenance_whitelist()
    for entry in entries:
        if entry["port"] == port:
            entry["verified"] = True
            break
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
 
def verify_trunk_cdp_identity(port, expected_name=""):
    """Check CDP neighbors — verify admin-provided device name"""
    try:
        with LoadingSpinner(f"Verifying CDP identity on {port}"):
            cdp_out = netmiko_execute("show cdp neighbors | begin Device ID", is_config=False)
        
        match = re.match(r'^(Fa|Gi|Te|Et)(.*)$', port, re.IGNORECASE)
        if not match:
            return False, None
        prefix = match.group(1)
        port_num = match.group(2)
        
        for line in cdp_out.splitlines():
            if "Device ID" in line or "Capability" in line or line.startswith("Capability Codes"):
                continue
                
            tokens = line.split()
            if len(tokens) >= 3:
                neighbor_name = tokens[0].strip()
                local_part = line[len(neighbor_name):]
                if re.search(rf'\b{prefix}[a-z]*\s*{port_num}\b', local_part, re.IGNORECASE):
                    clean_neighbor = neighbor_name.split('.')[0]
                    if expected_name:
                        if clean_neighbor.lower() == expected_name.lower():
                            return True, clean_neighbor
                        else:
                            return False, clean_neighbor
                    else:
                        return True, clean_neighbor
        
        return False, None
    except Exception as e:
        print(f"\033[1;31m[!] Error in CDP parsing:\033[0m {e}")
        return False, None
 
def open_port_workflow(ports, has_force=False):
    """
    Complete secure port open workflow:
    1. Check administrative mode (access/trunk)
    2. Ask maintenance timer
    3. Push hardening config BEFORE no shutdown
    4. Verify identity after port up (802.1X for access, CDP for trunk)
    """
    print(f"\n{'='*50}")
    print(f"  SECURE PORT OPEN WORKFLOW")
    print(f"{'='*50}")
    
    with LoadingSpinner("Checking Administrative Mode for ports"):
        port_modes = get_port_modes(ports)
    
    access_ports = []
    trunk_ports = []
    
    for port, mode in port_modes.items():
        if "trunk" in mode:
            trunk_ports.append(port)
            print(f"  \033[1;37m{port}\033[0m: \033[1;35mTRUNK\033[0m")
        else:
            access_ports.append(port)
            print(f"  \033[1;37m{port}\033[0m: \033[1;32mACCESS\033[0m (\033[3m{mode}\033[0m)")
    
    print(f"{'='*50}")
    
    timer_input = input("\n[?] Maintenance timer in minutes (empty = 60s auto-scan default): ").strip()
    
    if timer_input:
        try:
            timer_minutes = int(timer_input)
            expire_ts = time.time() + (timer_minutes * 60)
            print(f"[TIMER] Maintenance window: {timer_minutes} minutes")
        except:
            print("[!] Invalid timer. Using 60s auto-scan default.")
            expire_ts = 0  
    else:
        expire_ts = 0 
        print("[TIMER] No timer set. Auditor 60s unused scan will handle.")
    
    if access_ports:
        print(f"\n\033[1;36m--- ACCESS PORTS ({len(access_ports)}) ---\033[0m")
        status_out = netmiko_execute("show interfaces status", is_config=False)
        run_out = netmiko_execute("show run | include ^interface|description|authentication port-control auto", is_config=False)
        
        port_desc = {}
        ports_with_802x = set()
        current_intf = None
        
        for line in run_out.splitlines():
            stripped = line.strip()
            if stripped.startswith("interface "):
                raw = stripped.split("interface ")[1].strip()
                current_intf = raw.replace("FastEthernet", "Fa").replace("GigabitEthernet", "Gi").replace("TenGigabitEthernet", "Te")
                port_desc[current_intf] = ""
            elif stripped.startswith("description ") and current_intf:
                port_desc[current_intf] = stripped.split("description ", 1)[1].lower()
            elif "authentication port-control auto" in stripped and current_intf:
                ports_with_802x.add(current_intf)
        
        already_up = []
        currently_down = []
        
        for port in access_ports:
            found_status = False
            for line in status_out.splitlines():
                match = re.match(r'^(Fa|Gi|Te|Et)(\d+/\d+)', line.strip())
                if match:
                    sw_port = match.group(0)
                    if sw_port == port:
                        found_status = True
                        if "connected" in line.lower():
                            already_up.append(port)
                        else:
                            currently_down.append(port)
                        break
    
            if not found_status:
                currently_down.append(port)
        
        critical_ports = []
        normal_ports = []
        critical_keywords = ["server", "printer", "camera", "voip", "phone", "iot", "critical", "infra"]
        
        for port in currently_down:
            desc = port_desc.get(port, "")
            if any(kw in desc for kw in critical_keywords):
                critical_ports.append(port)
                matched = [kw for kw in critical_keywords if kw in desc]
                print(f"  \033[1;37m{port}\033[0m: \033[1;31mCRITICAL\033[0m ({matched})")
            else:
                normal_ports.append(port)
        
        if critical_ports:
            print(f"\n\033[1;31m[CRITICAL]\033[0m Labeled infrastructure: {critical_ports}")
            config_lines = [build_range_cmd(critical_ports), "no shutdown"]
            
            if has_force:
                confirm = 'y'
            else:
                confirm = input(f"\n[CONFIRM] no shutdown on {critical_ports}? (y/n): ")
            
            if confirm.lower() == 'y':
                result = netmiko_execute("\\n".join(config_lines), is_config=True)
                print(f"[RESULT]\n{result}")
                for port in critical_ports:
                    write_maintenance_whitelist(port, "access", expire_ts)
                    mark_verified(port)
                    print(f"\033[1;32m[WHITELIST]\033[0m {port} | \033[1;31mCRITICAL\033[0m | \033[1;36mVERIFIED\033[0m")

        if already_up:
            print(f"\n[MAINTENANCE] Ports already UP: {already_up}")
            for port in already_up:
                write_maintenance_whitelist(port, "access", expire_ts)
                mark_verified(port)
                print(f"[WHITELIST] {port} | VERIFIED (already UP)")

        if normal_ports:
            ports_skip_802x = []
            ports_need_802x = []
            for port in normal_ports:
                if port in ports_with_802x:
                    print(f"  \033[1;37m{port}\033[0m: \033[1;32m802.1X already configured.\033[0m")
                    ports_skip_802x.append(port)
                else:
                    print(f"  \033[1;37m{port}\033[0m: \033[1;33mNo 802.1X found.\033[0m")
                    ports_need_802x.append(port)
            
            config_lines = []

            if ports_skip_802x:
                config_lines.append(build_range_cmd(ports_skip_802x))
                config_lines.append("no shutdown")
            if ports_need_802x:
                config_lines.append(build_range_cmd(ports_need_802x))
                config_lines.extend(ACCESS_PORT_HARDENING)
            print(f"\n[CONFIG PREVIEW] ({len(config_lines)} total commands)")
            for line in config_lines[:8]:
                print(f"    {line}")
            if len(config_lines) > 8:
                print(f"    ...")
            if has_force:
                confirm = 'y'
            else:
                confirm = input(f"\n[CONFIRM] Apply config on {normal_ports}? (y/n): ")

            if confirm.lower() == 'y':
                result = netmiko_execute("\\n".join(config_lines), is_config=True)
                print(f"[RESULT]\n{result}")
                for port in normal_ports:
                    write_maintenance_whitelist(port, "access", expire_ts)
                    print(f"[WHITELIST] {port} | access | expire={expire_ts if expire_ts else 'auditor-scan'}")
                print(f"\n[802.1X] Auditor will monitor AUTHMGR-5-SUCCESS.")
            else:
                print("[CANCELLED]")

    if trunk_ports:
        print(f"\n--- TRUNK PORTS ({len(trunk_ports)}) ---")
        trunk_identities = {}
        for port in trunk_ports:
            device_name = input(f"[?] Expected device name on {port} (e.g. R1, SW2): ").strip()
            if not device_name:
                print(f"[!] No device name provided. Skipping {port}.")
                trunk_ports.remove(port)
                continue
            trunk_identities[port] = device_name
        
        config_lines = []

        for port in trunk_ports:
            config_lines.append(f"interface {port}")
            config_lines.extend(TRUNK_PORT_HARDENING)
        
        if has_force:
            confirm = 'y'
            print("[FORCE] Auto-confirming.")
        else:
            confirm = input(f"\n[CONFIRM] Push CDP hardening + no shutdown on {trunk_ports}? (y/n): ")
        
        if confirm.lower() == 'y':
            cmd_str = "\\n".join(config_lines)
            result = netmiko_execute(cmd_str, is_config=True)
            print(f"[RESULT]\n{result}")
            print(f"\n[CDP] Waiting for port(s) to come UP...")
            for port in trunk_ports:
                if expire_ts > 0:
                    max_wait = int(expire_ts - time.time())
                    print(f"\n[CDP] Maintenance timer active. Polling up to {max_wait//60}min for {port}.")
                else:
                    max_wait = 60
                    print(f"\n[CDP] No timer. Polling up to 60s for {port}.")

                poll_interval = 5
                port_up = False
                elapsed = 0
                
                while elapsed < max_wait:
                    with LoadingSpinner(f"Waiting for {port} to come UP ({elapsed}s/{max_wait}s)"):
                        time.sleep(poll_interval)
                    elapsed += poll_interval
        
                    status_out = netmiko_execute(f"show interfaces {port} status", is_config=False)
                    if "connected" in status_out.lower():
                        port_up = True
                        print(f"\n[CDP] {port} is UP! Waiting 7s for CDP discovery...")
                        break
                    elif "notconnect" in status_out.lower() and elapsed % 30 == 0:
                        print(f"  {port} still notconnect... ({elapsed}s)")
                
                if not port_up:
                    print(f"\n[CDP] {port} did not come UP within {max_wait}s.")
                    write_maintenance_whitelist(port, "trunk", expire_ts, trunk_identities.get(port, ""))
                    print(f"[WHITELIST] {port} added. Auditor will monitor.")
                    continue
                
                time.sleep(7)
                
                expected = trunk_identities.get(port, "")
                found, actual_name = verify_trunk_cdp_identity(port, expected)
            
                if found:
                    print(f"\033[1;32m[CDP] [SUCCESS]\033[0m {port} — '\033[1;36m{actual_name}\033[0m' matches expected '{expected}'")
                    write_maintenance_whitelist(port, "trunk", expire_ts, trunk_identities.get(port, ""))
                    mark_verified(port)
                elif actual_name:
                    print(f"\033[1;31m[CDP] [FAIL]\033[0m {port} — Expected '{expected}' but found '\033[1;31m{actual_name}\033[0m'!")
                    print(f"[Reason] Device name mismatch. Possible rogue device or wrong port.")
                    shut_result = netmiko_execute(f"interface {port}\\nshutdown", is_config=True)
                    print(f"[SECURITY] {port} SHUTDOWN — Identity mismatch.")
                else:
                    print(f"[CDP] [FAIL] {port} — No CDP neighbor found!")
                    shut_result = netmiko_execute(f"interface {port}\\nshutdown", is_config=True)
                    print(f"[SECURITY] {port} SHUTDOWN — No identity.")
        else:
            print("[CANCELLED]")
            return
    
    print(f"\n{'='*50}")
    print(f"  PORT OPEN WORKFLOW COMPLETE")
    print(f"{'='*50}")

def vlan_migration_workflow(ports, target_vlan, has_force=False, remove_vlans=None):
    print(f"\n\033[1;35m{'='*50}\033[0m")
    print(f"  \033[1;35mVLAN MIGRATION → VLAN {target_vlan}\033[0m")
    print(f"\033[1;35m{'='*50}\033[0m")
    
    run_out = netmiko_execute(
        "show run | include ^interface|description|switchport mode trunk|spanning-tree portfast",
        is_config=False
    )
    
    port_desc = {}
    trunk_ports = set()
    portfast_ports = set()
    current_intf = None
    
    for line in run_out.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface "):
            raw = stripped.split("interface ")[1].strip()
            current_intf = raw.replace("FastEthernet", "Fa").replace("GigabitEthernet", "Gi").replace("TenGigabitEthernet", "Te")
            port_desc[current_intf] = ""
        elif stripped.startswith("description ") and current_intf:
            port_desc[current_intf] = stripped.split("description ", 1)[1].lower()
        elif "switchport mode trunk" in stripped and current_intf:
            trunk_ports.add(current_intf)
        elif "spanning-tree portfast" in stripped and current_intf:
            portfast_ports.add(current_intf)
    
    critical_ports = []
    trunk_blocked = []
    no_portfast = []
    safe_ports = []
    critical_keywords = ["server", "printer", "camera", "voip", "phone", "iot", "critical", "infra"]
    
    for port in ports:
        if port in trunk_ports:
            trunk_blocked.append(port)
            print(f"  \033[1;37m{port}\033[0m: \033[1;31mTRUNK - BLOCKED\033[0m")
            continue
        
        desc = port_desc.get(port, "")
        if any(kw in desc for kw in critical_keywords):
            critical_ports.append(port)
            print(f"  \033[1;37m{port}\033[0m: \033[1;31mCRITICAL - WARNING\033[0m")
        elif port not in portfast_ports:
            no_portfast.append(port)
            print(f"  \033[1;37m{port}\033[0m: \033[1;33mNO PORTFAST - CAUTION\033[0m (not confirmed edge port)")
        else:
            safe_ports.append(port)
            print(f"  \033[1;37m{port}\033[0m: \033[1;32mSAFE\033[0m")
    
    if trunk_blocked:
        print("\033[1;41m[!] WARNING: TRUNK PORTS DETECTED!\033[0m")
        print(f"\033[1;31m[BLOCKED]\033[0m \033[1;37mTrunk ports cannot be migrated:\033[0m \033[1;31m{trunk_blocked}\033[0m")
    
    if critical_ports:
        print(f"\n\033[1;41m[CRITICAL BLOCK]\033[0m Server/critical ports cannot be migrated: {critical_ports}")
        print("\033[1;31m[!]\033[0m VLAN migration on critical ports requires manual CLI. BLOCKED regardless of --force.")
    
    if no_portfast:
        print(f"\033[1;33m[CAUTION]\033[0m \033[1;37mPorts without portfast (not confirmed edge):\033[0m \033[1;33m{no_portfast}\033[0m")
        print("\033[1;36m[INFO]\033[0m \033[3mThese may be uplinks or unconfigured ports. Risky to migrate.\033[0m")
        if has_force:
            print(f"\033[1;35m[FORCE]\033[0m Including no-portfast ports.")
            safe_ports.extend(no_portfast)
        else:
            confirm = input(f"[?] Use VERIFIED to include, or skip? (v=include with VERIFIED, s=skip): ")
            if confirm.lower() == 'v':
                verify = input(f"Type 'VERIFIED' to confirm these are safe: ")
                if verify == "VERIFIED":
                    safe_ports.extend(no_portfast)
                    print(f"\033[1;32m[VERIFIED]\033[0m Including no-portfast ports.")
                else:
                    print(f"\033[1;33m[SKIP]\033[0m Excluding no-portfast ports.")
    
    if not safe_ports:
        print(f"\033[1;31m[ABORT]\033[0m No safe ports.")
        return
    
    config_lines = [
        build_range_cmd(safe_ports),
        "switchport mode access",
        f"switchport access vlan {target_vlan}"
    ]
    
    orphan_warnings = []
    if remove_vlans:
        vlan_out = netmiko_execute("show vlan brief", is_config=False)
        
        for vlan_to_remove in remove_vlans:
            ports_in_vlan = []
            in_block = False
            for line in vlan_out.splitlines():
                m = re.match(r'^(\d+)\s+\S+\s+\S+\s+(.*)', line)
                if m:
                    in_block = (m.group(1) == str(vlan_to_remove))
                    if in_block:
                        ports_in_vlan.extend([p.strip().rstrip(',') for p in m.group(2).split(",") if p.strip()])
                elif in_block and line.startswith("                "):
                    ports_in_vlan.extend([p.strip().rstrip(',') for p in line.split(",") if p.strip()])
                elif re.match(r'^\d+', line.strip()):
                    in_block = False
            
            ports_in_vlan = [p.replace("FastEthernet", "Fa").replace("GigabitEthernet", "Gi") for p in ports_in_vlan]
            ports_in_vlan = [p for p in ports_in_vlan if re.match(r'^(Fa|Gi|Te|Et)\d+/\d+', p)]
            orphans = [p for p in ports_in_vlan if p not in safe_ports]
            
            if orphans:
                orphan_warnings.append((vlan_to_remove, orphans))
                print(f"\n\033[1;41m[ORPHAN WARNING]\033[0m \033[1;31mVLAN {vlan_to_remove} still has {len(orphans)} ports not migrated:\033[0m")                
                print(f"  {orphans}")
                print(f"  → If you remove VLAN {vlan_to_remove}, these ports will be ORPHANED!")
        
        if orphan_warnings and not has_force:
            print(f"\n\033[1;31m[!]\033[0m \033[1;33mRemoving VLANs with active ports will orphan them.\033[0m")
            choice = input(f"[?] (a)bort | (s)kip VLAN removal | (f)orce remove anyway: ").lower()
            if choice == 'a':
                print("\033[1;31m[CANCELLED]\033[0m")
                return
            elif choice == 's':
                remove_vlans = []
                print("\033[1;36m[INFO]\033[0m Skipping VLAN removal. Migration only.")
            elif choice == 'f':
                print(f"\033[1;35m[FORCE]\033[0m Will auto-migrate orphans to VLAN 1 default before removing VLANs.")
                config_lines.insert(0, build_range_cmd(orphans))
                config_lines.insert(1, "switchport access vlan 1")
    
    if remove_vlans:
        for v in remove_vlans:
            config_lines.append(f"no vlan {v}")
    
    print(f"\n\033[1;36m[CONFIG PREVIEW]\033[0m")
    for line in config_lines:
        print(f"    {line}")
    
    if has_force:
        confirm = 'y'
    else:
        confirm = input(f"\n[CONFIRM] Apply? (y/n): ")
    
    if confirm.lower() == 'y':
        result = netmiko_execute("\\n".join(config_lines), is_config=True)
        print(f"\033[1;37m[RESULT]\033[0m\n{result}")
        print(f"\033[1;32m[MIGRATION COMPLETE]\033[0m \033[1;37m{len(safe_ports)} ports → VLAN {target_vlan}\033[0m")
        if remove_vlans:
            print(f"\033[1;33m[VLAN REMOVED]\033[0m \033[1;37m{remove_vlans}\033[0m")
    else:
        print("\033[1;31m[CANCELLED]\033[0m")

def vlan_move_all_workflow(source_vlan, target_vlan, has_force=False):
    """
    Move all ports from VLAN X to VLAN Y.
    Discover ports from 'show vlan brief' at runtime.
    """
    print(f"\n\033[1;35m{'='*50}\033[0m")
    print(f"  \033[1;35mVLAN MIGRATION: {source_vlan} → {target_vlan}\033[0m")
    print(f"\033[1;35m{'='*50}\033[0m")
    
    vlan_out = netmiko_execute("show vlan brief", is_config=False)
    
    source_ports = []
    in_source_block = False

    for line in vlan_out.splitlines():
        m = re.match(r'^(\d+)\s+\S+\s+\S+\s+(.*)', line)
        if m:
            vlan_id = m.group(1)
            ports_str = m.group(2)
            in_source_block = (vlan_id == str(source_vlan))
            if in_source_block:
                source_ports.extend([p.strip().rstrip(',') for p in ports_str.split(",") if p.strip()])
        elif in_source_block and line.startswith("                "):
            source_ports.extend([p.strip().rstrip(',') for p in line.split(",") if p.strip()])
        elif line.strip() == "" or re.match(r'^\d+', line.strip()):
            in_source_block = False
    
    source_ports = [p.replace("FastEthernet", "Fa").replace("GigabitEthernet", "Gi").replace("TenGigabitEthernet", "Te") for p in source_ports]
    source_ports = [p for p in source_ports if re.match(r'^(Fa|Gi|Te|Et)\d+/\d+', p)]
    
    if not source_ports:
        print(f"\033[1;31m[ABORT]\033[0m No ports found in VLAN {source_vlan}.")
        return
    print(f"\n\033[1;36m[DISCOVERED]\033[0m {len(source_ports)} ports in VLAN {source_vlan}: {source_ports}")

    vlan_migration_workflow(source_ports, target_vlan, has_force=has_force)


def pre_filter_ports(step_config, exclude_ports):
    """Remove globally-skipped ports from a step's config before audit.
    Returns modified config or None if all ports excluded."""
    if not exclude_ports:
        return step_config
    
    target_ports = []
    for line in step_config:
        if line.lower().startswith(("interface range ", "interface ")):
            port_part = line.split("interface", 1)[1].replace("range", "").strip()
            for chunk in port_part.split(","):
                m = re.match(r'(fa|gi|te|et)\s*(\d+/\d+)(?:\s*-\s*(\d+))?', chunk.strip(), re.IGNORECASE)
                if m:
                    prefix = m.group(1).capitalize()
                    slot, start = m.group(2).rsplit("/", 1)
                    end = m.group(3) if m.group(3) else start
                    for p in range(int(start), int(end)+1):
                        target_ports.append(f"{prefix}{slot}/{p}")
    
    remaining = [p for p in target_ports if p not in exclude_ports]
    
    if not remaining:
        return None
    
    if len(remaining) == len(target_ports):
        return step_config  
    
    new_config = []
    interface_replaced = False
    for line in step_config:
        if not interface_replaced and line.lower().startswith(("interface range ", "interface ")):
            new_config.append(build_range_cmd(remaining))
            interface_replaced = True
        else:
            new_config.append(line)
    
    return new_config
 
 
def audit_step_ports(step_config, has_force=False):
    """Real-time audit + auto-filter unsafe ports per step.
    Returns: (filtered_config, skipped_ports_info) or (None, skipped) if all unsafe."""
    target_ports = []
    for line in step_config:
        if line.lower().startswith(("interface range ", "interface ")):
            port_part = line.split("interface", 1)[1].replace("range", "").strip()
            for chunk in port_part.split(","):
                m = re.match(r'(fa|gi|te|et)\s*(\d+/\d+)(?:\s*-\s*(\d+))?', chunk.strip(), re.IGNORECASE)
                if m:
                    prefix = m.group(1).capitalize()
                    slot, start = m.group(2).rsplit("/", 1)
                    end = m.group(3) if m.group(3) else start
                    for p in range(int(start), int(end)+1):
                        target_ports.append(f"{prefix}{slot}/{p}")
    
    if not target_ports:
        return step_config, []
    
    run_out = netmiko_execute(
        "show run | include ^interface|description|switchport mode trunk|spanning-tree portfast",
        is_config=False
    )
    
    port_desc = {}
    trunk_ports = set()
    portfast_ports = set()
    current_intf = None
    
    for line in run_out.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface "):
            raw = stripped.split("interface ")[1].strip()
            current_intf = raw.replace("FastEthernet", "Fa").replace("GigabitEthernet", "Gi").replace("TenGigabitEthernet", "Te")
            port_desc[current_intf] = ""
        elif stripped.startswith("description ") and current_intf:
            port_desc[current_intf] = stripped.split("description ", 1)[1].lower()
        elif "switchport mode trunk" in stripped and current_intf:
            trunk_ports.add(current_intf)
        elif "spanning-tree portfast" in stripped and current_intf:
            portfast_ports.add(current_intf)
    
    has_force_access = any("switchport mode access" in line.lower() for line in step_config)
    has_portfast = any("spanning-tree portfast" in line.lower() for line in step_config)
    has_vlan_change = any("switchport access vlan" in line.lower() for line in step_config)
    
    # These commands MUST NEVER be applied to trunk ports
    TRUNK_INCOMPATIBLE = [
        "switchport mode access", "spanning-tree portfast", "spanning-tree bpduguard",
        "switchport port-security", "ip verify source", "ip dhcp snooping limit",
        "authentication", "dot1x", "mab", "switchport access vlan",
        "ipv6 nd raguard", "ipv6 snooping", "storm-control"
    ]
    has_trunk_incompatible = any(
        any(kw in line.lower() for kw in TRUNK_INCOMPATIBLE)
        for line in step_config
        if not line.lower().startswith(("interface", "!"))
    )
    
    is_adding_portfast = has_portfast
    
    safe_ports = []
    skipped = []
    critical_keywords = ["server", "printer", "camera", "voip", "phone", "iot", "critical", "infra"]
    
    for port in target_ports:
        # ABSOLUTE RULE: trunk ports NEVER get access-layer security
        if port in trunk_ports and has_trunk_incompatible:
            skipped.append((port, "TRUNK"))
            continue
        
        desc = port_desc.get(port, "")
        if any(kw in desc for kw in critical_keywords):
            if not has_force:
                matched = [kw for kw in critical_keywords if kw in desc]
                skipped.append((port, f"CRITICAL ({','.join(matched)})"))
                continue

        # Check NO_PORTFAST only if VLAN change AND not step adding portfast
        if has_vlan_change and port not in portfast_ports and port not in trunk_ports:
            if not is_adding_portfast and not has_force: 
                skipped.append((port, "NO_PORTFAST"))
                continue
        
        safe_ports.append(port)
    
    if not safe_ports:
        return None, skipped
    
    new_config = []
    interface_replaced = False
    for line in step_config:
        if not interface_replaced and line.lower().startswith(("interface range ", "interface ")):
            new_config.append(build_range_cmd(safe_ports))
            interface_replaced = True
        else:
            new_config.append(line)
    
    return new_config, skipped


def count_ports_in_config(config):
    """Count actual ports affected by step."""
    count = 0
    for line in config:
        if line.lower().startswith(("interface range ", "interface ")):
            port_part = line.split("interface", 1)[1].replace("range", "").strip()
            for chunk in port_part.split(","):
                m = re.match(r'(fa|gi|te|et)\s*\d+/(\d+)(?:\s*-\s*(\d+))?', chunk.strip(), re.IGNORECASE)
                if m:
                    start = int(m.group(2))
                    end = int(m.group(3)) if m.group(3) else start
                    count += (end - start + 1)
    return count


def validate_orchestration_plan(steps):
    errors = []
    if not isinstance(steps, list) or not steps:
        return ["Plan must be a non-empty JSON array."]

    for index, step in enumerate(steps, start=1):
        label = f"Step {step.get('step', index) if isinstance(step, dict) else index}"
        if not isinstance(step, dict):
            errors.append(f"{label}: must be a JSON object.")
            continue

        ports = step.get("ports")
        config = step.get("config")

        if not isinstance(ports, list) or not ports:
            errors.append(f"{label}: missing non-empty ports array.")
        elif not all(isinstance(port, str) and port.strip() for port in ports):
            errors.append(f"{label}: ports must contain only non-empty strings.")

        if not isinstance(config, list) or not config:
            errors.append(f"{label}: missing non-empty config array.")
            continue

        if not all(isinstance(line, str) and line.strip() for line in config):
            errors.append(f"{label}: config must contain only non-empty strings.")
            continue

        first_line = config[0].strip().lower()
        if not first_line.startswith(("interface ", "interface range ")):
            errors.append(f"{label}: first config command must be interface/interface range.")

        if len(config) > 8:
            errors.append(f"{label}: config has {len(config)} commands; maximum is 8.")

        if any("execute:" in line.lower() for line in config):
            errors.append(f"{label}: config must not include EXECUTE.")

        if any("spanning-tree portfast trunk" in line.lower() for line in config):
            errors.append(f"{label}: access workflows must not use spanning-tree portfast trunk.")

        if any("switchport security" in line.lower() for line in config):
            errors.append(f"{label}: use switchport port-security, not switchport security.")

    return errors

def print_plan_validation_errors(errors):
    print("\033[1;31m[ERROR]\033[0m AI returned JSON, but the plan contract is invalid:")
    for err in errors[:10]:
        print(f"  - {err}")
    if len(errors) > 10:
        print(f"  - ... {len(errors) - 10} more errors")

def orchestrate_workflow(user_input, has_force=False):
    """
    Multi-step orchestration: AI plans → Python executes step-by-step with confirmation.
    Each step is atomic (1 config block). Failed step aborts remaining steps.
    """
    print(f"\n\033[1;35m{'='*50}\033[0m")
    print(f"  \033[1;35mMULTI-STEP ORCHESTRATION\033[0m")
    print(f"\033[1;35m{'='*50}\033[0m")
    
    plan_prompt = f"""You are a network configuration planner. Break this admin request into atomic steps. Each step should configure ONE feature on a specific set of ports.

Output ONLY a JSON array, no other text, no EXECUTE keyword. Format:
[
  {{"step": 1, "desc": "Brief description", "ports": ["<requested ports>"], "config": ["interface range <requested ports>", "switchport mode access", "switchport access vlan <requested vlan>"]}},
  {{"step": 2, "desc": "...", "ports": [...], "config": [...]}}
]

Rules:
- Each step's "config" list contains atomic CLI commands
- Each step MUST include non-empty "ports" and "config" arrays
- First config line MUST be "interface" or "interface range"
- Use ONLY ports and VLANs from ADMIN_REQUEST; do not copy placeholder/example values
- Use Cisco IOS syntax
- Maximum 8 commands per step

ADMIN_REQUEST: {user_input}"""

    print(f"\n\033[1;36m[PLAN]\033[0m Asking AI to break down request...")
    
    plan_response = ask_ai(
        plan_prompt,
        silent=True,
        spinner_text="MIMIR planner is building configuration plan..",
        model=AI_PLANNER_MODEL,
        use_history=False,
        record_history=False,
    )
    
    json_match = re.search(r'\[\s*\{.*\}\s*\]', plan_response, re.DOTALL)
    if not json_match:
        print("\033[1;31m[ERROR]\033[0m AI did not return valid JSON plan.")
        print(f"AI Response: \033[3m{plan_response[:500]}\033[0m")
        return
    
    try:
        steps = json.loads(json_match.group(0))
    except json.JSONDecodeError as e:
        print(f"\033[1;31m[ERROR]\033[0m JSON parse failed: {e}")
        print(f"Raw: {json_match.group(0)[:500]}")
        return
    
    if not steps or not isinstance(steps, list):
        print("\033[1;31m[ERROR]\033[0m Empty or invalid plan.")
        return

    plan_errors = validate_orchestration_plan(steps)
    if plan_errors:
        print_plan_validation_errors(plan_errors)
        print(f"AI Response: \033[3m{plan_response[:800]}\033[0m")
        return
    
    print(f"\n\033[1;36m[PLAN]\033[0m \033[1;37m{len(steps)} atomic steps generated:\033[0m")
    print(f"\033[1;30m{'-'*50}\033[0m")
    for s in steps:
        step_num = s.get('step', '?')
        desc = s.get('desc', 'No description')
        ports = s.get('ports', [])
        print(f"  Step {step_num}: {desc}")
        print(f"    Ports: {ports}")
        print(f"    Commands: {len(s.get('config', []))}")
    print(f"{'-'*50}")
    
    confirm = input(f"\n[CONFIRM] Review plan above. Execute all {len(steps)} steps? (y/n/preview/s=fix plan): ")
        
    if confirm.lower() == 'preview':
        for s in steps:
            print(f"\n--- Step {s['step']}: {s['desc']} ---")
            for line in s.get('config', []):
                print(f"    {line}")
        confirm = input(f"\n[CONFIRM] Proceed? (y/n/s=fix plan): ")
        
    if confirm.lower() == 's':
        print(f"\n\033[1;33m[FIX]\033[0m Choose edit mode:")
        print(f"  1. Simple edit (paste commands like 'preview' format)")
        print(f"  2. JSON edit (advanced)")
        mode = input("Choice (1/2): ").strip()
            
        if mode == '1':
            print(f"\n\033[1;34m[*]\033[0m Paste corrected plan in this format (END to finish):")
            print(f"--- Step 1: <description> ---")
            print(f"    interface range Fa0/12-24")
            print(f"    switchport mode access")
            print(f"--- Step 2: <description> ---")
            print(f"    ...")
                
            lines = []
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
                
            steps = parse_simple_plan(lines)
            if not steps:
                print("\033[1;31m[ERROR]\033[0m Could not parse plan.")
                return

            plan_errors = validate_orchestration_plan(steps)
            if plan_errors:
                print_plan_validation_errors(plan_errors)
                return
                
            print(f"\033[1;32m[V]\033[0m Plan updated: {len(steps)} steps")
            save_qa_dataset(plan_prompt, json.dumps(steps))
            print(f"\033[1;32m[+]\033[0m Saved to training dataset")
                
            confirm = input(f"\n[CONFIRM] Execute corrected plan? (y/n): ")
            if confirm.lower() != 'y':
                print("\033[1;31m[CANCELLED]\033[0m")
                return
            
        elif mode == '2':
            print(f"\n\033[1;34m[*]\033[0m Paste corrected JSON (END to finish):")
            
            lines = []
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
                
            corrected = "\n".join(lines)
                
            try:
                steps = json.loads(corrected)
                plan_errors = validate_orchestration_plan(steps)
                if plan_errors:
                    print_plan_validation_errors(plan_errors)
                    return
                print(f"\033[1;32m[V]\033[0m Plan updated: {len(steps)} steps")
                save_qa_dataset(plan_prompt, json.dumps(steps))
                print(f"\033[1;32m[+]\033[0m Saved to training dataset")
                    
                confirm = input(f"\n[CONFIRM] Execute corrected plan? (y/n): ")
                if confirm.lower() != 'y':
                    print("\033[1;31m[CANCELLED]\033[0m")
                    return
            except json.JSONDecodeError as e:
                print(f"\033[1;31m[ERROR]\033[0m Invalid JSON: {e}")
                return
            
        else:
            print("\033[1;31m[ERROR]\033[0m Invalid choice.")
            return
        
    elif confirm.lower() != 'y':
        print("\033[1;31m[CANCELLED]\033[0m")
        return
    
    BLAST_THRESHOLD = 10
    completed_steps = []
    globally_skipped_ports = set()  
    security_was_removed = False     
    
    for s in steps:
        step_num = s.get('step', '?')
        desc = s.get('desc', '')
        config = s.get('config', [])
        ports = s.get('ports', [])
        
        if not config:
            print(f"\n\033[1;33m[SKIP]\033[0m Step {step_num}: empty config")
            continue
        
        print(f"\n\033[1;34m{'='*50}\033[0m")
        print(f"  \033[1;34mEXECUTING STEP {step_num}:\033[0m {desc}")
        print(f"\033[1;34m{'='*50}\033[0m")
        print(f"  \033[1;37mOriginal ports:\033[0m {ports}")
        print(f"  \033[1;36m[AUDIT]\033[0m Real-time switch state check...")
        
        has_interface_line = any(
            line.lower().startswith(("interface range ", "interface "))
            for line in config
        )
        if not has_interface_line and ports:
            expanded = []
            for p in ports:
                m = re.match(r'(Fa|Gi|Te)(\d+/\d+)(?:-(\d+))?', p, re.IGNORECASE)
                if m:
                    prefix = m.group(1)[:2].capitalize()
                    slot_start = m.group(2)
                    end = m.group(3)
                    if end:
                        slot = slot_start.rsplit("/", 1)[0]
                        start_num = int(slot_start.rsplit("/", 1)[1])
                        for i in range(start_num, int(end)+1):
                            expanded.append(f"{prefix}{slot}/{i}")
                    else:
                        expanded.append(f"{prefix}{slot_start}")
            if expanded:
                config = [build_range_cmd(expanded)] + config
        
        if globally_skipped_ports:
            pre_filtered_config = pre_filter_ports(config, globally_skipped_ports)
            if pre_filtered_config is None:
                print(f"\n  \033[1;31m[SKIP]\033[0m All ports already filtered in previous steps.")
                continue
        else:
            pre_filtered_config = config
        
        filtered_config, skipped = audit_step_ports(pre_filtered_config, has_force=has_force)
        
        for port, reason in skipped:
            if reason == "TRUNK" or reason.startswith("CRITICAL"):
                globally_skipped_ports.add(port)
        
        if skipped:
            print(f"\n  \033[1;33m[FILTER]\033[0m \033[1;37mAuto-skipped {len(skipped)} unsafe ports:\033[0m")
            for port, reason in skipped:
                print(f"    {port}: {reason}")
        
        if filtered_config is None:
            print(f"\n  \033[1;31m[SKIP]\033[0m \033[1;33mAll ports unsafe. Step {step_num} skipped entirely.\033[0m")
            continue
        
        # Tier 1: CRITICAL — BLOCKED even with --force (network integrity)
        CRITICAL_REMOVAL_PATTERNS = {
            "no ipv6 nd raguard": "RA Guard — ONLY IPv6 Rogue RA protection on 2960 (DHCPv6 Guard not supported by ASIC)",
            "no ipv6 snooping": "IPv6 Snooping — prerequisite for ALL IPv6 First-Hop Security",
            "no dot1x": "802.1X — primary network access control",
            "no authentication": "Authentication framework — disables all AAA on port",
        }
        
        # Tier 2: WARNING — removable with confirmation
        SECURITY_REMOVAL_PATTERNS = {
            "no switchport port-security": "Port Security (MAC-based access control)",
            "no ip verify source": "IP Source Guard (IP spoofing prevention)",
            "no ip dhcp snooping": "DHCP Snooping (rogue DHCP prevention)",
            "no storm-control": "Storm Control (broadcast/multicast flood prevention)",
            "no spanning-tree bpduguard": "BPDU Guard (STP attack protection)",
        }
        
        # Check CRITICAL first
        critical_blocked = []
        for line in filtered_config:
            for pattern, feature_name in CRITICAL_REMOVAL_PATTERNS.items():
                if pattern in line.lower():
                    critical_blocked.append(feature_name)
        
        critical_blocked = list(dict.fromkeys(critical_blocked))
        
        if critical_blocked:
            print(f"\n  \033[1;41m[CRITICAL BLOCK]\033[0m \033[1;31mStep {step_num} attempts to remove CRITICAL security:\033[0m")
            for feat in critical_blocked:
                print(f"    \033[1;31m✗ {feat}\033[0m")
            print(f"  \033[1;31m[!] --force CANNOT override critical security features.\033[0m")
            print(f"  \033[1;31m[!] Manual CLI required to remove these protections.\033[0m")
            continue
        
        # Check WARNING tier
        removed_features = []
        for line in filtered_config:
            for pattern, feature_name in SECURITY_REMOVAL_PATTERNS.items():
                if pattern in line.lower():
                    removed_features.append(feature_name)
        
        # Deduplicate (storm-control may appear multiple times)
        removed_features = list(dict.fromkeys(removed_features))
        
        if removed_features and not has_force:
            print(f"\n  \033[1;41m[SECURITY WARNING]\033[0m \033[1;31mStep {step_num} REMOVES security features:\033[0m")
            for feat in removed_features:
                print(f"    \033[1;31m✗\033[0m {feat}")
            print(f"  \033[1;33m[INFO]\033[0m Removing these features reduces port protection.")
            print(f"  \033[1;33m[INFO]\033[0m Re-issue with --force if intentional.")
            sec_confirm = input(f"  [?] Remove {len(removed_features)} security feature(s)? (y/n): ")
            if sec_confirm.lower() != 'y':
                print(f"\033[1;31m[BLOCKED]\033[0m Step {step_num} cancelled — security features preserved.")
                continue
            security_was_removed = True  
        elif removed_features and has_force:
            security_was_removed = True 
        
        # === BLAST RADIUS CHECK ===
        port_count = count_ports_in_config(filtered_config)
        if port_count > BLAST_THRESHOLD and not has_force:
            print(f"\n  \033[1;41m[BLAST RADIUS WARNING]\033[0m \033[1;31mStep {step_num} affects {port_count} ports (>{BLAST_THRESHOLD})\033[0m")
            print(f"  \033[1;36m[INFO]\033[0m Large-scale changes can cause widespread disruption.")
            blast_confirm = input(f"  [?] Confirm large-scale operation? (y/n/skip): ")
            if blast_confirm.lower() == 'skip':
                print(f"\033[1;33m[SKIPPED]\033[0m Step {step_num}")
                continue
            if blast_confirm.lower() != 'y':
                print(f"\033[1;31m[ABORTED]\033[0m")
                return
        
        print(f"\n  \033[1;36m[FILTERED CONFIG]\033[0m ({len(filtered_config)} commands, {port_count} ports)")
        for line in filtered_config[:10]:
            print(f"    {line}")
        if len(filtered_config) > 10:
            print(f"    ... +{len(filtered_config)-8} more")
        
        # Per-step confirmation (skip if --force)
        if not has_force:
            step_confirm = input(f"\n[?] Apply Step {step_num}? (y=yes / s=skip this step / a=abort all): ")
            if step_confirm.lower() == 'a':
                print(f"\n\033[1;31m[ABORTED]\033[0m Stopping at step {step_num}.")
                print(f"\033[1;36m[INFO]\033[0m Completed: {completed_steps}")
                return
            elif step_confirm.lower() == 's':
                print(f"\033[1;33m[SKIPPED]\033[0m Step {step_num} skipped.")
                continue
            elif step_confirm.lower() != 'y':
                print(f"\033[1;31m[CANCELLED]\033[0m User declined.")
                return
        else:
            print(f"\n\033[1;35m[FORCE]\033[0m Auto-applying Step {step_num}...")
        print(f"  \033[1;36m[PRE-EXEC]\033[0m Re-verifying switch state...")
        recheck_config, recheck_skipped = audit_step_ports(pre_filtered_config, has_force=has_force)
        
        if [p for p, _ in recheck_skipped] != [p for p, _ in skipped]:
            print(f"  \033[1;41m[DRIFT DETECTED]\033[0m \033[1;31mSwitch state changed since audit!\033[0m")
            print(f"  \033[1;31m[DRIFT]\033[0m Original skip: {[p for p, _ in skipped]}")
            print(f"  \033[1;31m[DRIFT]\033[0m Current skip:  {[p for p, _ in recheck_skipped]}")
            
            if not has_force:
                drift_choice = input(f"  [?] State changed. (y=use new state / a=abort): ")
                if drift_choice.lower() != 'y':
                    print(f"\033[1;31m[ABORTED]\033[0m State drift detected.")
                    return
            
            filtered_config = recheck_config
            if filtered_config is None:
                print(f"  \033[1;33m[SKIP]\033[0m All ports unsafe after drift. Skipping step.")
                continue
        
        cmd_str = "\\n".join(filtered_config)
        with LoadingSpinner(f"Step {step_num}: executing {len(filtered_config)} commands"):
            result = netmiko_execute(cmd_str, is_config=True)
        
        if "EXECUTION_ERROR" in result:
            print(f"\n\033[1;41m[ERROR]\033[0m \033[1;31mStep {step_num} FAILED!\033[0m")
            print(f"  {result[:300]}")
            
            if not has_force:
                err_choice = input(f"\n[?] Continue to next step? (y/n): ")
                if err_choice.lower() != 'y':
                    print(f"\033[1;31m[ABORTED]\033[0m Stopping due to error.")
                    return
        else:
            print(f"\n\033[1;32m[V] Step {step_num} COMPLETED\033[0m ({port_count} ports)")
            completed_steps.append(step_num)
    
    print(f"\n\033[1;35m{'='*50}\033[0m")
    print(f"  \033[1;35mORCHESTRATION COMPLETE\033[0m")
    print(f"\033[1;35m{'='*50}\033[0m")
    print(f"  Total steps:     {len(steps)}")
    print(f"  Completed:       {len(completed_steps)}")
    print(f"  Steps applied:   {completed_steps}")
    print(f"{'='*50}")

def parse_simple_plan(lines):
    """Parse human-readable plan format. Supports multiple step header formats:
    - "--- Step 1: desc ---"
    - "Step 1: desc"
    - "1. desc"
    - "Step 1"
    """
    steps = []
    current_step = None
    
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
    
        m = (re.match(r'-{2,}\s*Step\s+(\d+)[:\s]*(.+?)?\s*-{2,}', stripped, re.IGNORECASE) or
             re.match(r'Step\s+(\d+)[:\s]*(.+)?', stripped, re.IGNORECASE) or
             re.match(r'(\d+)[\.\)]\s*(.+)', stripped))
        
        if m:
            if current_step:
                steps.append(current_step)
            desc = (m.group(2) or "").strip().rstrip('-').strip()
            current_step = {
                "step": int(m.group(1)),
                "desc": desc if desc else f"Step {m.group(1)}",
                "ports": [],
                "config": []
            }
        elif current_step:
            cmd = stripped
            current_step["config"].append(cmd)
            if cmd.lower().startswith(("interface range ", "interface ")):
                port_part = cmd.split("interface", 1)[1].replace("range", "").strip()
                current_step["ports"] = [p.strip() for p in port_part.split(",")]
    
    if current_step:
        steps.append(current_step)
    
    return steps

def is_complex_orchestration_request(user_input):
    text = user_input.lower()
    if any(word in text for word in ["show", "check", "ping", "traceroute", "mismatch", "error", "issue"]):
        return False

    feature_categories = {
        "dot1x": ["802.1x", "dot1x", "mab"], # Gom chung 1 nhóm Auth
        "storm": ["storm-control", "storm control"],
        "ipv6": ["ipv6", "raguard"],
        "dhcp": ["dhcp snooping", "ip verify"],
        "stp": ["bpduguard", "portfast"],
        "port_sec": ["port-security", "isolate", "protected"],
        "cdp": ["cdp"]
    }
    
    found_categories = set()
    for category, keywords in feature_categories.items():
        for kw in keywords:
            if re.search(rf'(?<!no\s){re.escape(kw)}', text):
                found_categories.add(category)
                break
    
    major_count = len(found_categories)
    
    params = ["maximum", "sticky", "violation", "restrict", "timer", "inactivity", "protect"]
    total_keywords = major_count + sum(1 for p in params if p in text)

    port_pattern = r'(?:fa|gi|te|et)\d+/\d+(?:\s*(?:-|\bto\b)\s*(?:(?:fa|gi|te|et)\d+/)?\d+)?'
    unique_groups = set(re.findall(port_pattern, text))
    group_count = len(unique_groups)

    return major_count >= 3 or (group_count >= 2 and major_count >= 1) or total_keywords >= 12
 

def is_open_port_request(user_input):
    """Detect if admin wants to open/no shut ports"""
    open_keywords = ["open", "no shut", "no shutdown", "enable port", "bring up", "activate"]
    return any(kw in user_input.lower() for kw in open_keywords)


def is_information_request(user_input):
    """Detect concept/CCNA-style questions that should not execute switch commands."""
    text = user_input.lower().strip()

    info_patterns = [
        r"\bwhat\s+(?:is|are)\b",
        r"\bexplain\b",
        r"\bdescribe\b",
        r"\btell me about\b",
        r"\bprovide\s+(?:me\s+)?(?:information|info)\b",
        r"\binformation about\b",
        r"\bhow does\b",
        r"\bwhy\s+(?:does|is|are)\b",
        r"\bdifference between\b",
    ]

    if not any(re.search(pattern, text) for pattern in info_patterns):
        return False

    operational_patterns = [
        r"\bshow\b",
        r"\bcheck\b",
        r"\bverify\b",
        r"\bstatus\b",
        r"\bcounters?\b",
        r"\bbinding\b",
        r"\blease\b",
        r"\blog(?:s|ging)?\b",
        r"\brunning-config\b",
        r"\bconfigured\b",
        r"\bconfiguration\b",
        r"\bcurrent\b",
        r"\bon\s+(?:vlan|interface|fa|gi|te|et)\b",
        r"\bvlan\s+\d+\b",
        r"\b(?:fa|gi|te|et)\d+/\d+\b",
        r"\bconfigure\b",
        r"\bconfig\b",
        r"\benable\b",
        r"\bdisable\b",
        r"\bremove\b",
        r"\bshutdown\b",
        r"\bshut\b",
        r"\bopen\b",
        r"\bapply\b",
        r"\bset\b",
        r"\bexecute\b",
        r"\brun\b",
    ]

    return not any(re.search(pattern, text) for pattern in operational_patterns)

def local_information_answer(user_input):
    """Fallback explanations for safety concepts when the model tries to execute."""
    text = user_input.lower()

    if "ipsg" in text or "ip source guard" in text or "ip verify source" in text:
        return (
            "Sure Admin! IPSG (IP Source Guard) is an access-layer protection feature "
            "that blocks IP traffic when the source IP/MAC does not match a trusted "
            "binding for that switch port.\n\n"
            "On a Cisco Catalyst 2960, IPSG normally depends on DHCP Snooping bindings "
            "or static IP source bindings. After it is enabled on an untrusted Layer 2 "
            "access port, DHCP traffic is still allowed, but normal IP traffic is only "
            "allowed when the source matches the binding table.\n\n"
            "The IOS feature is configured with commands such as ip verify source, but "
            "I will not query or configure the switch unless you explicitly ask me to "
            "show, check, verify, or configure it."
        )

    return None

def sanitize_information_response(ai_response, user_input):
    """Remove accidental EXECUTE blocks from informational answers."""
    if "execute:" in ai_response.lower():
        fallback = local_information_answer(user_input)
        if fallback:
            return fallback

    clean_lines = []
    for line in ai_response.replace("\\n", "\n").splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if "execute:" in lower:
            break
        if re.search(r"\b(let me|i can|i will).*(command|show|check|verify|run|bring up)", lower):
            continue
        if re.search(r"\bdo you want me to\b.*\b(configure|configured|show|check|verify|run)\b", lower):
            continue
        clean_lines.append(line)

    cleaned = "\n".join(clean_lines).strip()
    return cleaned or local_information_answer(user_input) or (
        "Sure Admin. This is an informational question, so I will answer it without "
        "running any switch command."
    )
 
# --- MAIN ---
def get_gradient_color(step, total_steps, start_rgb, end_rgb):
    r = int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * (step / max(1, total_steps)))
    g = int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * (step / max(1, total_steps)))
    b = int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * (step / max(1, total_steps)))
    return f"\033[38;2;{r};{g};{b}m"

def print_mimir_banner():
    print("\033[1;36m" + "—" * 120 + "\033[0m")
    mimir_logo = """
                     ██████   ██████ █████ ██████   ██████ █████ ███████████   
                      ██████ ██████ ▒▒███ ▒▒██████ ██████ ▒▒███ ▒▒███▒▒▒▒▒███  
                      ███▒█████▒███  ▒███  ▒███▒█████▒███  ▒███  ▒███    ▒███  
                      ███▒▒███ ▒███  ▒███  ▒███▒▒███ ▒███  ▒███  ▒██████████   
                      ███ ▒▒▒  ▒███  ▒███  ▒███ ▒▒▒  ▒███  ▒███  ▒███▒▒▒▒▒███  
                      ███      ▒███  ▒███  ▒███      ▒███  ▒███  ▒███    ▒███  
                     █████     █████ █████ █████     █████ █████ █████   █████ Cisco Assistant
                    ▒▒▒▒▒     ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒     ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒  
    """
    lines = mimir_logo.strip("\n").split("\n")
    max_width = max(len(line) for line in lines) if lines else 1
    
    start_color = (0, 255, 255)  
    end_color = (0, 0, 139)      
    
    for line in lines:
        for i, char in enumerate(line):
            color_code = get_gradient_color(i, max_width, start_color, end_color)
            if "Cisco Assistant" in line and i >= line.find("Cisco Assistant"):
                color_code += "\033[3m"
            sys.stdout.write(color_code + char)
        sys.stdout.write("\033[0m\n")
    sys.stdout.flush()

    print("\033[1;37m" + "—" * 120 + "\033[0m")
    print("\033[1;36m                         MIMIR AI\033[0m | \033[1;37mNetwork Defense Control Plane\033[0m")
    print("\033[3m                   Status: Training Mode | Dataset: admin_dataset.json\033[0m")
    print("\033[1;37m" + "—" * 120 + "\033[0m\n")

def print_mini_tips():
    print("\033[1;30m[Tip: Use \033[1;33m--force\033[1;30m bypass | \033[1;36mVERIFIED\033[1;30m skip checks | \033[1;32m!save\033[1;30m write memory | \033[1;31mexit\033[1;30m to quit]\033[0m")

print_mimir_banner()
 
while not authenticated:
    try:
        print("\n\033[1;33m🛡️  Authentication required.\033[0m")
        username = input("\033[1;37mUsername: \033[0m")
        password = getpass.getpass("\033[1;37mPassword: \033[0m")
 
        if ADMIN_USERS.get(username) == password:
            authenticated = True
            print(f"\n\033[1;32m🔓 [OK] Welcome {username}.\033[0m Type '\033[1;31mexit\033[0m' to quit.\n")
        else:
            print("\033[1;31m🔒 [DENIED] Wrong credentials. Try again.\033[0m")
    except KeyboardInterrupt:
        print("\n👋 \033[1;30mGoodbye.\033[0m")
        exit()
 
while authenticated:
    try:
        is_manually_corrected = False

        print_mini_tips() 
        prompt = f"[\033[1;34m{username}\033[0m]\033[34m>>>\033[0m "
        user_input = input(prompt)
 
        if not user_input.strip():
            continue
 
        if user_input.lower() in ['exit', 'quit']:
            print("👋 \033[1;30mGoodbye.\033[0m")
            break

        if user_input.lower() == "!save":
            print("\n\033[1;32m[SYSTEM]\033[0m Saving configuration in NVRAM (write memory)...")
            try:
                save_result = netmiko_execute("write memory", is_config=False)
                print(f"\033[1;32m[OK] Configuration has been save!\033[0m\n{save_result}")
            except Exception as e:
                print(f"\033[1;31m[!] Error when saving configuration:\033[0m {e}")
            continue
 
        # --- DETECT FLAGS ---
        clean_input, has_force, has_verified = detect_flags(user_input)
        
        if has_force:
            print("\n\033[1;35m[FLAG]\033[0m \033[1;37m--force detected. Bypassing edge-port auto-audit; trunk/critical protection still enforced.\033[0m")
        if has_verified:
            print("\033[1;36m[FLAG]\033[0m \033[1;37mVERIFIED detected. Admin confirms prerequisites.\033[0m")
 
        # --- BUILD PROMPT WITH CONTEXT ---
        prompt_text = f"ADMIN_REQUEST: {clean_input}\nAuthenticated admin: {username}"
        
        requested_ports = extract_ports_from_input(clean_input)
        clean_lower = clean_input.lower()
        info_request = is_information_request(clean_input)

        if info_request:
            prompt_text += (
                "\nSYSTEM_HINT: This is an informational/concept question, not a request to query "
                "or configure the switch. Answer conversationally from networking knowledge. "
                "Do not use EXECUTE. If you mention IOS commands, describe them only as examples."
            )

        if requested_ports and is_open_port_request(clean_input):
            prompt_text += (
                "\nSYSTEM_HINT: Admin is requesting an INTERFACE enable/no-shutdown action, "
                "not a generic unsafe 'open command'. Return a Cisco IOS EXECUTE block using "
                f"interface {requested_ports[0]} and no shutdown. "
                "MIMIR will route no shutdown through the Secure Port Open Workflow for live "
                "validation, hardening, and final admin confirmation."
            )

        if has_force and requested_ports and re.search(r'\b(shutdown|shut)\b', clean_lower) and "no shut" not in clean_lower:
            prompt_text += (
                "\nSYSTEM_HINT: Admin requested an INTERFACE shutdown, not a system shutdown or reboot. "
                "--force bypasses edge-port audit only; it does NOT override MIMIR backend trunk/critical-port protection. "
                "Return an interface shutdown EXECUTE block for the requested port(s). "
                "MIMIR will run final trunk/critical checks and y/n confirmation before execution."
            )

        if ("ra guard" in clean_lower or "raguard" in clean_lower or re.search(r'\bra\b', clean_lower)) and "counter" in clean_lower:
            vlan_hint = re.search(r'\bvlan\s+(\d+)\b', clean_input, re.IGNORECASE)
            if vlan_hint:
                prompt_text += f"\nSYSTEM_HINT: For RA Guard VLAN counters, use exactly: EXECUTE: show ipv6 snooping counters vlan {vlan_hint.group(1)}"
            elif requested_ports:
                prompt_text += f"\nSYSTEM_HINT: For RA Guard interface counters, use exactly: EXECUTE: show ipv6 snooping counters interface {requested_ports[0]}"
            else:
                prompt_text += "\nSYSTEM_HINT: RA Guard hardware counters require a VLAN or interface. If neither VLAN nor interface is provided, ask the admin to specify one and do not use EXECUTE."

        if is_complex_orchestration_request(clean_input) and (has_verified or has_force):
            print(f"\n\033[1;35m[ORCHESTRATION]\033[0m Complex multi-config detected.")
            orchestrate_workflow(clean_input, has_force=has_force)
            continue
        elif is_complex_orchestration_request(clean_input):
            print(f"\n\033[1;33m[WARNING]\033[0m Complex multi-config detected. Use VERIFIED to confirm.")
            continue
        
        if has_verified and requested_ports:
            prompt_text += f"\nADMIN_VERIFICATION: Admin has explicitly verified that ports {', '.join(requested_ports)} meet all prerequisites (edge access mode, active DHCP binding, portfast enabled)."

        is_vlan_migration = bool(re.search(r'switchport\s+access\s+vlan\s+\d+', clean_input, re.IGNORECASE)) or \
                    bool(re.search(r'\b(?:move|migrate|transfer)\b.*vlan', clean_input, re.IGNORECASE))
        
        # --- AUTO-AUDIT (unless --force, VERIFIED, or VLAN migration) ---
        audit_context = ""
        if not has_force and not has_verified and not is_vlan_migration and requested_ports:
            config_keywords = ["config", "enable", "add", "set", "limit", "apply", "configure", 
                             "shutdown", "shut", "open", "remove", "disable"]
            is_config_request = any(kw in clean_input.lower() for kw in config_keywords)
            
            if is_config_request and should_trigger_audit(clean_input, ""):
                print("\n\033[1;33m[AUTO-AUDIT]\033[0m Risky config detected. Running edge-port verification...")
                audit_context = run_edge_port_audit(requested_ports)
                prompt_text += f"\n{audit_context}"
                is_port_security_request = (
                    "port-security" in clean_lower
                    or "port security" in clean_lower
                    or ("maximum" in clean_lower and "mac" in clean_lower)
                )
                if is_port_security_request and "NO PORTFAST" in audit_context and not has_verified:
                    prompt_text += (
                        "\nSYSTEM_HINT: For port-security, NO PORTFAST is CAUTION / not confirmed edge. "
                        "Do not claim the interface is invalid or not an access port unless audit says TRUNK/BLOCKED. "
                        "Tell admin to use VERIFIED after confirming the port is an unused edge access port, "
                        "and offer to check current status/running-config with EXECUTE show commands."
                    )
                if "SAFE" in audit_context and "BLOCKED" not in audit_context and re.search(r'\b(shutdown|shut)\b', clean_lower) and "no shut" not in clean_lower:
                    prompt_text += f"\nSYSTEM_HINT: The auto-audit has already verified {', '.join(requested_ports)} is SAFE for this requested shutdown. Start with this exact caution: WARNING: Shutdown will administratively disable the port until no shutdown is applied. Then return the Cisco IOS command using EXECUTE. Do not ask the admin to type YES or ask 'are you sure' in the AI response because MIMIR will show its own final y/n execution confirmation."

        # --- AI RESPONSE ---
        if info_request:
            ai_response = ask_ai(
                prompt_text,
                silent=True,
                spinner_text="MIMIR is explaining the concept",
                record_history=False,
            )
            ai_response = sanitize_information_response(ai_response, clean_input)
            print(f"\n\033[1;36m[MIMIR]\033[0m \033[1;36m{ai_response}\033[0m\n")
        else:
            ai_response = ask_ai(prompt_text)

        # --- SECURITY FILTER ---
        is_safe, security_msg = validate_security_policy(ai_response)
 
        if not is_safe:
            if has_force:
                # --force overrides security violations EXCEPT critical ones
                if any(x in ai_response.lower() for x in ["no ipv6 nd raguard", "no dot1x"]):
                    print(f"\n\n\033[1;31m{security_msg}\033[0m")
                    print("\033[1;31m[!] --force CANNOT override critical security features. Blocked.\033[0m")
                    judge = 's'
                else:
                    print(f"\n\033[1;35m[FORCE]\033[0m {security_msg}")
                    print("\033[1;35m[FORCE]\033[0m Audit bypassed. Ready to save dataset.")
                    judge = input("[?] AI correct? (y = Yes / s = Wrong, retype / n = Skip): ")
            else:
                print(f"\n{security_msg}")
                print("\033[1;33mAction:\033[0m Mandatory correction required.")
                judge = 's'
        else:
            if "[RISK ALERT]" in security_msg:
                print(f"\n{security_msg}")
                if has_force:
                    print("\033[1;35m[FORCE]\033[0m Acknowledged. Proceeding.")
            judge = input("[?] AI correct? (y = Yes / s = Wrong, retype / n = Skip): ")
 
        if judge.lower() == 's':
            # --- STEP 1: VERIFY ---
            suggested_cmd = ""
            cmd_match = re.search(r"EXECUTE:\s*(.*)", ai_response, re.DOTALL)
            if cmd_match: suggested_cmd = cmd_match.group(1).split("\n")[0].strip()
            
            print(f"\n\033[1;34m[*]\033[0m STEP 1: Verify Switch Data (Optional)")
            choice = input(f"[?] AI suggested '{suggested_cmd}'. Run? (y/n/custom): ")
            cmd_to_run = suggested_cmd if choice.lower() == 'y' else (choice if choice.lower() != 'n' and choice != "" else "")
 
            if cmd_to_run:
                is_c = any(x in cmd_to_run.lower() for x in ["conf t", "interface", "vlan", "ipv6"])
                print(f"\n\033[1;37m[REAL RESULT]\033[0m\n{netmiko_execute(cmd_to_run, is_config=is_c)}\n")
 
            # --- STEP 2: EDIT ---
            print("\033[1;34m[*]\033[0m STEP 2: Fix the Response")
            display_text = re.sub(r'\*\*(.*?)\*\*', r'\033[1m\1\033[1;37m', ai_response)
            display_text = display_text.replace("EXECUTE:", "\033[1mEXECUTE:\033[1;37m")
            print("\033[1;30m" + "-" * 40 + "\033[0m")
            print(f"\033[1;37m{display_text}\033[0m")
            print("\033[1;30m" + "-" * 40 + "\033[0m")
            print("\033[1;34m[*]\033[0m (Type 'U' to undo last line | 'END' to save | 'EXIT' to cancel)")
 
            final_lines = []
            while True:
                line = sys.stdin.readline()
                if not line: break
                
                cmd_upper = line.strip().upper()
 
                if cmd_upper == "END": 
                    break
                if cmd_upper == "EXIT":
                    final_lines.clear()
                    break
                if cmd_upper == "U":
                    if final_lines:
                        removed = final_lines.pop()
                        print(f"    \033[1;33m[UNDO]\033[0m Removed: {removed.strip()}")
                    else:
                        print("    \033[1;31m[!]\033[0m Nothing to undo.")
                    continue
 
                final_lines.append(line)
 
            correct_output = "".join(final_lines).strip()
            
            if correct_output:
                save_qa_dataset(prompt_text, correct_output)
                ai_response = correct_output
                is_manually_corrected = True
                print("\033[1;32m[+]\033[0m Saved corrected answer!")
            else:
                print("\033[1;33m[!]\033[0m Empty. Skipping dataset save...")
 
        elif judge.lower() == 'y':
            save_qa_dataset(prompt_text, ai_response)
            print("\033[1;32m[+]\033[0m Saved correct answer!")
 
        else:
            print("\033[1;33m[!]\033[0m Skipped saving.")
            continue
 
        # --- EXECUTE LOGIC ---
        if "EXECUTE:" in ai_response:
            execute_count = ai_response.count("EXECUTE:")
            if execute_count > 1:
                print(f"\n\033[1;31m[!]\033[0m AI returned {execute_count} EXECUTE blocks. System processes one at a time.")
                print(f"\033[1;33m[!]\033[0m Please split your request into separate commands and try again.")
                continue

            raw_cmd = ai_response.split("EXECUTE:")[1].split("\n")[0].strip()
            move_all_match = re.search(
                r'(?:move|migrate|transfer)\s+all.*?vlan\s+(\d+).*?(?:to\s+)?vlan\s+(\d+)',
                ai_response,
                re.IGNORECASE
            )
            if move_all_match:
                src = move_all_match.group(1)
                dst = move_all_match.group(2)
                print(f"\n\033[1;35m[WORKFLOW]\033[0m AI triggered move all: VLAN {src} → {dst}")
                vlan_move_all_workflow(src, dst, has_force=has_force)
                continue
 
            cmd = raw_cmd.split("| MSG")[0].strip()
 
            is_conf = not cmd.startswith(("show", "ping", "traceroute", "clear", "terminal"))
 
            if cmd.startswith("show "):
                if "| section include" in cmd:
                    base_cmd = cmd.split("|")[0].strip()
                    filters = cmd.split("include")[1].strip().split("|")
                    result = netmiko_execute(base_cmd, is_config=False)
                    filtered = []
                    capture = False
                    for line in result.splitlines():
                        if any(f.strip() in line for f in filters):
                            capture = True
                        elif line.startswith("interface ") or line.startswith("!"):
                            if capture and line.startswith("!"):
                                capture = False
                        if capture:
                            filtered.append(line)
                    result = "\n".join(filtered)
 
                elif ("Administrative Mode:" in cmd and "spanning-tree portfast" in cmd and "\\n" in cmd):
                    commands = [c.strip() for c in cmd.replace("\\n", "\n").split("\n") if c.strip()]
                    print(f"\033[1;36m[*]\033[0m Running Security Audit on Switch...")
 
                    if len(commands) >= 2:
                        sw_out = netmiko_execute(commands[0], is_config=False)
                        run_out = netmiko_execute(commands[1], is_config=False)
                        status_out = netmiko_execute("show interfaces status", is_config=False)
 
                        safe_ports, critical_ports = parse_safe_shutdown(sw_out, run_out, status_out)
 
                        print(f"\n\033[1;36m{'='*50}\033[0m")
                        print(f"  \033[1;36mSECURITY AUDIT RESULT\033[0m")
                        print(f"\033[1;36m{'='*50}\033[0m")
                        if critical_ports:
                            print(f"  \033[1;31mCRITICAL\033[0m (has description): {', '.join(sorted(critical_ports))}")
                        
                        if safe_ports:
                            print(f"  \033[1;32mSAFE\033[0m to shutdown ({len(safe_ports)}): {', '.join(safe_ports)}")
                            print(f"\033[1;36m{'='*50}\033[0m")
 
                            confirm = input(f"\n[CONFIRM] Shutdown {len(safe_ports)} safe ports? (y/n): ")
                            if confirm.lower() == 'y':
                                from collections import defaultdict
                                groups = defaultdict(list)
                                for p in safe_ports:
                                    prefix, num = p.rsplit("/", 1)
                                    groups[prefix].append(int(num))
                                ranges = []
                                for prefix in sorted(groups):
                                    nums = sorted(groups[prefix])
                                    start = end = nums[0]
                                    for n in nums[1:]:
                                        if n == end + 1:
                                            end = n
                                        else:
                                            ranges.append(f"{prefix}/{start}" if start == end else f"{prefix}/{start}-{end}")
                                            start = end = n
                                    ranges.append(f"{prefix}/{start}" if start == end else f"{prefix}/{start}-{end}")
                                
                                range_str = "interface range " + ",".join(ranges)
                                shut_cmd = f"{range_str}\\nshutdown"
                                result = netmiko_execute(shut_cmd, is_config=True) 
                                print(f"\033[1;37m[RESULT]\033[0m\n{result}")
                            else:
                                print("\033[1;31m[CANCELLED]\033[0m")
                        else:
                            print(f"  \033[1;41mWARNING:\033[0m \033[1;31mNo safe ports found!\033[0m")
                            print(f"  \033[1;33mAll ports are either Trunks, missing Portfast, or have description.\033[0m")
                            print(f"\033[1;36m{'='*50}\033[0m")
                    else:
                        print("\033[1;31m[ERROR]\033[0m Could not parse 2 show commands.")
                    continue
 
                else:
                    result = netmiko_execute(cmd, is_config=False)
 
                print(f"\033[1;37m[RAW OUTPUT]\033[0m\n{result}")
 
                pre_summary = ""
                if "interfaces status" in cmd:
                    disabled, connected, notconnect = [], [], []
                    for line in result.splitlines():
                        match = re.match(r'^(Fa|Gi|Te|Et)(\d+/\d+(/\d+)?)\s+', line.strip())
                        if match:
                            port = match.group(0).strip()
                            if "disabled" in line: disabled.append(port)
                            elif "connected" in line: connected.append(port)
                            elif "notconnect" in line: notconnect.append(port)
                    pre_summary = f"\nPARSED BY SYSTEM (accurate):\n- Disabled ({len(disabled)}): {', '.join(disabled)}\n- Connected ({len(connected)}): {', '.join(connected)}\n- Notconnect ({len(notconnect)}): {', '.join(notconnect)}\nUSE THESE NUMBERS. Do not recount."
                
                if "processes cpu history" in cmd:
                    # Replace ASCII graph with simple numbers
                    simple_cpu = netmiko_execute("show processes cpu | include CPU", is_config=False)
                    pre_summary = f"""
                    [SYSTEM OVERRIDE - CRITICAL DATA]: 
                    WARNING: As an AI, you cannot reliably parse ASCII graphs. 
                    IGNORE the ASCII graph in the RAW CLI above. 
                    STRICTLY USE these parsed numbers to analyze CPU load:
                    >>> {simple_cpu.strip()} <<<
                    """

                if not is_manually_corrected:
                    ask_sum = input("\n[?] Do you want AI to summarize this result? (y/n): ")
                    if ask_sum.lower() == 'y':
                        if "processes cpu history" in cmd:
                            dynamic_steps = "Analyze the CPU usage strictly using the [SYSTEM OVERRIDE] numbers. Report the CPU load trends (average and peaks) concisely."
                        elif "interfaces status" in cmd:
                            dynamic_steps = textwrap.dedent("""
                                [STRICT SYSTEM AUDIT]:
                                1. SCAN: Look at the 'Status' column for EVERY port.
                                2. LIST: List all ports marked 'connected' (DO NOT miss Fa0/1 Trunk).
                                3. COUNT: Sum the total for each status.
                                
                                [OUTPUT FORMAT - FILL IN THE BLANKS]:
                                * [TOTAL_CONNECTED] ports are connected: [List ports with Descriptions, e.g., Fa0/1 (TRUNK), Fa0/9 (SERVER)]
                                * [TOTAL_DISABLED] ports are disabled: [Group port names, e.g., Fa0/2-8, Fa0/11-24]
                                
                                [STRICT RULE]: No narrative. No 'Mapping' or 'Filtering' headers. Just the two lines above.
                            """).strip()
                            
                        elif "running-config" in cmd:
                            dynamic_steps = textwrap.dedent("""
                                1. SCANNING: Look at each 'interface' line.
                                2. VERIFICATION: Check if 'attach-policy' is immediately below.
                                - YES: PROTECTED.
                                - NO: VULNERABLE.
                                3. VLAN AUDIT: Identify VLANs with global policies.
                                [MANDATORY OUTPUT FORMAT]:
                                - PROTECTED PORTS: [List]
                                - GLOBAL PROTECTION: [List]
                                - SECURITY GAPS: [List ALL vulnerable ports]
                                - FHS STATUS: [Briefly mention RA Guard/Snooping]
                                """).strip()
                        else:
                            dynamic_steps = "Summarize the key information from the RAW CLI output concisely. Focus ONLY on what is actually present in the data."
                        
                        summary_prompt = f"""
                        SUMMARY_MODE: The command has ALREADY been executed. Summarize RAW CLI output only.
                        [ROLE]: Senior Forensic Network Auditor.
                        [STRICT RULES]:
                        - Do NOT use EXECUTE.
                        - Do NOT suggest or repeat a show/config command.
                        - Do NOT answer the original admin request.
                        - Summarize only facts visible in RAW CLI.
                     
                        [INPUT]:
                        - COMMAND ALREADY RUN: {cmd}
                        - RAW CLI: {result[-2000:]}
                        {pre_summary}
                     
                        [FORENSIC ANALYSIS STEPS]:
                        {dynamic_steps}
                    
                        [LIMIT]: 5 lines max. No hallucinations. If a port has no config, it is NOT protected.
                        """
                     
                        print("\n\033[1;36m[MIMIR IS ANALYZING SYSTEM LOGS...]\033[0m")
                        summary = ask_ai(summary_prompt, silent=True, spinner_text="MIMIR is summarizing raw CLI output")
                        if "execute:" in summary.lower():
                            summary = local_cli_summary(cmd, result, pre_summary)
                        print(f"\n\033[1;36m[MIMIR]\033[0m \033[1;36m{summary}\033[0m\n")
                else:
                    print("\n\033[1;36m[INFO]\033[0m Manual correction applied. Skipping auto-summary to avoid repetition.")
                    is_manually_corrected = False
 
# --- CONFIG COMMAND EXECUTION ---

            else:
                if audit_context and "BLOCKED" in audit_context:
                    print(f"\n\033[1;31m[AUTO-AUDIT BLOCK]\033[0m Cannot execute — audit found protected/trunk ports.")
                    print(f"\033[1;34m[INFO]\033[0m Use --force to override audit (except trunk or critical ports).")
                    if not has_force:
                        continue

                is_dangerous_trunk_cmd = (
                    ("shutdown" in cmd.lower() and "no shutdown" not in cmd.lower()) or
                    ("switchport mode" in cmd.lower() and "trunk" not in cmd.lower())
                )
                if is_dangerous_trunk_cmd:
                    has_trunk, trunk_list = is_trunk_port(cmd)
                    if has_trunk:
                        print(f"\n\033[1;41m[CRITICAL BLOCK]\033[0m \033[1;31mTrunk port(s) detected: {', '.join(trunk_list)}\033[0m")
                        print("\033[1;31m[!]\033[0m \033[1;33mShutdown trunk or Changing trunk mode = network isolation. BLOCKED regardless of --force or VERIFIED.\033[0m")
                        continue
                    
                    if audit_context and any(f"{p}" in audit_context and "CRITICAL" in audit_context for p in extract_ports_from_input(cmd)):
                        print(f"\n\033[1;41m[CRITICAL BLOCK]\033[0m \033[1;31mServer port(s) detected (from prior audit)\033[0m")
                        print("\033[1;31m[!]\033[0m \033[1;33mServer ports require manual CLI shutdown. BLOCKED.\033[0m")
                        continue
                    port_match = []
                    matches = re.findall(r'(fa[a-z]*|gi[a-z]*|te[a-z]*|et[a-z]*)\s*(\d+(?:/\d+)?)/(\d+)(?:\s*(?:-|to)\s*(?:(?:fa[a-z]*|gi[a-z]*|te[a-z]*|et[a-z]*)\s*\d+(?:/\d+)?/)?(\d+))?', cmd, re.IGNORECASE)
                    for match in matches:
                        prefix = match[0][:2].capitalize()
                        slot = match[1]
                        start_port = int(match[2])
                        if match[3]:
                            end_port = int(match[3])
                            for p in range(start_port, int(match[3])+1):
                                port_match.append(f"{prefix}{slot}/{p}")
                        else:
                            port_match.append(f"{prefix}{slot}/{start_port}")
                        
                    if port_match:
                        server_blocked = []
                        switchport_out = netmiko_execute("show interfaces switchport | include Name:|Administrative", is_config=False)
                        run_out = netmiko_execute("show run | section interface", is_config=False)
                        status_out = netmiko_execute("show interfaces status", is_config=False)
                        _, critical_ports = parse_safe_shutdown(switchport_out, run_out, status_out)
                        
                        for p in port_match:
                            normalized = p[:2].capitalize() + p[2:]
                            if normalized in critical_ports:
                                server_blocked.append(normalized)
                        
                        if server_blocked:
                            print(f"\n\033[1;41m[CRITICAL BLOCK]\033[0m \033[1;31mServer port(s) detected: {', '.join(server_blocked)}\033[0m")
                            print("\033[1;31m[!]\033[0m \033[1;33mServer ports require manual CLI shutdown. BLOCKED regardless of --force or VERIFIED.\033[0m")
                            print("\033[1;33m[TIP]\033[0m Connect via direct console/SSH for accountability.\033[0m")
                            continue

                # --- SECURE PORT OPEN WORKFLOW ---
                vlan_match = re.search(r'switchport\s+access\s+vlan\s+(\d+)', cmd, re.IGNORECASE)
                
                cmd_lines = [l.strip() for l in cmd.replace("\\n", "\n").split("\n") if l.strip()]
                is_complex = len(cmd_lines) > 4 or "authentication" in cmd or "storm-control" in cmd or "dhcp snooping" in cmd or "raguard" in cmd
                
                if vlan_match and not is_complex:
                    target_vlan = vlan_match.group(1)
                    remove_matches = re.findall(r'no\s+vlan\s+(\d+)', cmd, re.IGNORECASE)
                    remove_vlans = [v for v in remove_matches if v != target_vlan]
                    
                    migrate_ports = extract_ports_from_input(cmd)
                    if not migrate_ports:
                        migrate_ports = extract_ports_from_input(user_input)
                    
                    if migrate_ports:
                        print(f"\n\033[1;35m[VLAN MIGRATION]\033[0m {migrate_ports} → VLAN {target_vlan}")
                        if remove_vlans:
                            print(f"\033[1;33m[VLAN REMOVAL]\033[0m Will also remove: {remove_vlans}")
                        vlan_migration_workflow(migrate_ports, target_vlan, has_force=has_force, remove_vlans=remove_vlans)
                
                        if "no shutdown" in cmd.lower():
                            print(f"\n\033[1;36m[CHAIN]\033[0m Detected 'no shutdown' — chaining to Open Port Workflow...")
                            open_port_workflow(migrate_ports, has_force=has_force)
                        
                        continue
                
                if "no shutdown" in cmd.lower():
                    open_ports = extract_ports_from_input(cmd)
                    
                    if not open_ports:
                        open_ports = extract_ports_from_input(user_input)
                    
                    if open_ports:
                        print(f"\n\033[1;35m[SECURE OPEN]\033[0m Detected port open request: \033[1;33m{open_ports}\033[0m")
                        print("\033[1;35m[SECURE OPEN]\033[0m Routing through Secure Port Open Workflow...")
                        open_port_workflow(open_ports, has_force=has_force)
                        continue
                    else:
                        print("\033[1;33m[!]\033[0m Could not extract ports from command. Proceeding with raw execute.")

                is_conf = not cmd.startswith(("show", "ping", "traceroute", "clear", "terminal"))

                if has_force:
                    print(f"\033[1;35m[FORCE]\033[0m Auto-executing: {cmd}")
                    confirm = 'y'
                else:
                    confirm = input(f"[CONFIRM] Execute '{cmd}'? (y/n): ")
                
                if confirm.lower() == 'y':
                    result = netmiko_execute(cmd, is_config=is_conf)
                    print(f"\033[1;37m[RESULT]\033[0m\n{result}")
                else:
                    print("[CANCELLED]")
        else:
            pass
 
    except KeyboardInterrupt:
        print("\n👋 \033[1;30mGoodbye.\033[0m")
        break

    except Exception as e:
        print("\n" + "="*50)
        print("\033[1;31m[CRASH DETECTED]\033[0m")
        traceback.print_exc()
        print("="*50)
        input("\n[!] CMD IS BEING HOLD...")
