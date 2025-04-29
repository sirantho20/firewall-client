import subprocess
import shutil
import re
import os
import tempfile
from flask import Flask, request, jsonify
from functools import wraps

# ========================== Security Config ==========================
API_KEY = "tony123"

# ========================== Flask App ==========================
app = Flask(__name__)

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.headers.get("Authorization") != f"Bearer {API_KEY}":
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

# ========================== Combined Manager ==========================

class FirewallManager:
    """
    Combined manager for UFW and Fail2Ban operations.
    """

    def __init__(self):
        self.ufw_command = "sudo ufw"
        self.ufw_installed = shutil.which("ufw") is not None

    def _run(self, command):
        try:
            print(str(command))
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            return {"success": True, "output": result.strip()}
        except subprocess.CalledProcessError as e:
            return {"success": False, "output": e.output.strip()}

    # ------------------------- UFW METHODS -------------------------

    def ufw_status(self):
        if not self.ufw_installed:
            return {"success": False, "output": "UFW not installed. Install with sudo apt install ufw"}
        
        # First get the status to check if UFW is active
        status_result = self._run(f"{self.ufw_command} status")
        if not status_result["success"]:
            return status_result
            
        # Then get the numbered rules
        rules_result = self._run(f"{self.ufw_command} status")
        if not rules_result["success"]:
            return rules_result
            
        # Parse the status
        status = "inactive"
        if "Status: active" in status_result["output"]:
            status = "active"
            
        # Parse the rules
        rules = []
        rule_number = 1
        
        # Skip the header lines
        lines = [line for line in rules_result["output"].splitlines() 
                if line and not line.startswith(('To', '--'))]
                
        for line in lines:
            print(f"\nProcessing line: {line}")  # Debug print
            
            # Split the line into components
            parts = line.split()
            print(f"Parts: {parts}")  # Debug print
            
            if len(parts) < 3:
                continue
                
            # Check for IPv6 - look for (v6) anywhere in the line
            is_ipv6 = "(v6)" in line
            print(f"Is IPv6: {is_ipv6}")  # Debug print
            
            # Extract port and protocol, handling IPv6 format
            port_proto = parts[0].replace("(v6)", "").strip()
            if '/' in port_proto:
                port, protocol = port_proto.split('/')
            else:
                port = port_proto
                protocol = "tcp"  # Default protocol
                
            # Extract action (it's always the second part)
            action = parts[1]
            
            # Extract IP/network (it's always the third part)
            ip = parts[2].replace("(v6)", "").strip() if parts[2] != "Anywhere" else None
            
            # Only add the rule if we have valid components
            if port and action in ["ALLOW", "DENY"]:
                rules.append({
                    "number": rule_number,
                    "action": action,
                    "direction": "IN",  # Default direction
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "interface": None,  # Interface not shown in this format
                    "ipv6": is_ipv6
                })
                rule_number += 1
                
        return {
            "success": True,
            "status": status,
            "rules": rules
        }

    def ufw_add_rule(self, action, port, proto="tcp", direction="in", ip=None, interface=None):
        if ip:
            action = action.lower()
            if interface:
                cmd = f"{self.ufw_command} {action} from {ip} to any port {port} proto {proto} on {interface}"
            else:
                cmd = f"{self.ufw_command} {action} from {ip} to any port {port} proto {proto}"
        else:
            if interface:
                cmd = f"{self.ufw_command} {action} {port}/{proto} {direction} on {interface}"
            else:
                cmd = f"{self.ufw_command} {action} {port}/{proto} {direction}"
        
        result = self._run(cmd)
        if not result["success"]:
            return result
            
        # Return structured response
        return {
            "success": True,
            "rule": {
                "action": action.upper(),
                "direction": direction,
                "interface": interface,
                "ip": ip,
                "port": str(port),
                "protocol": proto
            }
        }

    def ufw_delete_rule(self, rule_number):
        return self._run(f"echo y | {self.ufw_command} delete {rule_number}")

    def ufw_enable(self):
        return self._run(f"{self.ufw_command} --force enable")

    def ufw_disable(self):
        return self._run(f"{self.ufw_command} disable")

    # ------------------------- FAIL2BAN METHODS -------------------------

    def f2b_list_jails(self):
        return self._run("sudo fail2ban-client status")

    def f2b_jail_status(self, jail):
        return self._run(f"sudo fail2ban-client status {jail}")

    def f2b_ban_ip(self, jail, ip):
        return self._run(f"sudo fail2ban-client set {jail} banip {ip}")

    def f2b_unban_ip(self, jail, ip):
        return self._run(f"sudo fail2ban-client set {jail} unbanip {ip}")

    def f2b_reload(self):
        return self._run("sudo fail2ban-client reload")

    def f2b_create_jail(self, jail_name, port, logpath, filter_name=None,
                        maxretry=5, bantime=600, findtime=300, action=None):
        jail_file = f"/etc/fail2ban/jail.d/{jail_name}.local"
        filter_name = filter_name or jail_name
        action = action or f"iptables[name={jail_name}, port={port}, protocol=tcp]"
        content = f"""[{jail_name}]
enabled = true
port = {port}
filter = {filter_name}
logpath = {logpath}
maxretry = {maxretry}
bantime = {bantime}
findtime = {findtime}
action = {action}
"""
        try:
            with open(jail_file, 'w') as f:
                f.write(content)
            return {"success": True, "output": f"Jail '{jail_name}' created."}
        except Exception as e:
            return {"success": False, "output": str(e)}

    def f2b_create_filter(self, filter_name, failregex, ignoreregex=""):
        filter_file = f"/etc/fail2ban/filter.d/{filter_name}.conf"
        content = f"""[Definition]
failregex = {failregex}
ignoreregex = {ignoreregex}
"""
        try:
            with open(filter_file, 'w') as f:
                f.write(content)
            return {"success": True, "output": f"Filter '{filter_name}' created."}
        except Exception as e:
            return {"success": False, "output": str(e)}

    def f2b_validate_filter(self, log_sample, failregex, ignoreregex=""):
        try:
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as log_file,                  tempfile.NamedTemporaryFile(mode="w+", delete=False) as filter_file:

                log_file.write(log_sample)
                log_file.flush()

                filter_file.write(f"[Definition]\nfailregex = {failregex}\nignoreregex = {ignoreregex}\n")
                filter_file.flush()

                cmd = f"sudo fail2ban-regex {log_file.name} {filter_file.name}"
                result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
                return {"success": True, "output": result}
        except subprocess.CalledProcessError as e:
            return {"success": False, "output": e.output}
        except Exception as ex:
            return {"success": False, "output": str(ex)}

manager = FirewallManager()

# ========================== Flask Routes ==========================

# -------- UFW
@app.route('/api/ufw/status', methods=['GET'])
@require_auth
def ufw_status():
    return jsonify(manager.ufw_status())

@app.route('/api/ufw/add', methods=['POST'])
@require_auth
def ufw_add_rule():
    data = request.json
    return jsonify(manager.ufw_add_rule(data["action"], data["port"], data.get("proto", "tcp"),
                                        data.get("direction", "in"), data.get("ip", None), data.get("interface", None)))

@app.route('/api/ufw/delete', methods=['DELETE'])
@require_auth
def ufw_delete_rule():
    data = request.json
    return jsonify(manager.ufw_delete_rule(data["rule_number"]))

# @app.route('/api/ufw/enable', methods=['POST'])
# @require_auth
# def ufw_enable():
#     return jsonify(manager.ufw_enable())

# @app.route('/api/ufw/disable', methods=['POST'])
# @require_auth
# def ufw_disable():
#     return jsonify(manager.ufw_disable())

# -------- Fail2Ban
@app.route('/api/f2b/jails', methods=['GET'])
@require_auth
def f2b_list_jails():
    return jsonify(manager.f2b_list_jails())

@app.route('/api/f2b/status/<jail>', methods=['GET'])
@require_auth
def f2b_jail_status(jail):
    return jsonify(manager.f2b_jail_status(jail))

@app.route('/api/f2b/ban', methods=['POST'])
@require_auth
def f2b_ban_ip():
    data = request.json
    return jsonify(manager.f2b_ban_ip(data["jail"], data["ip"]))

@app.route('/api/f2b/unban', methods=['POST'])
@require_auth
def f2b_unban_ip():
    data = request.json
    return jsonify(manager.f2b_unban_ip(data["jail"], data["ip"]))

@app.route('/api/f2b/reload', methods=['POST'])
@require_auth
def f2b_reload():
    return jsonify(manager.f2b_reload())

@app.route('/api/f2b/create-jail', methods=['POST'])
@require_auth
def f2b_create_jail():
    data = request.json
    return jsonify(manager.f2b_create_jail(data["jail_name"], data["port"], data["logpath"],
                                           data.get("filter_name"), data.get("maxretry", 5),
                                           data.get("bantime", 600), data.get("findtime", 300),
                                           data.get("action")))

@app.route('/api/f2b/create-filter', methods=['POST'])
@require_auth
def f2b_create_filter():
    data = request.json
    return jsonify(manager.f2b_create_filter(data["filter_name"], data["failregex"], data.get("ignoreregex", "")))

@app.route('/api/f2b/validate-filter', methods=['POST'])
@require_auth
def f2b_validate_filter():
    data = request.json
    return jsonify(manager.f2b_validate_filter(data["log_sample"], data["failregex"], data.get("ignoreregex", "")))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005)
