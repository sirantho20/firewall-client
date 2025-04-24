
import subprocess
import shutil
import re
import os
import tempfile
from flask import Flask, request, jsonify
from functools import wraps

# ========================== Security Config ==========================
API_KEY = "your-secure-token"

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
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            return {"success": True, "output": result.strip()}
        except subprocess.CalledProcessError as e:
            return {"success": False, "output": e.output.strip()}

    # ------------------------- UFW METHODS -------------------------

    def ufw_status(self):
        if not self.ufw_installed:
            return {"success": False, "output": "UFW not installed. Install with sudo apt install ufw"}
        result = self._run(f"{self.ufw_command} status numbered")
        if result["success"]:
            return self._parse_ufw_rules(result["output"])
        return result

    def _parse_ufw_rules(self, raw_output):
        lines = raw_output.splitlines()
        rules = []
        for line in lines:
            match = re.match(r'\[(\d+)\]\s+(.+?)\s+(ALLOW|DENY)\s+(IN|OUT)\s+(.+)', line)
            if match:
                rules.append({
                    "number": int(match.group(1)),
                    "rule": match.group(2).strip(),
                    "action": match.group(3),
                    "direction": match.group(4),
                    "from_to": match.group(5).strip(),
                })
        return {"success": True, "rules": rules}

    def ufw_add_rule(self, action, port, proto="tcp", direction="in", ip=None):
        if ip:
            cmd = f"{self.ufw_command} {action} from {ip} to any port {port} proto {proto}"
        else:
            cmd = f"{self.ufw_command} {action} {port}/{proto} {direction}"
        return self._run(cmd)

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

@app.route('/api/ufw/rule', methods=['POST'])
@require_auth
def ufw_add_rule():
    data = request.json
    return jsonify(manager.ufw_add_rule(data["action"], data["port"], data.get("proto", "tcp"),
                                        data.get("direction", "in"), data.get("ip", None)))

@app.route('/api/ufw/delete', methods=['POST'])
@require_auth
def ufw_delete_rule():
    data = request.json
    return jsonify(manager.ufw_delete_rule(data["rule_number"]))

@app.route('/api/ufw/enable', methods=['POST'])
@require_auth
def ufw_enable():
    return jsonify(manager.ufw_enable())

@app.route('/api/ufw/disable', methods=['POST'])
@require_auth
def ufw_disable():
    return jsonify(manager.ufw_disable())

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
