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
        """List all available Fail2Ban jails."""
        jail_dir = "/etc/fail2ban/jail.d"
        try:
            if not os.path.exists(jail_dir):
                return {"success": False, "output": f"Jail directory {jail_dir} not found"}
            
            jails = []
            for filename in os.listdir(jail_dir):
                if filename.endswith('.local'):
                    jail_name = filename[:-6]  # Remove .local extension
                    jails.append(jail_name)
            
            return {"success": True, "jails": jails}
        except Exception as e:
            return {"success": False, "output": str(e)}

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

    def f2b_create_filter(self, filter_name, content):
        """Create a new Fail2Ban filter."""
        filter_path = f"/etc/fail2ban/filter.d/{filter_name}.conf"
        try:
            if os.path.exists(filter_path):
                return {"success": False, "output": f"Filter {filter_name} already exists"}
            
            # Validate the content has required sections
            if "[Definition]" not in content:
                return {"success": False, "output": "Filter content must contain [Definition] section"}
            
            # Write the new content
            with open(filter_path, 'w') as f:
                f.write(content)
            
            # Validate the new filter
            validation_result = self.f2b_validate_filter("", "", "")
            if not validation_result["success"]:
                # Remove the file if validation fails
                os.remove(filter_path)
                return {"success": False, "output": f"Filter validation failed: {validation_result['output']}"}
            
            return {"success": True, "output": f"Filter {filter_name} created successfully"}
        except Exception as e:
            # Clean up if any error occurs
            if os.path.exists(filter_path):
                os.remove(filter_path)
            return {"success": False, "output": str(e)}

    def f2b_delete_filter(self, filter_name):
        """Delete a Fail2Ban filter."""
        filter_path = f"/etc/fail2ban/filter.d/{filter_name}.conf"
        try:
            if not os.path.exists(filter_path):
                return {"success": False, "output": f"Filter {filter_name} not found"}
            
            # Create a backup before deletion
            backup_path = f"{filter_path}.bak"
            shutil.copy2(filter_path, backup_path)
            
            # Delete the filter
            os.remove(filter_path)
            
            # Check if any jails are using this filter
            jail_dir = "/etc/fail2ban/jail.d"
            if os.path.exists(jail_dir):
                for jail_file in os.listdir(jail_dir):
                    if jail_file.endswith('.local'):
                        with open(os.path.join(jail_dir, jail_file), 'r') as f:
                            content = f.read()
                            if f"filter = {filter_name}" in content:
                                # Restore the filter if it's being used
                                shutil.move(backup_path, filter_path)
                                return {"success": False, "output": f"Cannot delete filter {filter_name} as it is being used by one or more jails"}
            
            # Remove backup if everything is successful
            os.remove(backup_path)
            return {"success": True, "output": f"Filter {filter_name} deleted successfully"}
        except Exception as e:
            # Restore from backup if any error occurs
            if os.path.exists(backup_path):
                shutil.move(backup_path, filter_path)
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

    def f2b_list_filters(self):
        """List all available Fail2Ban filters."""
        filter_dir = "/etc/fail2ban/filter.d"
        try:
            if not os.path.exists(filter_dir):
                return {"success": False, "output": f"Filter directory {filter_dir} not found"}
            
            filters = []
            for filename in os.listdir(filter_dir):
                if filename.endswith('.conf'):
                    filter_name = filename[:-5]  # Remove .conf extension
                    filters.append(filter_name)
            
            return {"success": True, "filters": filters}
        except Exception as e:
            return {"success": False, "output": str(e)}

    def f2b_read_filter(self, filter_name):
        """Read the contents of a specific Fail2Ban filter."""
        filter_path = f"/etc/fail2ban/filter.d/{filter_name}.conf"
        try:
            if not os.path.exists(filter_path):
                return {"success": False, "output": f"Filter {filter_name} not found"}
            
            with open(filter_path, 'r') as f:
                content = f.read()
            
            return {"success": True, "content": content}
        except Exception as e:
            return {"success": False, "output": str(e)}

    def f2b_update_filter(self, filter_name, content):
        """Update the contents of a specific Fail2Ban filter."""
        filter_path = f"/etc/fail2ban/filter.d/{filter_name}.conf"
        try:
            if not os.path.exists(filter_path):
                return {"success": False, "output": f"Filter {filter_name} not found"}
            
            # Validate the content has required sections
            if "[Definition]" not in content:
                return {"success": False, "output": "Filter content must contain [Definition] section"}
            
            # Create a backup of the original file
            backup_path = f"{filter_path}.bak"
            shutil.copy2(filter_path, backup_path)
            
            # Write the new content
            with open(filter_path, 'w') as f:
                f.write(content)
            
            # Validate the new filter
            validation_result = self.f2b_validate_filter("", "", "")
            if not validation_result["success"]:
                # Restore from backup if validation fails
                shutil.move(backup_path, filter_path)
                return {"success": False, "output": f"Filter validation failed: {validation_result['output']}"}
            
            # Remove backup if everything is successful
            os.remove(backup_path)
            return {"success": True, "output": f"Filter {filter_name} updated successfully"}
        except Exception as e:
            # Restore from backup if any error occurs
            if os.path.exists(backup_path):
                shutil.move(backup_path, filter_path)
            return {"success": False, "output": str(e)}

    def f2b_read_jail(self, jail_name):
        """Read the contents of a specific Fail2Ban jail."""
        jail_path = f"/etc/fail2ban/jail.d/{jail_name}.local"
        try:
            if not os.path.exists(jail_path):
                return {"success": False, "output": f"Jail {jail_name} not found"}
            
            with open(jail_path, 'r') as f:
                content = f.read()
            
            return {"success": True, "content": content}
        except Exception as e:
            return {"success": False, "output": str(e)}

    def f2b_update_jail(self, jail_name, content):
        """Update the contents of a specific Fail2Ban jail."""
        jail_path = f"/etc/fail2ban/jail.d/{jail_name}.local"
        try:
            if not os.path.exists(jail_path):
                return {"success": False, "output": f"Jail {jail_name} not found"}
            
            # Validate the content has required sections
            if f"[{jail_name}]" not in content:
                return {"success": False, "output": f"Jail content must contain [{jail_name}] section"}
            
            # Create a backup of the original file
            backup_path = f"{jail_path}.bak"
            shutil.copy2(jail_path, backup_path)
            
            # Write the new content
            with open(jail_path, 'w') as f:
                f.write(content)
            
            # Reload fail2ban to apply changes
            reload_result = self.f2b_reload()
            if not reload_result["success"]:
                # Restore from backup if reload fails
                shutil.move(backup_path, jail_path)
                return {"success": False, "output": f"Failed to reload fail2ban: {reload_result['output']}"}
            
            # Remove backup if everything is successful
            os.remove(backup_path)
            return {"success": True, "output": f"Jail {jail_name} updated successfully"}
        except Exception as e:
            # Restore from backup if any error occurs
            if os.path.exists(backup_path):
                shutil.move(backup_path, jail_path)
            return {"success": False, "output": str(e)}

    def f2b_delete_jail(self, jail_name):
        """Delete a Fail2Ban jail."""
        jail_path = f"/etc/fail2ban/jail.d/{jail_name}.local"
        try:
            if not os.path.exists(jail_path):
                return {"success": False, "output": f"Jail {jail_name} not found"}
            
            # Create a backup before deletion
            backup_path = f"{jail_path}.bak"
            shutil.copy2(jail_path, backup_path)
            
            # Delete the jail
            os.remove(jail_path)
            
            # Reload fail2ban to apply changes
            reload_result = self.f2b_reload()
            if not reload_result["success"]:
                # Restore from backup if reload fails
                shutil.move(backup_path, jail_path)
                return {"success": False, "output": f"Failed to reload fail2ban: {reload_result['output']}"}
            
            # Remove backup if everything is successful
            os.remove(backup_path)
            return {"success": True, "output": f"Jail {jail_name} deleted successfully"}
        except Exception as e:
            # Restore from backup if any error occurs
            if os.path.exists(backup_path):
                shutil.move(backup_path, jail_path)
            return {"success": False, "output": str(e)}

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
    if not data or 'filter_name' not in data or 'content' not in data:
        return jsonify({"success": False, "output": "Missing filter_name or content in request"}), 400
    return jsonify(manager.f2b_create_filter(data['filter_name'], data['content']))

@app.route('/api/f2b/validate-filter', methods=['POST'])
@require_auth
def f2b_validate_filter():
    data = request.json
    return jsonify(manager.f2b_validate_filter(data["log_sample"], data["failregex"], data.get("ignoreregex", "")))

@app.route('/api/f2b/filters', methods=['GET'])
@require_auth
def f2b_list_filters():
    return jsonify(manager.f2b_list_filters())

@app.route('/api/f2b/filters/<filter_name>', methods=['GET'])
@require_auth
def f2b_read_filter(filter_name):
    return jsonify(manager.f2b_read_filter(filter_name))

@app.route('/api/f2b/filters/<filter_name>', methods=['PUT'])
@require_auth
def f2b_update_filter(filter_name):
    data = request.json
    if not data or 'content' not in data:
        return jsonify({"success": False, "output": "Missing filter content in request"}), 400
    return jsonify(manager.f2b_update_filter(filter_name, data['content']))

@app.route('/api/f2b/filters/<filter_name>', methods=['DELETE'])
@require_auth
def f2b_delete_filter(filter_name):
    return jsonify(manager.f2b_delete_filter(filter_name))

# Jail CRUD endpoints
@app.route('/api/f2b/jails/<jail_name>', methods=['GET'])
@require_auth
def f2b_read_jail(jail_name):
    return jsonify(manager.f2b_read_jail(jail_name))

@app.route('/api/f2b/jails/<jail_name>', methods=['PUT'])
@require_auth
def f2b_update_jail(jail_name):
    data = request.json
    if not data or 'content' not in data:
        return jsonify({"success": False, "output": "Missing jail content in request"}), 400
    return jsonify(manager.f2b_update_jail(jail_name, data['content']))

@app.route('/api/f2b/jails/<jail_name>', methods=['DELETE'])
@require_auth
def f2b_delete_jail(jail_name):
    return jsonify(manager.f2b_delete_jail(jail_name))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005)
