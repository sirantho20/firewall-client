#!/bin/bash

# Exit on any error
set -e

# Get the absolute path of the current directory
CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Define target directory
TARGET_DIR="/opt/firewall/agent"

# Create target directory if it doesn't exist
echo "Creating target directory..."
sudo mkdir -p "$TARGET_DIR"

# Copy project files
echo "Copying project files..."
sudo cp -r "$CURRENT_DIR"/* "$TARGET_DIR/"

# Create systemd service file
echo "Creating systemd service..."
sudo tee /etc/systemd/system/FirewallAgent.service > /dev/null << EOL
[Unit]
Description=Firewall Agent Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$TARGET_DIR
ExecStart=$TARGET_DIR/env/bin/python $TARGET_DIR/agent.py
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=FirewallAgent

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd to recognize new service
echo "Reloading systemd..."
sudo systemctl daemon-reload

# Enable and start the service
echo "Enabling and starting service..."
sudo systemctl enable FirewallAgent
sudo systemctl start FirewallAgent

echo "Installation complete! Service has been installed and started."
echo "You can check the service status with: sudo systemctl status FirewallAgent"
echo "You can view logs with: journalctl -u FirewallAgent" 