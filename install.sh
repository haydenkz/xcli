#!/bin/bash
set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Please run with sudo."
  exit 1
fi

# Check if Go is installed
if ! command -v go &>/dev/null; then
  echo "Go is not installed. Please install Go and try again."
  exit 1
fi

echo "IMPORTANT: Ensure your Twitter Developer Portal callback URL is set to: http://localhost:5000/callback"
echo ""

# Compile the application from xcli.go
echo "Compiling xcli.go..."
go build -o x xcli.go
echo "Compilation successful."

# Copy the binary to /bin
echo "Copying the binary to /bin/x..."
cp x /bin/x
chmod +x /bin/x
echo "Binary copied to /bin/x."

# Create configuration directory if it doesn't exist
if [ ! -d /etc/xcli ]; then
  echo "Creating /etc/xcli directory..."
  mkdir -p /etc/xcli
fi

# Create config file if not exists
CONFIG_FILE="/etc/xcli/config"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Configuration file not found."
  read -p "Enter your CLIENT ID: " CLIENT_ID
  echo "Creating configuration file at $CONFIG_FILE..."
  echo "{ \"client_id\": \"${CLIENT_ID}\" }" > "$CONFIG_FILE"
  echo "Configuration saved."
fi

echo "Installation complete. You can now run the application using 'x'."
