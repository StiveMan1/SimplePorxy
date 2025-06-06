#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Preamble ---
echo "Starting simple-proxy installation..."

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)."
  exit 1
fi

# --- Install Dependencies ---
echo "Installing dependencies..."
if command -v apt &> /dev/null; then
  # Debian/Ubuntu
  apt update
  apt install -y gcc libconfig-dev
elif command -v yum &> /dev/null; then
  # CentOS/RHEL
  yum install -y gcc libconfig-devel
elif command -v dnf &> /dev/null; then
  # Fedora
  dnf install -y gcc libconfig-devel
elif command -v pacman &> /dev/null; then
  # Arch Linux
  pacman -Sy --noconfirm gcc libconfig
else
  echo "Unsupported package manager. Please install 'gcc' and 'libconfig-dev' (or equivalent) manually."
  exit 1
fi
echo "Dependencies installed."

# --- Create Directories ---
echo "Creating necessary directories..."
mkdir -p /etc/simple-proxy
echo "Directories created."

# --- Compile Source Code ---
echo "Compiling simple-proxy..."
gcc main.c -o simple-proxy -lconfig -pthread -std=c11
if [ $? -ne 0 ]; then
  echo "Compilation failed. Exiting."
  exit 1
fi
echo "Compilation successful."

# --- Install Files ---
echo "Copying files to system locations..."
cp config.cfg /etc/simple-proxy/config.cfg
cp simple-proxy /usr/bin/simple-proxy
cp simple-proxy.service /etc/systemd/system/simple-proxy.service
echo "Files copied."

# --- Systemd Setup ---
echo "Setting up systemd service..."
systemctl daemon-reload
systemctl enable simple-proxy
systemctl start simple-proxy
echo "Systemd service enabled and started."

echo "Installation complete. simple-proxy is running and will start on boot."
echo "You can check its status with: systemctl status simple-proxy"
