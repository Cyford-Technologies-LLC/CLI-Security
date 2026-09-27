#!/bin/bash

# Initialize environment detection
source_env() {
    ENV_FILE="/tmp/cyford-security/env.txt"
    if [ -f "$ENV_FILE" ]; then
        source "$ENV_FILE"
    else
        # Create environment file
        mkdir -p /tmp/cyford-security
        if [ -f /.dockerenv ] || [ -n "$DOCKER_ENV" ]; then
            echo "docker=1" > "$ENV_FILE"
            docker=1
        else
            echo "docker=0" > "$ENV_FILE"
            docker=0
        fi
        chmod 644 "$ENV_FILE"
    fi
}

# Load environment
source_env

# Get the queue directory from postfix
QUEUE_DIR=$(postconf -h queue_directory)
echo "Postfix queue directory: $QUEUE_DIR"

# Create pickup directory if it doesn't exist
sudo mkdir -p $QUEUE_DIR/pickup
sudo chown postfix:postfix $QUEUE_DIR/pickup
sudo chmod 775 $QUEUE_DIR/pickup

# Add report-ip user to postfix group
sudo usermod -a -G postfix report-ip

# Create sudoers file for report-ip user (non-interactive)
# Create sudoers file for report-ip user (non-interactive)
sudo tee /etc/sudoers.d/report-ip-postfix > /dev/null << 'EOF'
# Allow report-ip user to run specific postfix commands without password
report-ip ALL=(ALL) NOPASSWD: /bin/cp /tmp/sec_* /var/spool/postfix/pickup/
report-ip ALL=(ALL) NOPASSWD: /bin/mv /tmp/sec_* /var/spool/postfix/pickup/
report-ip ALL=(ALL) NOPASSWD: /bin/chown postfix:postfix /var/spool/postfix/pickup/sec_*
report-ip ALL=(ALL) NOPASSWD: /bin/chmod 644 /var/spool/postfix/pickup/sec_*
report-ip ALL=(ALL) NOPASSWD: /bin/rm /tmp/sec_*
EOF


# Set proper permissions on sudoers file
sudo chmod 440 /etc/sudoers.d/report-ip-postfix

# Kill existing report-ip processes to apply group changes (skip in Docker)
if [ "$docker" != "1" ]; then
    sudo pkill -u report-ip || true
else
    echo "Skipping process kill in Docker environment"
fi

# Test the setup
echo "Testing sudoers configuration..."
sudo -u report-ip sudo -n cp /dev/null /tmp/test_sec_123 2>/dev/null && echo "Sudoers OK" || echo "Sudoers FAILED"

# Test pickup directory access
echo "Testing pickup directory access..."
if sudo -u report-ip touch $QUEUE_DIR/pickup/test_file 2>/dev/null; then
    echo "SUCCESS: report-ip user can write to pickup directory"
    sudo rm $QUEUE_DIR/pickup/test_file
else
    echo "FAILED: report-ip user cannot write to pickup directory"
    echo "Current permissions:"
    ls -la $QUEUE_DIR/pickup
    echo "User groups:"
    sudo -u report-ip groups
fi

echo "Setup complete."

# Check if we're in Docker and restart appropriately
if [ "$docker" = "1" ]; then
    echo "Docker environment detected - services managed by supervisor"
    echo "No manual restart needed"
else
    echo "Restart Postfix to ensure all changes take effect:"
    echo "sudo systemctl restart postfix"
    # Optionally restart automatically
    # sudo systemctl restart postfix
fi
