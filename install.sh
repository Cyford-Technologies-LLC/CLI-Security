

# Add report-ip user to postfix group
sudo usermod -a -G postfix report-ip

# Make pickup directory group writable
sudo chmod g+w /var/spool/postfix/pickup

# Or alternatively, change ownership to allow report-ip user
sudo chown postfix:postfix /var/spool/postfix/pickup
sudo chmod 775 /var/spool/postfix/pickup




#  create a directory for the queue files
# Get the queue directory from postfix
QUEUE_DIR=$(postconf -h queue_directory)
echo "Postfix queue directory: $QUEUE_DIR"

# Create pickup directory
sudo mkdir -p $QUEUE_DIR/pickup
sudo chown postfix:postfix $QUEUE_DIR/pickup
sudo chmod 730 $QUEUE_DIR/pickup

# Add report-ip user to postfix group
sudo usermod -a -G postfix report-ip
# Make the pickup directory writable by the postfix group
sudo chmod 775 /var/spool/postfix/pickup

# Ensure report-ip user is in postfix group and restart to apply group changes
sudo usermod -a -G postfix report-ip

# Check current permissions
ls -la /var/spool/postfix/pickup

# Test if report-ip user can write to the directory
sudo -u report-ip touch /var/spool/postfix/pickup/test_file
sudo rm /var/spool/postfix/pickup/test_file
