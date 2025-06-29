# CLI-Security

CLI-Security is a PHP-based API solution for managing and reporting IPs from security systems. It integrates with your
firewall, Fail2Ban, and Postfix to provide a secure and automated reporting framework.

##  THIS SCRIPT IS IN BETA.    CREATED 06/25/2025  //  AND IS AN EXTENSION OF https://www.cyfordtechnologies.com/webarmor.php

## **System Requirements**

- **Operating System**: Debian-based distributions (Ubuntu, Debian) or RHEL-based distributions (CentOS, Fedora).
- **PHP Version**: PHP 8+.
- **Dependencies**:
    - PHP CLI
    - Composer
    - cURL
    - Postfix (optional for email integration)

---

## **Installation Instructions**

### **Step 1: Install Required Software**

Make sure your system is updated and has the required dependencies installed.

For Debian/Ubuntu:
sudo apt update && sudo apt install php-cli unzip curl git -y

For Red Hat-based systems (RHEL/CentOS/Fedora):
sudo yum install php-cli unzip curl git -y

### **2. Install Composer**

Install Composer (PHP dependency manager):
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer/usr/local/bin/composer

Verify Composer installation:

Verify Composer installation:

### **3. Clone the Repository**

1. Clone the CLI-Security repository to your system:
   ```sh
   sudo git clone https://github.com/Cyford-Technologies-LLC/CLI-Security.git /usr/local/share/cyford/security
   ```

2. Navigate into the project directory:
   ```sh
   cd /usr/local/share/cyford/security
   ```

3. Install PHP dependencies using Composer:
   ```sh
   composer install
   ```

### **4. Set up Symlinks**

Create a symlink for easier and global execution of the script:
sh sudo ln -s /usr/local/share/cyford/security/index.php /usr/local/bin/cyford-report sudo chmod +x
/usr/local/share/cyford/security/index.php

You can now run the script from anywhere using:
sh cyford-report

## **Configuration**

Before running the project, configure it by editing `config.php` in the project directory. Open the file for manual
changes:
sh nano /usr/local/share/cyford/security/config.php

### **Configurable Fields in `config.php`**

1. **API Login & Report Endpoints**:
    - `api.login_endpoint`: The API login endpoint.
    - `api.report_endpoint`: The API report endpoint.
2. **Credentials**:
    - `credentials.email`: Your email used for the API.
    - `credentials.password`: Your password used for the API.
3. **Error Reporting** (optional):
    - Set `errors.report_errors` to `1` to enable detailed error output.

Save the file after making changes.

---

## **Running the Script**

To report IPs to the API, use the following syntax:
sh cyford-report --ips=<comma-separated-IPs> --categories=<comma-separated-categories>

### **Arguments**

1. `--ips`: A comma-separated list of IP addresses to report.
2. `--categories`: A comma-separated list of categories for the report.

**Example:**
sh cyford-report --ips=192.168.1.1,127.0.0.1 --categories=3,5




---

## **Integrations**

### **Postfix Integration**

CLI-Security provides **automatic Postfix configuration** and **manual setup** options for email security filtering.

#### **Option 1: Automatic Configuration (Recommended)**

Run the script once to automatically configure Postfix:
```sh
cyford-report --input_type=manual
```

The script will:
- Detect your server's public IP address
- Configure IP-based SMTP filtering
- Create backups of your configuration files
- Set up spam handling according to your config

#### **Option 2: Manual Configuration**

If you prefer manual setup or need to troubleshoot:

1. **Get your server's public IP address**:
   ```sh
   curl ifconfig.me
   ```

2. **Edit the `master.cf` Configuration File**:
   ```sh
   sudo nano /etc/postfix/master.cf
   ```
   
   Add these entries (replace `YOUR_PUBLIC_IP` with your actual IP):
   ```
   # External SMTP (with content filter for security)
   YOUR_PUBLIC_IP:smtp inet  n       -       n       -       -       smtpd
     -o content_filter=security-filter:dummy
   
   # Internal SMTP (no content filter)
   127.0.0.1:smtp inet  n       -       n       -       -       smtpd
     -o smtpd_client_restrictions=permit_mynetworks,reject
     -o content_filter=
   
   # Security filter service
   security-filter unix - n n - - pipe
     flags=Rq user=report-ip argv=/usr/bin/php /usr/local/share/cyford/security/index.php --input_type=postfix --ips=${client_address} --categories=3
   ```

3. **Remove any old global content_filter from main.cf** (if present):
   ```sh
   sudo nano /etc/postfix/main.cf
   ```
   Remove or comment out this line if it exists:
   ```
   # content_filter = security-filter:dummy
   ```

4. **Restart Postfix**:
   ```sh
   sudo systemctl restart postfix
   ```

#### **Spam Handling Configuration**

Configure spam handling in `/usr/local/share/cyford/security/config.php`:

```php
'postfix' => [
    'spam_handling' => [
        'action' => 'quarantine', // Options: 'reject', 'quarantine', 'allow'
        'bounce_message' => 'Your message has been rejected due to spam content.',
        'quarantine_folder' => 'Spam', // Folder name for spam emails
        'add_footer' => true, // Add footer to clean emails
        'footer_text' => '\n\n--- Scanned by Cyford Security Filter ---',
    ],
],
```

**Spam Actions:**
- `reject`: Bounce spam back to sender with custom message
- `quarantine`: Move spam to user's spam folder (creates folder if needed)
- `allow`: Let spam through with warning footer

#### **Verification**

Test your configuration:
1. Send a test email to your server
2. Check logs: `sudo tail -f /var/log/cyford-security/application.log`
3. Verify email delivery: `sudo tail -f /var/log/mail.log`

You should see:
- External emails processed by security filter
- Clean emails delivered to inbox
- Spam handled according to your configuration

### **Firewall Integration**

The `Firewall` functionality allows managing firewall rules directly from the script.

- **Add Rule**:
  ```sh
  cyford-report add-rule="<firewall-rule>"
  ```

- **Remove Rule**:
  ```sh
  cyford-report remove-rule="<firewall-rule>"
  ```

- **Check Firewall Status**:
  ```sh
  cyford-report firewall-status
  ```

---

## **Troubleshooting**

### **1. Debug Mode for Errors**

To troubleshoot errors, enable detailed error reporting in `config.php`:

php 'errors' => [ 'report_errors' => 1, ],

### **2. Common Problems**

- **Permission Issues**:
  Ensure files and scripts are executable:
   ```sh
   sudo chmod +x /usr/local/share/cyford/security/index.php
   ```

- **Postfix Configuration Fails**:
  Check logs for details:
   ```sh
   sudo tail -f /var/log/mail.log
   ```

---

## **Internal Commands**

CLI-Security includes comprehensive built-in management commands for setup, monitoring, user management, and Docker deployment.

### **System Setup Commands**

#### **Complete Permission Setup (Recommended First Step):**
```bash
# Setup all system permissions, sudoers rules, and directory structure
php index.php --input_type=internal --command=setup-permissions
```

**What setup-permissions does:**
- ✅ Creates sudoers rule for report-ip user
- ✅ Sets up log directories with proper permissions
- ✅ Configures database directory and permissions
- ✅ Initializes whitelist/blacklist files
- ✅ Sets project directory permissions

#### **Database Setup:**
```bash
# Initialize database with proper permissions (run after setup-permissions)
php index.php --input_type=internal --command=setup-database

# Test database connectivity
php index.php --input_type=internal --command=test-database
```

### **Docker Environment Commands**

#### **Create Complete Docker Mail Stack:**
```bash
# Generate Dockerfile, docker-compose.yml, and setup scripts
php index.php --input_type=internal --command=create-docker
```

**Creates:**
- 🐳 **Dockerfile** - Ubuntu with Postfix, Dovecot, PHP, SquirrelMail
- 🐳 **docker-compose.yml** - Service orchestration
- 🐳 **docker-setup.sh** - Automated configuration script

### **User Management Commands**

#### **Create Mail Users:**
```bash
# Create new mail user with system account and maildir
php index.php --input_type=internal --command=create-user --username=testuser --password=securepass
```

**User creation includes:**
- 👤 System user account creation
- 📧 Postfix virtual user configuration
- 📬 Dovecot authentication setup
- 📁 Maildir structure with Spam folder
- 🔐 Proper permissions and ownership

### **Spam Pattern Management**

#### **View and Manage Spam Patterns:**
```bash
# View recent spam patterns
php index.php --input_type=internal --command=view-spam-patterns --limit=20

# Remove specific spam pattern
php index.php --input_type=internal --command=clear-spam-pattern --pattern_id=123
```

### **System Monitoring**

#### **Statistics and System Health:**
```bash
# Show comprehensive system statistics
php index.php --input_type=internal --command=stats

# Reload whitelist/blacklist files
php index.php --input_type=internal --command=reload-lists
```

### **Testing and Debugging Tools**

#### **Spam Filter Testing:**
```bash
# Test spam filter with sample content
php index.php --input_type=internal --command=test-spam-filter --subject="Hello" --body="Test message"

# Show all available commands
php index.php --input_type=internal --command=help
```

### **Complete Setup Workflow**

#### **For Production Deployment:**
```bash
# 1. Setup all permissions and directories
php index.php --input_type=internal --command=setup-permissions

# 2. Initialize database
php index.php --input_type=internal --command=setup-database

# 3. Create mail users
php index.php --input_type=internal --command=create-user --username=admin --password=securepass

# 4. Test system
php index.php --input_type=internal --command=stats
```

#### **For Docker Development:**
```bash
# 1. Create Docker environment
php index.php --input_type=internal --command=create-docker

# 2. Start services
docker-compose up -d

# 3. Setup inside container
docker exec -it cyford-mail ./docker-setup.sh

# 4. Create test users
docker exec -it cyford-mail php /usr/local/share/cyford/security/index.php --input_type=internal --command=create-user --username=test --password=test123
```

### **Hash-Based Spam Detection**

The system includes advanced hash-based spam detection that:
- **Learns spam patterns** automatically
- **Blocks duplicate spam** instantly
- **Improves performance** over time
- **Persists across reboots**

**Enable in config.php:**
```php
'spam_handling' => [
    'hash_detection' => true,
    'hash_threshold' => 3, // Block after X identical emails
],
```

**Note:** Run `setup-database` command first to initialize the SQLite database with proper permissions.

---

## **Docker Environment**

CLI-Security includes a complete Docker-based mail server environment for testing and development.

### **Quick Start with Docker**

#### **1. Create Docker Environment:**
```bash
php index.php --input_type=internal --command=create-docker
```

#### **2. Start Services:**
```bash
docker-compose up -d
```

#### **3. Setup Mail Stack:**
```bash
docker exec -it cyford-mail ./docker-setup.sh
```

#### **4. Access Services:**
- **SquirrelMail (Webmail):** http://localhost:8080/webmail
- **SMTP Server:** localhost:25
- **IMAP Server:** localhost:143
- **POP3 Server:** localhost:110

### **Included Services**

- **📧 Postfix** - SMTP server with Cyford Security integration
- **📬 Dovecot** - IMAP/POP3 server for email retrieval
- **🌐 SquirrelMail** - Web-based email client
- **🔒 Cyford Security** - Advanced spam filtering and protection
- **🛡️ Fail2Ban** - Intrusion prevention system
- **🐘 PHP 8.1** - With SQLite support for database operations

### **Docker Features**

- **One-Command Setup** - Complete mail server in minutes
- **Pre-configured Services** - All components work together seamlessly
- **Persistent Storage** - Email data survives container restarts
- **Web Interface** - Easy email testing via SquirrelMail
- **Development Ready** - Perfect for testing spam filters and mail flows

---

## **User Management**

CLI-Security provides built-in user management for mail servers with integrated Postfix and Dovecot support.

### **Create Mail Users**

```bash
# Create a new mail user
php index.php --input_type=internal --command=create-user --username=testuser --password=securepass
```

### **What User Creation Does**

1. **✅ Creates System User** - Linux user account with home directory
2. **✅ Sets Password** - For both system and email authentication
3. **✅ Creates Maildir Structure** - Including Spam quarantine folder
4. **✅ Configures Postfix** - Adds user to virtual user mapping
5. **✅ Configures Dovecot** - Sets up IMAP/POP3 authentication
6. **✅ Sets Permissions** - Proper ownership for mail directories

### **User Features**

- **📧 Email Account** - Full SMTP/IMAP/POP3 access
- **🗂️ Spam Folder** - Quarantined emails accessible via email client
- **🔐 Secure Authentication** - Encrypted password storage
- **📱 Multi-Client Support** - Works with any email client
- **🌐 Webmail Access** - Login via SquirrelMail interface

### **Example Usage**

```bash
# Create test user
php index.php --input_type=internal --command=create-user --username=john --password=mypassword

# User can now:
# - Send/receive emails: john@yourdomain.com
# - Access via IMAP: john / mypassword
# - Login to webmail: http://localhost:8080/webmail
# - View spam folder in email client
```

### **Coming Soon**

- **User Deletion** - Remove users and clean up mail data
- **Password Reset** - Change user passwords
- **Quota Management** - Set mailbox size limits
- **Alias Management** - Create email aliases and forwards
- **Bulk User Import** - CSV-based user creation
- **User Statistics** - Mail usage and spam statistics per user

---

## **Contributing**

We welcome contributions to improve the script or add new features. You can:

- Report bugs.
- Request features.
- Submit pull requests.

Visit the repository: [GitHub Repository](https://github.com/Cyford-Technologies-LLC/CLI-Security)

---

## **License**

This project is licensed under the [MIT License](LICENSE).

For support, please contact [support@cyfordtechnologies.com](mailto:support@cyfordtechnologies.com).



####

I had to add rule to polkit  for rocky os 9
[root@CT-MAIL-00 security]#    sudo nano /etc/polkit-1/rules.d/50-report-ip.rules
polkit.addRule(function(action, subject) {
if (action.id === "org.freedesktop.systemd1.manage-units" &&
subject.user === "report-ip") {
return polkit.Result.YES;
}
});
[root@CT-MAIL-00 security]#    sudo systemctl restart polkit


