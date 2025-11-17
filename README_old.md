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

## **Quick Start Installation**

### **Automated Setup (Recommended)**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Cyford-Technologies-LLC/CLI-Security.git
   cd CLI-Security
   ```

2. **Run the setup script:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

   The setup script will:
   - ✅ Detect your operating system
   - ✅ Install Docker if needed
   - ✅ Set up system requirements
   - ✅ Guide you through deployment options

### **Deployment Options**

Choose your deployment method:

#### **🧪 Testing Environment (Development)**
- **Complete mail stack** in Docker
- **Includes:** Postfix + Dovecot + SquirrelMail
- **Perfect for:** Development and testing

```bash
cd system/testing
docker-compose up -d
docker exec cyford-mail ./docker-setup.sh
```

**Access:**
- Web: http://localhost:8081/webmail
- SMTP: localhost:25
- IMAP: localhost:143

#### **🏭 Live Production (Host Integration)**
- **Security system only** in Docker
- **Features:** Firewalld + Fail2Ban + Docker control
- **Integrates with:** External mail containers

```bash
cd system/live
docker-compose up -d
```

**Capabilities:**
- ✅ Control host firewalld
- ✅ Manage host fail2ban
- ✅ Connect to external Postfix containers
- ✅ Full Docker container management

#### **📖 Manual Installation (Traditional)**
- Direct host installation
- No Docker required

```bash
chmod +x install.sh
./install.sh
```

### **Manual Installation Steps**

If you prefer manual setup:

#### **Step 1: Install Docker (Optional but Recommended)**

**Ubuntu/Debian:**
```bash
# Remove old versions
sudo apt-get remove docker docker-engine docker.io containerd runc

# Install prerequisites
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg lsb-release

# Add Docker's GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Add repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add user to docker group
sudo usermod -aG docker $USER
```

**RHEL/CentOS/Rocky:**
```bash
# Install Docker
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf install docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

#### **Step 2: Install System Requirements**

**Ubuntu/Debian:**
```bash
sudo apt update && sudo apt install -y php-cli php-sqlite3 php-curl curl git unzip
```

**RHEL/CentOS/Rocky:**
```bash
sudo dnf install -y php-cli php-pdo php-curl curl git unzip
```

#### **Step 3: Clone and Setup**

```bash
# Clone repository
git clone https://github.com/Cyford-Technologies-LLC/CLI-Security.git
cd CLI-Security

# Install PHP dependencies (if using Composer)
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer
composer install

# Create system user
sudo useradd -r -s /bin/false report-ip

# Setup directories
sudo mkdir -p /opt/cyford/security /var/log/cyford-security
sudo chown -R report-ip:report-ip /var/log/cyford-security
```

## **Configuration**

Before running the project, configure it by editing `config.php` in the project directory. Open the file for manual
changes:
sh nano /opt/cyford/security/config.php

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
     flags=Rq user=report-ip argv=/usr/bin/php /opt/cyford/security/index.php --input_type=postfix --ips=${client_address} --categories=3
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

Configure spam handling in `/opt/cyford/security/config.php`:

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
   sudo chmod +x /opt/cyford/security/index.php
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

#### **Testing Environment Setup:**
```bash
# Navigate to testing directory
cd system/testing

# Start complete mail stack
docker-compose up -d --build

# Initialize services
docker exec cyford-mail ./docker-setup.sh

# Create test users
docker exec cyford-mail php /opt/cyford/security/index.php --input_type=internal --command=create-user --username=test --password=test123
```

#### **Live Production Setup:**
```bash
# Navigate to live directory
cd system/live

# Start security system
docker-compose up -d --build

# Check system status
docker exec cyford-security php /opt/cyford/security/index.php --input_type=internal --command=system-inventory
```

#### **Legacy Docker Generation (Deprecated):**
```bash
# Generate Dockerfile, docker-compose.yml, and setup scripts (old method)
php index.php --input_type=internal --command=create-docker
```

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

#### **Setup User Directory Permissions:**
```bash
# Configure user directories for postfix access (enables user_maildir quarantine)
php index.php --input_type=internal --command=setup-user-permissions --username=testuser
```

**Permission setup includes:**
- 👥 Adds postfix user to user's group
- 🏠 Sets group permissions on home directory
- 📁 Configures maildir for postfix access
- 📧 Creates spam folder with proper permissions
- ✅ Enables user maildir quarantine method

#### **Setup Dovecot Sieve Spam Rules:**
```bash
# Configure automatic spam filtering rules for users
php index.php --input_type=internal --command=setup-sieve-rules --username=testuser
```

**Sieve rules setup includes:**
- 📧 Creates Dovecot Sieve spam filtering rules
- 🔄 Automatically moves X-Spam flagged emails to Spambox
- 📁 Creates spam folders if they don't exist
- ✅ Compiles and activates Sieve scripts
- 🔄 Reloads Dovecot configuration

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

# 4. Setup user directory permissions (for user_maildir quarantine)
php index.php --input_type=internal --command=setup-user-permissions --username=admin

# 5. Setup Dovecot Sieve spam filtering rules
php index.php --input_type=internal --command=setup-sieve-rules --username=admin

# 6. Test system
php index.php --input_type=internal --command=stats
```

#### **For Docker Development (Testing Environment):**
```bash
# 1. Navigate to testing environment
cd system/testing

# 2. Start services
docker-compose up -d --build

# 3. Setup inside container
docker exec cyford-mail ./docker-setup.sh

# 4. Create test users
docker exec cyford-mail php /opt/cyford/security/index.php --input_type=internal --command=create-user --username=test --password=test123

# 5. Access webmail: http://localhost:8081/webmail
```

#### **For Docker Production (Live Environment):**
```bash
# 1. Navigate to live environment
cd system/live

# 2. Start security system
docker-compose up -d --build

# 3. Verify host integration
docker exec cyford-security php /opt/cyford/security/index.php --input_type=internal --command=system-inventory

# 4. Test firewalld access
docker exec cyford-security firewall-cmd --state

# 5. Test fail2ban access
docker exec cyford-security fail2ban-client status
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

### **X-Spam Headers (Default Method)**

CLI-Security now uses **X-Spam headers** as the default spam handling method, following industry standards like SpamAssassin.

#### **How X-Spam Headers Work:**
```php
'spam_handling' => [
    'action' => 'headers', // Adds X-Spam headers instead of quarantining
],
```

**Headers Added to Spam Emails:**
```
X-Spam-Flag: YES
X-Spam-Checker-Version: Cyford Web Armor 1.0
X-Spam-Level: ****
X-Spam-Score: 7.0
X-Spam-Status: Yes, score=7.0 required=5.0 tests=CYFORD_SPAM
Subject: ***SPAM*** Original Subject
```

**Benefits:**
- ✅ **No Permission Issues** - No file system operations required
- ✅ **Standard Approach** - Compatible with all email clients and servers
- ✅ **User Control** - Users can configure their own spam handling rules
- ✅ **Dovecot Integration** - Works seamlessly with Sieve filtering rules
- ✅ **Chroot Compatible** - Works in restricted Postfix environments

**Setup Automatic Spam Filtering:**
```bash
# Setup Sieve rules to automatically move spam to spam folder
php index.php --input_type=internal --command=setup-sieve-rules --username=all
```

### **Quarantine Configuration**

CLI-Security supports two quarantine methods for spam emails:

#### **Method 1: User Maildir (Recommended)**
```php
'quarantine_method' => 'user_maildir',
'maildir_path' => '/home/{user}/Maildir-cyford',
```

**Setup:**
```bash
# Configure user directory permissions
php index.php --input_type=internal --command=setup-user-permissions --username=allen
```

**Benefits:**
- ✅ **Email Client Integration** - Spam folder appears in user's email client
- ✅ **User Management** - Users can view, move, and delete quarantined emails
- ✅ **Standard Maildir** - Compatible with IMAP/POP3 protocols
- ✅ **Proper Organization** - Spam stored in user's mailbox structure

#### **Method 2: System Quarantine**
```php
'quarantine_method' => 'system_quarantine',
'system_quarantine_path' => '/var/spool/postfix/quarantine',
```

**Benefits:**
- ✅ **Chroot Compatible** - Works in restricted Postfix environments
- ✅ **No Setup Required** - Works out of the box
- ✅ **Admin Managed** - Centralized spam storage
- ✅ **Always Accessible** - No user directory dependencies

**Access quarantined emails:**
```bash
# View user's quarantined spam
ls -la /var/spool/postfix/quarantine/username/

# Move to user's maildir if needed
cp /var/spool/postfix/quarantine/username/*.spam /home/username/Maildir/.Spam/new/
```

---

## **Docker Environments**

CLI-Security provides two Docker deployment options:

### **Testing Environment** (`system/testing/`)

**Complete mail stack for development:**

```bash
cd system/testing
docker-compose up -d
docker exec cyford-mail ./docker-setup.sh
```

**Includes:**
- 📧 **Postfix** - SMTP server with Cyford Security integration
- 📬 **Dovecot** - IMAP/POP3 server for email retrieval
- 🌐 **SquirrelMail** - Web-based email client
- 🔒 **Cyford Security** - Advanced spam filtering and protection
- 🐘 **PHP 8.1** - With SQLite support for database operations

**Access Points:**
- **SquirrelMail:** http://localhost:8081/webmail
- **SMTP:** localhost:25
- **IMAP:** localhost:143
- **POP3:** localhost:110

**Create Test User:**
```bash
docker exec cyford-mail php /opt/cyford/security/index.php --input_type=internal --command=create-user --username=test --password=test123
```

### **Live Production Environment** (`system/live/`)

**Security system with host integration:**

```bash
cd system/live
docker-compose up -d
```

**Features:**
- 🛡️ **Host Firewalld Control** - Direct firewall management
- 🚫 **Host Fail2Ban Integration** - Intrusion prevention
- 🐳 **Docker Container Management** - Control other containers
- 📧 **External Postfix Integration** - Connect to mail containers
- 📊 **System Monitoring** - Comprehensive logging and stats

**Host Integration:**
- **Privileged access** to host system services
- **Docker socket** for container management
- **Network host mode** for direct system access
- **Volume mounts** for configuration and logs

**Check System Status:**
```bash
docker exec cyford-security php /opt/cyford/security/index.php --input_type=internal --command=stats
```

### **Docker Features**

- ✅ **One-Command Setup** - Complete deployment in minutes
- ✅ **Pre-configured Services** - All components work together
- ✅ **Persistent Storage** - Data survives container restarts
- ✅ **Host Integration** - Live system controls host services
- ✅ **Development Ready** - Testing environment for development

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


