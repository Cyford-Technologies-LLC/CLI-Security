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
docker compose up -d
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
docker compose up -d
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

## **Docker Environments**

CLI-Security provides two Docker deployment options:

### **Testing Environment** (`system/testing/`)

**Complete mail stack for development:**

```bash
cd system/testing
docker compose up -d
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
docker compose up -d
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

### **Docker Environment Commands**

#### **Testing Environment Setup:**
```bash
# Navigate to testing directory
cd system/testing

# Start complete mail stack
docker compose up -d --build

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
docker compose up -d --build

# Check system status
docker exec cyford-security php /opt/cyford/security/index.php --input_type=internal --command=system-inventory
```

#### **For Docker Development (Testing Environment):**
```bash
# 1. Navigate to testing environment
cd system/testing

# 2. Start services
docker compose up -d --build

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
docker compose up -d --build

# 3. Verify host integration
docker exec cyford-security php /opt/cyford/security/index.php --input_type=internal --command=system-inventory

# 4. Test firewalld access
docker exec cyford-security firewall-cmd --state

# 5. Test fail2ban access
docker exec cyford-security fail2ban-client status
```

---

*[Rest of README content remains the same...]*