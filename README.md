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

To integrate CLI-Security with Postfix for email filtering, perform the following steps:

1. **Edit the `main.cf` Configuration File**:
   ```sh
   sudo nano /etc/postfix/main.cf
   ```
   Add the content filter:
   ```
   content_filter = security-filter:dummy
   ```

2. **Edit the `master.cf` Configuration File**:
   ```sh
   sudo nano /etc/postfix/master.cf
   ```
   Add the following filter configuration:
   ```
   security-filter unix - n n - - pipe
     flags=Rq user=report-ip argv=/usr/local/bin/cyford-report --ips=${client_address} --categories=3
   ```

3. **Restart Postfix**:
   ```sh
   sudo systemctl restart postfix
   ```

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





