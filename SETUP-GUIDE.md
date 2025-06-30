# Cyford Web Armor - Complete Setup Guide

## Mission: Send messages with marked spam headers to the destined spam directory

This guide will help you set up the complete email security system that automatically moves spam emails to spam folders using Sieve filtering.

## 🚀 Quick Start (Auto-Configuration)

For a complete automated setup, run:

```bash
# Enable auto-configuration in config.php first
# Set 'allow_modification' => true

# Run complete auto-configuration
php autoconfig.php
```

This will automatically:
- Configure Postfix with IP-based filtering
- Set up Dovecot with Sieve support
- Create spam filtering rules for all users
- Set proper permissions
- Initialize database
- Test the complete system

## 📋 Manual Setup Steps

If you prefer manual setup or need to troubleshoot:

### Step 1: Basic System Setup

```bash
# Setup permissions and database
php index.php --input_type=internal --command=setup-permissions
php index.php --input_type=internal --command=setup-database
```

### Step 2: Configure Postfix

```bash
# This will configure Postfix for IP-based filtering
# Your system already does this automatically when processing emails
```

### Step 3: Setup Dovecot Sieve

```bash
# Complete Dovecot Sieve setup (install, configure, permissions)
php setup-dovecot-sieve.php --command=setup

# Or use the internal command
php index.php --input_type=internal --command=setup-dovecot-sieve
```

### Step 4: Setup User Permissions

```bash
# Setup permissions for all users
php index.php --input_type=internal --command=setup-user-permissions --username=all

# Or for a specific user
php index.php --input_type=internal --command=setup-user-permissions --username=allen
```

### Step 5: Setup Sieve Rules

```bash
# Setup Sieve spam filtering rules for all users
php setup-sieve-rules.php --command=setup

# Or use the internal command
php index.php --input_type=internal --command=setup-sieve-rules --username=all

# For a specific user
php index.php --input_type=internal --command=setup-sieve-rules --username=allen
```

## 🔧 Configuration

### Enable Auto-Configuration

In `config.php`, set:

```php
'postfix' => [
    'allow_modification' => true,  // Enable automatic configuration
    'spam_handling' => [
        'action' => 'headers',  // Add spam headers (required for Sieve)
        'quarantine_method' => 'user_maildir',  // Use user's maildir
        'quarantine_folder' => 'Spam',  // Spam folder name
    ],
],
```

### Current System Status

Based on your logs, your system is currently:
- ✅ Detecting spam correctly
- ✅ Adding X-Spam headers
- ❌ **Missing**: Sieve rules to move emails to spam folders

## 🧪 Testing

### Test Spam Detection

```bash
# Test the spam filter
php index.php --input_type=internal --command=test-spam-filter --subject="Test" --body="spam content"
```

### Test Complete System

```bash
# Send a test email and check if it goes to spam folder
# Your current logs show spam detection is working
# After setup, emails should go to Spambox folder
```

### Check System Status

```bash
# View system statistics
php index.php --input_type=internal --command=stats

# Check Sieve rules status
php setup-sieve-rules.php --command=status

# Check Dovecot Sieve status
php setup-dovecot-sieve.php --command=status
```

## 📧 User Management

### Create Mail Users

```bash
# Create a test user
php index.php --input_type=internal --command=create-user --username=testuser --password=testpass
```

### Check User Sieve Rules

```bash
# Test Sieve rules for a user
php setup-sieve-rules.php --command=test --user=allen
```

## 🔍 Troubleshooting

### Current Issue Analysis

From your logs, I can see:
1. ✅ Spam detection is working: "WARNING: Email flagged as spam. Reason: Spam patterns detected in the body."
2. ✅ X-Spam headers are being added: "Adding X-Spam headers and delivering email."
3. ❌ **Problem**: Emails are not being moved to spam folders because Sieve rules are not set up

### Fix the Issue

Run the auto-configuration:

```bash
php autoconfig.php
```

Or manually:

```bash
# 1. Setup Dovecot Sieve
php setup-dovecot-sieve.php --command=setup

# 2. Setup user permissions
php index.php --input_type=internal --command=setup-user-permissions --username=all

# 3. Setup Sieve rules
php setup-sieve-rules.php --command=setup
```

### Verify Fix

After setup, your Sieve rules will look like this:

```sieve
# Cyford Web Armor Spam Filtering Rules
require ["fileinto", "mailbox"];

# Move emails marked as spam by Cyford Web Armor
if header :contains "X-Spam-Flag" "YES" {
    if not mailboxexists "Spambox" {
        mailboxcreate "Spambox";
    }
    fileinto "Spambox";
    stop;
}
```

### Check Logs

```bash
# Application logs
tail -f /var/log/cyford-security/application.log

# Spam logs
tail -f /var/log/cyford-security/spam.log

# System mail logs
tail -f /var/log/maillog
```

## 📁 File Structure

```
CLI-Security/
├── autoconfig.php              # Complete auto-configuration
├── setup-dovecot-sieve.php    # Dovecot Sieve setup
├── setup-sieve-rules.php      # Sieve rules setup
├── config.php                 # Main configuration
├── src/Classes/
│   ├── Postfix.php            # Postfix integration
│   ├── SpamFilter.php         # Spam detection
│   ├── Internal.php           # Internal commands
│   └── Systems.php            # System utilities
└── test/ai                    # Your AI notes
```

## 🎯 Mission Success Criteria

After setup, your system will:

1. ✅ Receive emails via Postfix
2. ✅ Process through security filter
3. ✅ Detect spam patterns
4. ✅ Add X-Spam-Flag: YES headers
5. ✅ **NEW**: Sieve rules move spam to Spambox folder
6. ✅ Clean emails go to INBOX
7. ✅ All actions are logged

## 🚨 Important Notes

1. **Backup First**: The system will backup configurations before making changes
2. **Test Environment**: Consider testing in Docker first
3. **User Permissions**: Postfix user needs access to user maildirs
4. **Sieve Compilation**: Scripts are automatically compiled
5. **Logging**: All actions are logged for debugging

## 🐳 Docker Testing Environment

Create a complete testing environment:

```bash
php index.php --input_type=internal --command=create-docker
docker-compose up -d
docker exec -it cyford-mail ./docker-setup.sh
```

## 📞 Support Commands

```bash
# View all available commands
php index.php --input_type=internal --command=help

# Check system status
php setup-dovecot-sieve.php --command=status
php setup-sieve-rules.php --command=status

# View spam patterns
php index.php --input_type=internal --command=view-spam-patterns

# Reload configurations
php index.php --input_type=internal --command=reload-lists
```

---

## 🎉 Success!

Once setup is complete, your mission will be accomplished:
**Messages with marked spam headers will be automatically sent to the destined spam directory!**

The system respects your complete config.php settings and provides comprehensive logging for all aspects of the operation.