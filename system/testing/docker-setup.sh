#!/bin/bash
echo "🚀 Setting up Cyford Security Mail Stack..."

# Check .env file
echo "🔧 Checking configuration..."
cd /opt/cyford/security
if [ ! -f ".env" ]; then
    echo "❌ .env file not found. Please create it from .env.example"
    echo "ℹ️  Run: cp .env.example .env && edit .env with your credentials"
    exit 1
fi
echo "✅ .env file found"

# Setup permissions
echo "📋 Setting up permissions..."
php index.php --input_type=internal --command=setup-permissions

# Setup database
echo "🗄️ Setting up database..."
php index.php --input_type=internal --command=setup-database

# Configure Postfix
echo "📧 Configuring Postfix..."
postconf -e "myhostname = mail.cyford.local"
postconf -e "mydomain = cyford.local"
postconf -e "myorigin = \$mydomain"
postconf -e "inet_interfaces = all"
postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain"
postconf -e "home_mailbox = Maildir/"

# Configure Dovecot
echo "📬 Configuring Dovecot..."
echo "mail_location = maildir:~/Maildir" > /etc/dovecot/conf.d/10-mail.conf
echo "auth_mechanisms = plain login" > /etc/dovecot/conf.d/10-auth.conf
echo "passdb {" >> /etc/dovecot/conf.d/10-auth.conf
echo "  driver = passwd-file" >> /etc/dovecot/conf.d/10-auth.conf
echo "  args = /etc/dovecot/users" >> /etc/dovecot/conf.d/10-auth.conf
echo "}" >> /etc/dovecot/conf.d/10-auth.conf
echo "userdb {" >> /etc/dovecot/conf.d/10-auth.conf
echo "  driver = passwd" >> /etc/dovecot/conf.d/10-auth.conf
echo "}" >> /etc/dovecot/conf.d/10-auth.conf

# Configure SquirrelMail
echo "🌐 Configuring SquirrelMail..."
echo "<?php" > /etc/squirrelmail/config_local.php
echo "\$domain = 'cyford.local';" >> /etc/squirrelmail/config_local.php
echo "\$imapServerAddress = 'localhost';" >> /etc/squirrelmail/config_local.php
echo "\$imapPort = 143;" >> /etc/squirrelmail/config_local.php
echo "\$useSendmail = true;" >> /etc/squirrelmail/config_local.php
echo "\$sendmail_path = '/usr/sbin/sendmail';" >> /etc/squirrelmail/config_local.php
echo "?>" >> /etc/squirrelmail/config_local.php

# Setup Cyford Security integration
echo "🛡️ Integrating Cyford Security..."
php index.php --input_type=postfix --setup

echo "✅ Setup completed!"
echo ""
echo "📧 Mail Stack Ready:"
echo "  - SMTP: localhost:25"
echo "  - IMAP: localhost:143"
echo "  - POP3: localhost:110"
echo "  - SquirrelMail: http://localhost:8080/webmail"
echo ""
echo "👤 Create users with:"
echo "  php index.php --input_type=internal --command=create-user --username=test --password=pass"