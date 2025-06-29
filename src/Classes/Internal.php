<?php
namespace Cyford\Security\Classes;

class Internal
{
    private array $config;
    private $logger;

    public function __construct(array $config, $logger = null)
    {
        $this->config = $config;
        $this->logger = $logger;
    }

    /**
     * Process internal commands
     */
    public function processCommand(array $args): void
    {
        $command = $args['command'] ?? '';
        
        switch ($command) {
            case 'setup-database':
                $this->setupDatabase();
                break;
                
            case 'test-database':
                $this->testDatabase();
                break;
                
            case 'view-spam-patterns':
                $this->viewSpamPatterns($args['limit'] ?? 20);
                break;
                
            case 'clear-spam-pattern':
                $this->clearSpamPattern($args['pattern_id'] ?? 0);
                break;
                
            case 'stats':
                $this->showStats();
                break;
                
            case 'test-spam-filter':
                $this->testSpamFilter($args['subject'] ?? '', $args['body'] ?? '');
                break;
                
            case 'reload-lists':
                $this->reloadLists();
                break;
                
            case 'setup-permissions':
                $this->setupPermissions();
                break;
                
            case 'create-docker':
                $this->createDockerEnvironment();
                break;
                
            case 'create-user':
                $this->createUser($args['username'] ?? '', $args['password'] ?? '');
                break;
                
            default:
                $this->showHelp();
        }
    }

    /**
     * Setup database with proper permissions
     */
    private function setupDatabase(): void
    {
        echo "Setting up Cyford Security Database...\n";
        
        try {
            $database = new Database($this->config);
            echo "✅ Database created successfully at: " . $this->config['database']['path'] . "\n";
            
            // Set proper permissions for Postfix user
            $dbPath = $this->config['database']['path'];
            $dbDir = dirname($dbPath);
            
            exec("sudo chown postfix:postfix " . escapeshellarg($dbPath));
            exec("sudo chmod 664 " . escapeshellarg($dbPath));
            exec("sudo chown postfix:postfix " . escapeshellarg($dbDir));
            exec("sudo chmod 755 " . escapeshellarg($dbDir));
            
            echo "✅ Database permissions set for Postfix user\n";
            
            // Test functionality
            $database->setCache('setup_test', 'success', 60);
            $testValue = $database->getCache('setup_test');
            
            if ($testValue === 'success') {
                echo "✅ Database functionality test passed\n";
                echo "🎉 Database setup complete!\n";
            } else {
                echo "❌ Database functionality test failed\n";
            }
            
        } catch (\Exception $e) {
            echo "❌ Database setup failed: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Test database connection and functionality
     */
    private function testDatabase(): void
    {
        try {
            $database = new Database($this->config);
            echo "✅ Database connection successful\n";
            
            // Test cache
            $database->setCache('test_key', 'test_value', 60);
            $value = $database->getCache('test_key');
            echo $value === 'test_value' ? "✅ Cache test passed\n" : "❌ Cache test failed\n";
            
            // Test spam patterns
            $patterns = $database->getBlockedSpamPatterns(5);
            echo "📊 Found " . count($patterns) . " spam patterns in database\n";
            
        } catch (\Exception $e) {
            echo "❌ Database test failed: " . $e->getMessage() . "\n";
        }
    }

    /**
     * View spam patterns
     */
    private function viewSpamPatterns(int $limit): void
    {
        try {
            $database = new Database($this->config);
            $patterns = $database->getBlockedSpamPatterns($limit);
            
            echo "📋 Spam Patterns (showing $limit):\n";
            echo str_repeat("-", 80) . "\n";
            
            foreach ($patterns as $pattern) {
                echo "ID: {$pattern['id']}\n";
                echo "Subject: {$pattern['sample_subject']}\n";
                echo "Body Preview: " . substr($pattern['sample_body_preview'], 0, 100) . "...\n";
                echo "Count: {$pattern['count']} | First: {$pattern['first_seen']} | Last: {$pattern['last_seen']}\n";
                echo str_repeat("-", 80) . "\n";
            }
            
        } catch (\Exception $e) {
            echo "❌ Failed to view spam patterns: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Clear specific spam pattern
     */
    private function clearSpamPattern(int $patternId): void
    {
        if ($patternId <= 0) {
            echo "❌ Invalid pattern ID\n";
            return;
        }
        
        try {
            $database = new Database($this->config);
            if ($database->removeSpamPattern($patternId)) {
                echo "✅ Spam pattern $patternId removed successfully\n";
            } else {
                echo "❌ Failed to remove spam pattern $patternId\n";
            }
            
        } catch (\Exception $e) {
            echo "❌ Failed to clear spam pattern: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Show system statistics
     */
    private function showStats(): void
    {
        try {
            $database = new Database($this->config);
            
            // Spam pattern stats
            $patternStats = $database->getSpamPatternStats();
            echo "📊 Spam Pattern Statistics:\n";
            echo "  Total Patterns: " . ($patternStats['total_patterns'] ?? 0) . "\n";
            echo "  Total Blocked Emails: " . ($patternStats['total_blocked_emails'] ?? 0) . "\n";
            echo "  Average Blocks per Pattern: " . round($patternStats['avg_blocks_per_pattern'] ?? 0, 2) . "\n";
            echo "  Max Blocks (Single Pattern): " . ($patternStats['max_blocks_single_pattern'] ?? 0) . "\n";
            echo "\n";
            
            // Email stats
            $emailStats = $database->getSpamStats(7);
            echo "📈 Email Statistics (Last 7 Days):\n";
            foreach ($emailStats as $stat) {
                echo "  {$stat['date']}: Total={$stat['total_emails']}, Spam={$stat['spam_emails']}, Clean={$stat['clean_emails']}\n";
            }
            
        } catch (\Exception $e) {
            echo "❌ Failed to get statistics: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Test spam filter with sample content
     */
    private function testSpamFilter(string $subject, string $body): void
    {
        if (empty($subject) && empty($body)) {
            echo "❌ Please provide --subject and/or --body parameters\n";
            return;
        }
        
        try {
            $spamFilter = new SpamFilter($this->config);
            $headers = ['Subject' => $subject];
            
            $isSpam = $spamFilter->isSpam($headers, $body);
            $reason = $spamFilter->getLastSpamReason();
            
            echo "🔍 Spam Filter Test Results:\n";
            echo "Subject: $subject\n";
            echo "Body: " . substr($body, 0, 100) . (strlen($body) > 100 ? "..." : "") . "\n";
            echo "Result: " . ($isSpam ? "🚫 SPAM" : "✅ CLEAN") . "\n";
            if ($isSpam && $reason) {
                echo "Reason: $reason\n";
            }
            
        } catch (\Exception $e) {
            echo "❌ Spam filter test failed: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Reload whitelist/blacklist files
     */
    private function reloadLists(): void
    {
        echo "🔄 Reloading whitelist and blacklist files...\n";
        
        $lists = [
            'Whitelist IPs' => $this->config['whitelist']['ips_file'],
            'Whitelist Domains' => $this->config['whitelist']['domains_file'],
            'Whitelist Emails' => $this->config['whitelist']['emails_file'],
            'Blacklist IPs' => $this->config['blacklist']['ips_file'],
            'Blacklist Domains' => $this->config['blacklist']['domains_file'],
            'Blacklist Emails' => $this->config['blacklist']['emails_file'],
        ];
        
        foreach ($lists as $name => $file) {
            if (file_exists($file)) {
                $lines = count(file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
                echo "✅ $name: $lines entries loaded\n";
            } else {
                echo "❌ $name: File not found ($file)\n";
            }
        }
        
        // Clear alias cache
        $systems = new Systems();
        $systems->clearAliasCache();
        echo "✅ Alias cache cleared\n";
    }

    /**
     * Setup all permissions for report-ip user
     */
    private function setupPermissions(): void
    {
        echo "🔧 Setting up permissions for Cyford Security...\n";
        
        try {
            // 1. Create sudoers rule
            echo "📝 Creating sudoers rule...\n";
            $sudoersContent = "# Cyford Security permissions\n";
            $sudoersContent .= "report-ip ALL=(ALL) NOPASSWD: /bin/mkdir, /bin/chown, /bin/chmod\n";
            
            $sudoersFile = '/etc/sudoers.d/cyford-security';
            if (file_put_contents($sudoersFile, $sudoersContent)) {
                exec("chmod 440 {$sudoersFile}");
                echo "✅ Sudoers rule created: {$sudoersFile}\n";
            } else {
                echo "❌ Failed to create sudoers rule\n";
            }
            
            // 2. Setup log directories
            echo "📁 Setting up log directories...\n";
            $logDirs = [
                '/var/log/cyford-security',
                '/var/log/cyford-security/errors'
            ];
            
            foreach ($logDirs as $dir) {
                if (!is_dir($dir)) {
                    mkdir($dir, 0755, true);
                }
                exec("chown -R report-ip:report-ip {$dir}");
                exec("chmod -R 755 {$dir}");
                echo "✅ Log directory: {$dir}\n";
            }
            
            // 3. Setup database directory
            echo "🗄️ Setting up database...\n";
            $dbPath = $this->config['database']['path'];
            $dbDir = dirname($dbPath);
            
            if (!is_dir($dbDir)) {
                mkdir($dbDir, 0755, true);
            }
            
            if (file_exists($dbPath)) {
                exec("chown postfix:postfix {$dbPath}");
                exec("chmod 664 {$dbPath}");
                echo "✅ Database permissions: {$dbPath}\n";
            }
            
            exec("chown postfix:postfix {$dbDir}");
            exec("chmod 755 {$dbDir}");
            echo "✅ Database directory: {$dbDir}\n";
            
            // 4. Setup list files
            echo "📋 Setting up list files...\n";
            $listFiles = [
                $this->config['whitelist']['ips_file'],
                $this->config['whitelist']['domains_file'],
                $this->config['whitelist']['emails_file'],
                $this->config['blacklist']['ips_file'],
                $this->config['blacklist']['domains_file'],
                $this->config['blacklist']['emails_file']
            ];
            
            foreach ($listFiles as $file) {
                $dir = dirname($file);
                if (!is_dir($dir)) {
                    mkdir($dir, 0755, true);
                }
                
                if (!file_exists($file)) {
                    file_put_contents($file, "# Add entries here\n");
                }
                
                exec("chown report-ip:report-ip {$file}");
                exec("chmod 644 {$file}");
                echo "✅ List file: {$file}\n";
            }
            
            // 5. Setup project directory
            echo "📂 Setting up project directory...\n";
            $projectDir = '/usr/local/share/cyford/security';
            exec("chown -R report-ip:report-ip {$projectDir}");
            exec("chmod -R 755 {$projectDir}");
            echo "✅ Project directory: {$projectDir}\n";
            
            echo "\n🎉 Permission setup completed successfully!\n";
            echo "\n📋 Summary:\n";
            echo "  ✅ Sudoers rule created for report-ip user\n";
            echo "  ✅ Log directories configured\n";
            echo "  ✅ Database permissions set\n";
            echo "  ✅ List files initialized\n";
            echo "  ✅ Project directory permissions set\n";
            echo "\n🚀 System is ready for operation!\n";
            
        } catch (Exception $e) {
            echo "❌ Permission setup failed: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Create Docker environment with full mail stack
     */
    private function createDockerEnvironment(): void
    {
        echo "🐳 Creating Docker environment for Cyford Security...\n";
        
        try {
            // Create Dockerfile
            $dockerfile = $this->generateDockerfile();
            file_put_contents('Dockerfile', $dockerfile);
            echo "✅ Dockerfile created\n";
            
            // Create docker-compose.yml
            $dockerCompose = $this->generateDockerCompose();
            file_put_contents('docker-compose.yml', $dockerCompose);
            echo "✅ docker-compose.yml created\n";
            
            // Create setup script
            $setupScript = $this->generateSetupScript();
            file_put_contents('docker-setup.sh', $setupScript);
            chmod('docker-setup.sh', 0755);
            echo "✅ Setup script created\n";
            
            echo "\n🚀 Docker environment created successfully!\n";
            echo "\n📋 Next steps:\n";
            echo "  1. docker-compose up -d\n";
            echo "  2. docker exec -it cyford-mail ./docker-setup.sh\n";
            echo "  3. Access SquirrelMail: http://localhost:8080\n";
            echo "  4. Create users with: --command=create-user --username=test --password=pass\n";
            
        } catch (Exception $e) {
            echo "❌ Docker environment creation failed: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * Create mail user for Postfix and Dovecot
     */
    private function createUser(string $username, string $password): void
    {
        if (empty($username) || empty($password)) {
            echo "❌ Username and password are required\n";
            echo "Usage: --command=create-user --username=testuser --password=testpass\n";
            return;
        }
        
        echo "👤 Creating mail user: {$username}\n";
        
        try {
            // 1. Create system user
            $userExists = exec("id {$username} 2>/dev/null");
            if (empty($userExists)) {
                exec("useradd -m -s /bin/bash {$username}");
                echo "✅ System user created: {$username}\n";
            } else {
                echo "ℹ️  System user already exists: {$username}\n";
            }
            
            // 2. Set password
            exec("echo '{$username}:{$password}' | chpasswd");
            echo "✅ Password set for user: {$username}\n";
            
            // 3. Create maildir structure
            $maildirTemplate = $this->config['postfix']['spam_handling']['maildir_path'] ?? '/home/{user}/Maildir';
            $maildir = str_replace('{user}', $username, $maildirTemplate);
            
            $maildirDirs = [
                $maildir,
                $maildir . '/cur',
                $maildir . '/new',
                $maildir . '/tmp',
                $maildir . '/.Spam',
                $maildir . '/.Spam/cur',
                $maildir . '/.Spam/new',
                $maildir . '/.Spam/tmp'
            ];
            
            foreach ($maildirDirs as $dir) {
                if (!is_dir($dir)) {
                    mkdir($dir, 0755, true);
                }
            }
            
            exec("chown -R {$username}:{$username} {$maildir}");
            echo "✅ Maildir created: {$maildir}\n";
            
            // 4. Add to Postfix virtual users (if using virtual domains)
            $domain = gethostname() ?: 'localhost';
            $virtualUsers = "/etc/postfix/virtual_users";
            $userEntry = "{$username}@{$domain}\t{$username}\n";
            
            if (file_exists($virtualUsers)) {
                file_put_contents($virtualUsers, $userEntry, FILE_APPEND);
                exec("postmap {$virtualUsers}");
                echo "✅ Added to Postfix virtual users\n";
            }
            
            // 5. Add to Dovecot users
            $dovecotUsers = "/etc/dovecot/users";
            $dovecotEntry = "{$username}@{$domain}:{{{PLAIN}}{$password}::::::\n";
            
            if (!file_exists($dovecotUsers)) {
                touch($dovecotUsers);
            }
            
            file_put_contents($dovecotUsers, $dovecotEntry, FILE_APPEND);
            echo "✅ Added to Dovecot users\n";
            
            // 6. Reload services
            exec("systemctl reload postfix 2>/dev/null");
            exec("systemctl reload dovecot 2>/dev/null");
            
            echo "\n🎉 User created successfully!\n";
            echo "\n📧 Email Details:\n";
            echo "  Email: {$username}@{$domain}\n";
            echo "  Password: {$password}\n";
            echo "  Maildir: {$maildir}\n";
            echo "\n🌐 Access via SquirrelMail or IMAP client\n";
            
        } catch (Exception $e) {
            echo "❌ User creation failed: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * Generate Dockerfile for complete mail stack
     */
    private function generateDockerfile(): string
    {
        return <<<'EOF'
# Cyford Security Mail Stack
FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install all required packages
RUN apt-get update && apt-get install -y \
    postfix \
    dovecot-core \
    dovecot-imapd \
    dovecot-pop3d \
    php8.1 \
    php8.1-cli \
    php8.1-sqlite3 \
    php8.1-curl \
    apache2 \
    squirrelmail \
    fail2ban \
    iptables \
    git \
    curl \
    wget \
    nano \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Create required users
RUN useradd -r -s /bin/false report-ip

# Create directory structure
RUN mkdir -p /usr/local/share/cyford/security \
    && mkdir -p /var/log/cyford-security \
    && mkdir -p /var/spool/cyford-security

# Copy CLI Security files
COPY . /usr/local/share/cyford/security/

# Set permissions
RUN chown -R report-ip:report-ip /usr/local/share/cyford/security \
    && chown -R report-ip:report-ip /var/log/cyford-security \
    && chmod -R 755 /usr/local/share/cyford/security

# Configure SquirrelMail
RUN ln -s /usr/share/squirrelmail /var/www/html/webmail \
    && chown -R www-data:www-data /var/lib/squirrelmail

# Create supervisor config
RUN echo '[supervisord]' > /etc/supervisor/conf.d/mailstack.conf \
    && echo 'nodaemon=true' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo '' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo '[program:postfix]' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo 'command=/usr/sbin/postfix start-fg' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo 'autorestart=true' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo '' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo '[program:dovecot]' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo 'command=/usr/sbin/dovecot -F' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo 'autorestart=true' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo '' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo '[program:apache2]' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo 'command=/usr/sbin/apache2ctl -DFOREGROUND' >> /etc/supervisor/conf.d/mailstack.conf \
    && echo 'autorestart=true' >> /etc/supervisor/conf.d/mailstack.conf

# Expose ports
EXPOSE 25 110 143 993 995 80

# Start supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/mailstack.conf"]
EOF;
    }
    
    /**
     * Generate docker-compose.yml
     */
    private function generateDockerCompose(): string
    {
        return <<<'EOF'
version: '3.8'

services:
  cyford-mail:
    build: .
    container_name: cyford-mail
    hostname: mail.cyford.local
    ports:
      - "25:25"     # SMTP
      - "110:110"   # POP3
      - "143:143"   # IMAP
      - "993:993"   # IMAPS
      - "995:995"   # POP3S
      - "8080:80"   # SquirrelMail
    volumes:
      - mail_data:/var/mail
      - mail_logs:/var/log
      - ./:/usr/local/share/cyford/security
    environment:
      - HOSTNAME=mail.cyford.local
      - DOMAIN=cyford.local
    privileged: true
    restart: unless-stopped

volumes:
  mail_data:
  mail_logs:
EOF;
    }
    
    /**
     * Generate setup script for Docker container
     */
    private function generateSetupScript(): string
    {
        return <<<'EOF'
#!/bin/bash
echo "🚀 Setting up Cyford Security Mail Stack..."

# Setup permissions
echo "📋 Setting up permissions..."
cd /usr/local/share/cyford/security
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
EOF;
    }

    /**
     * Show help information
     */
    private function showHelp(): void
    {
        echo "🛡️  Cyford Security Internal Commands\n";
        echo str_repeat("=", 50) . "\n";
        echo "Usage: php index.php --input_type=internal --command=<command> [options]\n\n";
        
        echo "Available Commands:\n";
        echo "  setup-database     - Initialize database with proper permissions\n";
        echo "  setup-permissions  - Setup all system permissions for report-ip user\n";
        echo "  create-docker      - Create Docker environment with full mail stack\n";
        echo "  create-user        - Create mail user (--username=user --password=pass)\n";
        echo "  test-database      - Test database connection and functionality\n";
        echo "  view-spam-patterns - View spam patterns (--limit=20)\n";
        echo "  clear-spam-pattern - Remove spam pattern (--pattern_id=123)\n";
        echo "  stats              - Show system statistics\n";
        echo "  test-spam-filter   - Test spam filter (--subject='...' --body='...')\n";
        echo "  reload-lists       - Reload whitelist/blacklist files\n";
        echo "  help               - Show this help message\n\n";
        
        echo "Examples:\n";
        echo "  php index.php --input_type=internal --command=create-docker\n";
        echo "  php index.php --input_type=internal --command=create-user --username=test --password=pass\n";
        echo "  php index.php --input_type=internal --command=setup-permissions\n";
        echo "  php index.php --input_type=internal --command=setup-database\n";
        echo "  php index.php --input_type=internal --command=stats\n";
        echo "  php index.php --input_type=internal --command=test-spam-filter --subject='Hello' --body='Test message'\n";
    }
}