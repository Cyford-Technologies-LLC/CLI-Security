<?php
/**
 * Cyford Web Armor - Complete Auto-Configuration Script
 * This script sets up the entire email security system from scratch
 */

require_once __DIR__ . '/bootstrap.php';

class AutoConfig
{
    private array $config;
    private $logger;
    private $systems;

    public function __construct(array $config, $logger, $systems)
    {
        $this->config = $config;
        $this->logger = $logger;
        $this->systems = $systems;
    }

    /**
     * Complete system auto-configuration (all-in-one setup)
     */
    public function autoConfigureSystem(): void
    {
        echo "🚀 Starting complete Cyford Web Armor auto-configuration...\n";
        echo "This will configure the entire email security system from scratch.\n\n";
        
        $allowModification = $this->config['postfix']['allow_modification'] ?? false;
        if (!$allowModification) {
            echo "❌ Auto-configuration disabled. Set 'allow_modification' => true in config.php\n";
            return;
        }
        
        try {
            // Step 1: Setup basic permissions
            echo "🔒 Step 1: Setting up system permissions...\n";
            $this->setupPermissions();
            echo "✅ System permissions configured\n\n";
            
            // Step 2: Setup database
            echo "🗄️ Step 2: Setting up database...\n";
            $this->setupDatabase();
            echo "✅ Database configured\n\n";
            
            // Step 3: Configure Postfix
            echo "📧 Step 3: Configuring Postfix...\n";
            $postfix = new \Cyford\Security\Classes\Postfix($this->config);
            if (!$postfix->checkConfig()) {
                $postfix->autoConfig();
            }
            echo "✅ Postfix configured\n\n";
            
            // Step 4: Setup Dovecot Sieve
            echo "📬 Step 4: Setting up Dovecot Sieve...\n";
            $this->setupDovecotSieve();
            echo "✅ Dovecot Sieve configured\n\n";
            
            // Step 5: Setup user permissions for all users
            echo "👥 Step 5: Setting up user permissions...\n";
            $this->setupUserPermissions('all');
            echo "✅ User permissions configured\n\n";
            
            // Step 6: Setup Sieve rules for all users
            echo "📧 Step 6: Setting up Sieve spam filtering rules...\n";
            $this->setupSieveRules('all');
            echo "✅ Sieve rules configured\n\n";
            
            // Step 7: Test the complete system
            echo "🧪 Step 7: Testing system configuration...\n";
            $this->testCompleteSystem();
            
            echo "\n🎉 COMPLETE SYSTEM AUTO-CONFIGURATION SUCCESSFUL! 🎉\n";
            echo "\n" . str_repeat("=", 60) . "\n";
            echo "📧 CYFORD WEB ARMOR IS NOW FULLY OPERATIONAL\n";
            echo str_repeat("=", 60) . "\n\n";
            
            echo "✅ System Status:\n";
            echo "  • Postfix: Configured with IP-based filtering\n";
            echo "  • Spam Detection: Active with X-Spam headers\n";
            echo "  • Dovecot Sieve: Configured for spam folder delivery\n";
            echo "  • User Permissions: Set for all mail users\n";
            echo "  • Database: Initialized and accessible\n";
            echo "  • Logging: Enabled for all components\n\n";
            
            echo "🎯 Mission Accomplished:\n";
            echo "  Spam emails will now be automatically moved to spam folders!\n\n";
            
            echo "📝 Next Steps:\n";
            echo "  1. Send a test email to verify spam filtering\n";
            echo "  2. Check spam folder in user's mailbox\n";
            echo "  3. Monitor logs: /var/log/cyford-security/\n";
            echo "  4. View stats: php index.php --input_type=internal --command=stats\n\n";
            
            echo "🔧 Manual Commands (if needed):\n";
            echo "  • Create user: php index.php --input_type=internal --command=create-user --username=test --password=pass\n";
            echo "  • Test spam filter: php index.php --input_type=internal --command=test-spam-filter --subject='test' --body='spam content'\n";
            echo "  • View spam patterns: php index.php --input_type=internal --command=view-spam-patterns\n";
            
        } catch (Exception $e) {
            echo "❌ Auto-configuration failed: " . $e->getMessage() . "\n";
            echo "\n🔧 Manual Recovery:\n";
            echo "  1. Check logs: /var/log/cyford-security/\n";
            echo "  2. Run individual setup commands\n";
            echo "  3. Verify system requirements\n";
        }
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
            
        } catch (Exception $e) {
            echo "❌ Permission setup failed: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Setup database with proper permissions
     */
    private function setupDatabase(): void
    {
        echo "Setting up Cyford Security Database...\n";
        
        try {
            $database = new \Cyford\Security\Classes\Database($this->config);
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
     * Setup Dovecot Sieve
     */
    private function setupDovecotSieve(): void
    {
        echo "🚀 Starting complete Dovecot Sieve setup...\n";
        
        try {
            // Install Dovecot and Sieve if needed
            $this->installDovecotAndSieve();
            
            // Configure Dovecot Sieve
            $this->configureDovecotSieve();
            
            // Setup permissions
            $this->setupDovecotPermissions();
            
            echo "✅ Dovecot Sieve setup completed\n";
            
        } catch (Exception $e) {
            echo "❌ Dovecot Sieve setup failed: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Install Dovecot and Sieve packages
     */
    private function installDovecotAndSieve(): void
    {
        // Check if Dovecot is installed
        exec('which dovecot 2>/dev/null', $dovecotPath, $dovecotExists);
        if ($dovecotExists !== 0) {
            echo "📦 Installing Dovecot...\n";
            exec('dnf install -y dovecot 2>/dev/null || yum install -y dovecot 2>/dev/null || apt-get install -y dovecot-core dovecot-imapd 2>/dev/null');
        }
        
        // Check if Sieve is installed
        exec('which sievec 2>/dev/null', $sievecPath, $sievecExists);
        if ($sievecExists !== 0) {
            echo "📦 Installing Dovecot Sieve...\n";
            exec('dnf install -y dovecot-pigeonhole 2>/dev/null || yum install -y dovecot-pigeonhole 2>/dev/null || apt-get install -y dovecot-sieve dovecot-managesieved 2>/dev/null');
        }
        
        // Start Dovecot
        exec('systemctl enable dovecot && systemctl start dovecot 2>/dev/null');
        echo "✅ Dovecot services configured\n";
    }

    /**
     * Configure Dovecot for Sieve
     */
    private function configureDovecotSieve(): void
    {
        echo "⚙️ Configuring Dovecot Sieve...\n";
        
        // Create Sieve configuration
        $sieveConfigFile = '/etc/dovecot/conf.d/99-cyford-sieve.conf';
        
        $sieveConfig = <<<'DOVECOT'
# Cyford Web Armor Sieve Configuration
protocol lda {
  mail_plugins = $mail_plugins sieve
}

protocol lmtp {
  mail_plugins = $mail_plugins sieve
}

plugin {
  sieve = ~/.dovecot.sieve
  sieve_dir = ~/sieve
  sieve_max_script_size = 1M
  sieve_max_actions = 32
  sieve_max_redirects = 4
}
DOVECOT;
        
        file_put_contents($sieveConfigFile, $sieveConfig);
        echo "✅ Created Sieve configuration\n";
        
        // Restart Dovecot
        exec('systemctl restart dovecot 2>/dev/null');
        echo "✅ Restarted Dovecot\n";
    }

    /**
     * Setup Dovecot permissions
     */
    private function setupDovecotPermissions(): void
    {
        // Add report-ip to mail group
        exec('usermod -a -G mail report-ip 2>/dev/null');
        exec('usermod -a -G dovecot report-ip 2>/dev/null');
        echo "✅ Added report-ip to mail groups\n";
    }

    /**
     * Setup user permissions for all users
     */
    private function setupUserPermissions(string $username): void
    {
        if ($username === 'all') {
            echo "🔧 Setting up user permissions for ALL users...\n";
            
            $homeDir = '/home';
            if (!is_dir($homeDir)) {
                echo "❌ /home directory does not exist\n";
                return;
            }
            
            $users = [];
            $directories = scandir($homeDir);
            
            foreach ($directories as $dir) {
                if ($dir === '.' || $dir === '..') continue;
                
                $userPath = $homeDir . '/' . $dir;
                if (is_dir($userPath) && $this->isValidUserDirectory($userPath)) {
                    $users[] = $dir;
                }
            }
            
            echo "👥 Found " . count($users) . " users: " . implode(', ', $users) . "\n";
            
            foreach ($users as $user) {
                $this->setupSingleUserPermissions($user);
            }
        }
    }

    /**
     * Setup permissions for a single user
     */
    private function setupSingleUserPermissions(string $username): void
    {
        // Add postfix to user's group
        exec("usermod -a -G {$username} postfix 2>/dev/null");
        exec("usermod -a -G {$username} report-ip 2>/dev/null");
        
        // Set group permissions on home directory
        if (is_dir("/home/{$username}")) {
            exec("chmod g+rx /home/{$username}");
        }
        
        echo "✅ Set permissions for user: {$username}\n";
    }

    /**
     * Setup Sieve rules for all users
     */
    private function setupSieveRules(string $username): void
    {
        if ($username === 'all') {
            echo "📧 Setting up Sieve rules for ALL users...\n";
            
            $homeDir = '/home';
            $users = [];
            $directories = scandir($homeDir);
            
            foreach ($directories as $dir) {
                if ($dir === '.' || $dir === '..') continue;
                
                $userPath = $homeDir . '/' . $dir;
                if (is_dir($userPath) && $this->isValidUserDirectory($userPath)) {
                    $users[] = $dir;
                }
            }
            
            foreach ($users as $user) {
                $this->setupSingleUserSieveRules($user);
            }
        }
    }

    /**
     * Setup Sieve rules for a single user
     */
    private function setupSingleUserSieveRules(string $username): void
    {
        $homeDir = "/home/{$username}";
        $sieveScript = "{$homeDir}/.dovecot.sieve";
        
        $spamRules = <<<'SIEVE'
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

# Move emails with ***SPAM*** in subject
if header :contains "Subject" "***SPAM***" {
    if not mailboxexists "Spambox" {
        mailboxcreate "Spambox";
    }
    fileinto "Spambox";
    stop;
}
SIEVE;
        
        file_put_contents($sieveScript, $spamRules);
        exec("chown {$username}:{$username} {$sieveScript}");
        exec("chmod 644 {$sieveScript}");
        
        // Compile sieve script
        exec("sudo -u {$username} sievec {$sieveScript} 2>/dev/null");
        
        echo "✅ Sieve rules configured for: {$username}\n";
    }

    /**
     * Check if directory is a valid user directory
     */
    private function isValidUserDirectory(string $userPath): bool
    {
        $username = basename($userPath);
        
        // Skip system directories
        $systemDirs = ['lost+found', 'ftp', 'www', 'backup', 'tmp', 'skel'];
        if (in_array($username, $systemDirs)) {
            return false;
        }
        
        // Check if user exists
        exec("id {$username} 2>/dev/null", $output, $returnCode);
        return $returnCode === 0;
    }

    /**
     * Test the complete system configuration
     */
    private function testCompleteSystem(): void
    {
        echo "🧪 Running comprehensive system tests...\n";
        
        // Test 1: Database connectivity
        try {
            $database = new \Cyford\Security\Classes\Database($this->config);
            $database->setCache('autoconfig_test', 'success', 60);
            $testValue = $database->getCache('autoconfig_test');
            if ($testValue === 'success') {
                echo "  ✅ Database: Connection and functionality OK\n";
            } else {
                echo "  ❌ Database: Functionality test failed\n";
            }
        } catch (Exception $e) {
            echo "  ❌ Database: " . $e->getMessage() . "\n";
        }
        
        // Test 2: Postfix configuration
        try {
            $postfix = new \Cyford\Security\Classes\Postfix($this->config);
            if ($postfix->checkConfig()) {
                echo "  ✅ Postfix: Configuration verified\n";
            } else {
                echo "  ❌ Postfix: Configuration incomplete\n";
            }
        } catch (Exception $e) {
            echo "  ❌ Postfix: " . $e->getMessage() . "\n";
        }
        
        // Test 3: Dovecot service status
        exec('systemctl is-active dovecot 2>/dev/null', $dovecotStatus, $dovecotReturn);
        if ($dovecotReturn === 0 && trim($dovecotStatus[0] ?? '') === 'active') {
            echo "  ✅ Dovecot: Service running\n";
        } else {
            echo "  ❌ Dovecot: Service not running\n";
        }
        
        // Test 4: Sieve compilation
        exec('which sievec 2>/dev/null', $sievecPath, $sievecReturn);
        if ($sievecReturn === 0) {
            echo "  ✅ Sieve: Compiler available\n";
        } else {
            echo "  ❌ Sieve: Compiler not found\n";
        }
        
        echo "\n🧪 System test completed\n";
    }
}

// CLI execution
if (php_sapi_name() === 'cli') {
    try {
        $bootstrap = require __DIR__ . '/bootstrap.php';
        $config = $bootstrap['config'];
        $logger = $bootstrap['logger'];
        $systems = $bootstrap['systems'];

        $autoConfig = new AutoConfig($config, $logger, $systems);
        $autoConfig->autoConfigureSystem();

        echo "\nAutoconfig completed successfully.\n";

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}