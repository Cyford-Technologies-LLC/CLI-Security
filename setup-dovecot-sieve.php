<?php
/**
 * Dovecot Sieve Configuration Setup for Cyford Web Armor
 * Automatically configures Dovecot to enable Sieve filtering
 */

require_once __DIR__ . '/bootstrap.php';

class DovecotSieveSetup
{
    private array $config;
    private $logger;
    private array $dovecotConfigs = [
        '/etc/dovecot/dovecot.conf',
        '/etc/dovecot/conf.d/20-managesieve.conf',
        '/etc/dovecot/conf.d/90-sieve.conf',
        '/etc/dovecot/conf.d/15-lda.conf'
    ];

    public function __construct(array $config, $logger)
    {
        $this->config = $config;
        $this->logger = $logger;
    }

    /**
     * Main setup method - configures Dovecot for Sieve support
     */
    public function setupDovecotSieve(): void
    {
        $this->logger->info("Starting Dovecot Sieve configuration...");

        // Check if Dovecot is installed
        if (!$this->isDovecotInstalled()) {
            throw new RuntimeException("Dovecot is not installed on this system");
        }

        // Backup existing configurations
        $this->backupConfigurations();

        // Configure Sieve plugin
        $this->configureSievePlugin();

        // Configure ManageSieve protocol
        $this->configureManageSieve();

        // Configure LDA (Local Delivery Agent)
        $this->configureLDA();

        // Test configuration
        if ($this->testDovecotConfiguration()) {
            // Restart Dovecot to apply changes
            $this->restartDovecot();
            $this->logger->info("Dovecot Sieve configuration completed successfully");
        } else {
            throw new RuntimeException("Dovecot configuration test failed");
        }
    }

    /**
     * Check if Dovecot is installed
     */
    private function isDovecotInstalled(): bool
    {
        $output = shell_exec('which dovecot 2>/dev/null');
        return !empty(trim($output));
    }

    /**
     * Backup existing Dovecot configurations
     */
    private function backupConfigurations(): void
    {
        $backupDir = '/var/backups/dovecot-' . date('Ymd_His');
        
        if (!is_dir($backupDir)) {
            mkdir($backupDir, 0755, true);
        }

        foreach ($this->dovecotConfigs as $configFile) {
            if (file_exists($configFile)) {
                $backupFile = $backupDir . '/' . basename($configFile);
                if (copy($configFile, $backupFile)) {
                    $this->logger->info("Backed up: {$configFile} -> {$backupFile}");
                } else {
                    $this->logger->warning("Failed to backup: {$configFile}");
                }
            }
        }
    }

    /**
     * Configure Sieve plugin in Dovecot
     */
    private function configureSievePlugin(): void
    {
        $sieveConfFile = '/etc/dovecot/conf.d/90-sieve.conf';
        
        $sieveConfig = <<<CONFIG
# Cyford Web Armor - Sieve Configuration
# Auto-generated on: {date('Y-m-d H:i:s')}

plugin {
  # Sieve plugin configuration
  sieve = file:~/sieve;active=~/.dovecot.sieve
  sieve_default = /var/lib/dovecot/sieve/default.sieve
  sieve_default_name = default
  sieve_dir = ~/sieve
  sieve_global_dir = /var/lib/dovecot/sieve/global/
  
  # Sieve extensions
  sieve_extensions = +notify +imapflags +mailbox +fileinto +envelope
  
  # Sieve limits
  sieve_max_script_size = 1M
  sieve_max_actions = 32
  sieve_max_redirects = 4
  
  # Sieve logging
  sieve_trace_debug = no
  sieve_trace_addresses = no
}

CONFIG;

        if (file_put_contents($sieveConfFile, $sieveConfig) === false) {
            throw new RuntimeException("Failed to write Sieve configuration: {$sieveConfFile}");
        }

        $this->logger->info("Sieve plugin configured: {$sieveConfFile}");
    }

    /**
     * Configure ManageSieve protocol
     */
    private function configureManageSieve(): void
    {
        $managesieveConfFile = '/etc/dovecot/conf.d/20-managesieve.conf';
        
        $managesieveConfig = <<<CONFIG
# Cyford Web Armor - ManageSieve Configuration
# Auto-generated on: {date('Y-m-d H:i:s')}

protocols = \$protocols sieve

service managesieve-login {
  inet_listener sieve {
    port = 4190
  }
  
  # Number of connections to handle before starting a new process
  service_count = 1
  
  # Number of processes to create
  process_min_avail = 0
  vsz_limit = 64M
}

service managesieve {
  # Max. number of ManageSieve processes (connections)
  process_limit = 1024
}

protocol sieve {
  # Maximum ManageSieve command line length in bytes
  managesieve_max_line_length = 65536
  
  # Maximum number of ManageSieve commands per connection
  managesieve_max_compile_errors = 5
  
  # Logout format string
  managesieve_logout_format = bytes=%i/%o
  
  # ManageSieve capability
  managesieve_sieve_capability = fileinto reject envelope encoded-character vacation subaddress comparator-i;ascii-numeric relational regex imap4flags copy include variables body enotify environment mailbox date index ihave duplicate mime foreverypart extracttext
}

CONFIG;

        if (file_put_contents($managesieveConfFile, $managesieveConfig) === false) {
            throw new RuntimeException("Failed to write ManageSieve configuration: {$managesieveConfFile}");
        }

        $this->logger->info("ManageSieve protocol configured: {$managesieveConfFile}");
    }

    /**
     * Configure LDA (Local Delivery Agent)
     */
    private function configureLDA(): void
    {
        $ldaConfFile = '/etc/dovecot/conf.d/15-lda.conf';
        
        // Read existing configuration
        $existingConfig = file_exists($ldaConfFile) ? file_get_contents($ldaConfFile) : '';
        
        // Check if Sieve is already configured
        if (strpos($existingConfig, 'mail_plugins') !== false && strpos($existingConfig, 'sieve') !== false) {
            $this->logger->info("LDA already configured with Sieve plugin");
            return;
        }

        $ldaConfig = <<<CONFIG
# Cyford Web Armor - LDA Configuration
# Auto-generated on: {date('Y-m-d H:i:s')}

protocol lda {
  # Space separated list of plugins to load (default is global mail_plugins).
  mail_plugins = \$mail_plugins sieve
  
  # Address to use when returning bounce messages
  postmaster_address = postmaster@{$_SERVER['SERVER_NAME'] ?? 'localhost'}
  
  # Hostname to use in various parts of sent mails, eg. in Message-Id.
  hostname = {$_SERVER['SERVER_NAME'] ?? 'localhost'}
  
  # If user is over quota, return with temporary failure instead of
  # bouncing the mail.
  quota_full_tempfail = yes
  
  # Binary to use for sending mails.
  sendmail_path = /usr/sbin/sendmail
  
  # If non-empty, send mails via this SMTP host[:port] instead of sendmail.
  #submission_host =
  
  # Subject: header to use for rejection mails. You can use the same variables
  # as for rejection_reason below.
  rejection_subject = Rejected: %s
  
  # Human readable error message for rejection mails. You can use variables:
  #  %n = CRLF, %r = reason, %s = original subject, %t = recipient
  rejection_reason = Your message to <%t> was automatically rejected:%n%r
  
  # Delimiter character between local and detail parts. Defaults to "+".
  recipient_delimiter = +
  
  # Header where the original recipient address (SMTP's RCPT TO) is taken
  # from if not available elsewhere. With dovecot-lda -a parameter overrides
  # this. A commonly used header for this is X-Original-To.
  lda_original_recipient_header = X-Original-To
  
  # Should saving a mail to a nonexistent mailbox automatically create it?
  lda_mailbox_autocreate = yes
  
  # Should automatically created mailboxes be also automatically subscribed?
  lda_mailbox_autosubscribe = yes
}

CONFIG;

        if (file_put_contents($ldaConfFile, $ldaConfig) === false) {
            throw new RuntimeException("Failed to write LDA configuration: {$ldaConfFile}");
        }

        $this->logger->info("LDA configured with Sieve plugin: {$ldaConfFile}");
    }

    /**
     * Create default global Sieve script
     */
    private function createDefaultSieveScript(): void
    {
        $globalSieveDir = '/var/lib/dovecot/sieve/global';
        $defaultSieveFile = '/var/lib/dovecot/sieve/default.sieve';

        // Create directories
        if (!is_dir($globalSieveDir)) {
            mkdir($globalSieveDir, 0755, true);
        }

        if (!is_dir('/var/lib/dovecot/sieve')) {
            mkdir('/var/lib/dovecot/sieve', 0755, true);
        }

        $defaultSieveScript = <<<SIEVE
# Cyford Web Armor - Default Global Sieve Script
# This script runs before user-specific scripts

require ["fileinto", "mailbox"];

# Global spam filtering - fallback if user scripts don't handle it
if header :contains "X-Spam-Flag" "YES" {
    fileinto :create "Spam";
    stop;
}

SIEVE;

        if (file_put_contents($defaultSieveFile, $defaultSieveScript) === false) {
            throw new RuntimeException("Failed to create default Sieve script: {$defaultSieveFile}");
        }

        // Set proper ownership
        exec('sudo chown -R dovecot:dovecot /var/lib/dovecot/sieve');
        exec('sudo chmod -R 755 /var/lib/dovecot/sieve');

        // Compile the default script
        exec("sudo -u dovecot sievec {$defaultSieveFile}");

        $this->logger->info("Default global Sieve script created: {$defaultSieveFile}");
    }

    /**
     * Test Dovecot configuration
     */
    private function testDovecotConfiguration(): bool
    {
        $this->logger->info("Testing Dovecot configuration...");
        
        exec('dovecot -n 2>&1', $output, $returnCode);
        
        if ($returnCode === 0) {
            $this->logger->info("Dovecot configuration test passed");
            return true;
        } else {
            $this->logger->error("Dovecot configuration test failed:");
            $this->logger->error(implode("\n", $output));
            return false;
        }
    }

    /**
     * Restart Dovecot service
     */
    private function restartDovecot(): void
    {
        $this->logger->info("Restarting Dovecot service...");
        
        exec('sudo systemctl restart dovecot 2>&1', $output, $returnCode);
        
        if ($returnCode === 0) {
            $this->logger->info("Dovecot service restarted successfully");
            
            // Wait a moment and check status
            sleep(2);
            exec('sudo systemctl is-active dovecot', $statusOutput, $statusCode);
            
            if ($statusCode === 0 && trim($statusOutput[0]) === 'active') {
                $this->logger->info("Dovecot service is running");
            } else {
                $this->logger->warning("Dovecot service may not be running properly");
            }
        } else {
            $this->logger->error("Failed to restart Dovecot service:");
            $this->logger->error(implode("\n", $output));
            throw new RuntimeException("Failed to restart Dovecot service");
        }
    }

    /**
     * Get Dovecot Sieve status
     */
    public function getSieveStatus(): array
    {
        $status = [
            'dovecot_installed' => $this->isDovecotInstalled(),
            'dovecot_running' => false,
            'sieve_plugin_configured' => false,
            'managesieve_configured' => false,
            'lda_configured' => false,
            'default_script_exists' => false
        ];

        // Check if Dovecot is running
        exec('sudo systemctl is-active dovecot 2>/dev/null', $output, $returnCode);
        $status['dovecot_running'] = ($returnCode === 0 && trim($output[0] ?? '') === 'active');

        // Check configuration files
        $status['sieve_plugin_configured'] = file_exists('/etc/dovecot/conf.d/90-sieve.conf');
        $status['managesieve_configured'] = file_exists('/etc/dovecot/conf.d/20-managesieve.conf');
        
        // Check LDA configuration
        $ldaConfFile = '/etc/dovecot/conf.d/15-lda.conf';
        if (file_exists($ldaConfFile)) {
            $ldaContent = file_get_contents($ldaConfFile);
            $status['lda_configured'] = (strpos($ldaContent, 'sieve') !== false);
        }

        // Check default script
        $status['default_script_exists'] = file_exists('/var/lib/dovecot/sieve/default.sieve');

        return $status;
    }

    /**
     * Remove Dovecot Sieve configuration (cleanup)
     */
    public function removeSieveConfiguration(): void
    {
        $this->logger->info("Removing Dovecot Sieve configuration...");

        $configFiles = [
            '/etc/dovecot/conf.d/90-sieve.conf',
            '/etc/dovecot/conf.d/20-managesieve.conf'
        ];

        foreach ($configFiles as $file) {
            if (file_exists($file)) {
                unlink($file);
                $this->logger->info("Removed configuration file: {$file}");
            }
        }

        // Remove LDA Sieve configuration
        $ldaConfFile = '/etc/dovecot/conf.d/15-lda.conf';
        if (file_exists($ldaConfFile)) {
            $content = file_get_contents($ldaConfFile);
            $content = preg_replace('/mail_plugins = \$mail_plugins sieve/', 'mail_plugins = $mail_plugins', $content);
            file_put_contents($ldaConfFile, $content);
            $this->logger->info("Removed Sieve from LDA configuration");
        }

        // Remove global Sieve directory
        if (is_dir('/var/lib/dovecot/sieve')) {
            exec('sudo rm -rf /var/lib/dovecot/sieve');
            $this->logger->info("Removed global Sieve directory");
        }

        $this->restartDovecot();
        $this->logger->info("Dovecot Sieve configuration removed");
    }

    /**
     * Install required Sieve packages
     */
    public function installSievePackages(): void
    {
        $this->logger->info("Installing Dovecot Sieve packages...");

        $packages = ['dovecot-sieve', 'dovecot-managesieved'];
        
        foreach ($packages as $package) {
            $this->logger->info("Installing package: {$package}");
            exec("sudo apt-get install -y {$package} 2>&1", $output, $returnCode);
            
            if ($returnCode === 0) {
                $this->logger->info("Successfully installed: {$package}");
            } else {
                $this->logger->warning("Failed to install {$package}: " . implode(' ', $output));
            }
        }
    }
}

// CLI execution
if (php_sapi_name() === 'cli') {
    try {
        $bootstrap = require __DIR__ . '/bootstrap.php';
        $config = $bootstrap['config'];
        $logger = $bootstrap['logger'];

        $dovecotSetup = new DovecotSieveSetup($config, $logger);

        // Parse command line arguments
        $command = 'setup'; // default

        foreach ($argv as $arg) {
            if (strpos($arg, '--command=') === 0) {
                $command = substr($arg, 10);
            }
        }

        switch ($command) {
            case 'setup':
                $dovecotSetup->setupDovecotSieve();
                break;
            case 'install':
                $dovecotSetup->installSievePackages();
                break;
            case 'status':
                $status = $dovecotSetup->getSieveStatus();
                echo "Dovecot Sieve Status:\n";
                echo "Dovecot installed: " . ($status['dovecot_installed'] ? 'YES' : 'NO') . "\n";
                echo "Dovecot running: " . ($status['dovecot_running'] ? 'YES' : 'NO') . "\n";
                echo "Sieve plugin configured: " . ($status['sieve_plugin_configured'] ? 'YES' : 'NO') . "\n";
                echo "ManageSieve configured: " . ($status['managesieve_configured'] ? 'YES' : 'NO') . "\n";
                echo "LDA configured: " . ($status['lda_configured'] ? 'YES' : 'NO') . "\n";
                echo "Default script exists: " . ($status['default_script_exists'] ? 'YES' : 'NO') . "\n";
                break;
            case 'remove':
                $dovecotSetup->removeSieveConfiguration();
                break;
            default:
                echo "Usage: php setup-dovecot-sieve.php [--command=setup|install|status|remove]\n";
                exit(1);
        }

        echo "Dovecot Sieve operation completed successfully.\n";

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}