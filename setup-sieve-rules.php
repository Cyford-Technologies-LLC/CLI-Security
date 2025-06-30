<?php
/**
 * Sieve Rules Setup for Cyford Web Armor
 * Automatically configures Sieve filtering rules to move spam emails to designated folders
 */

require_once __DIR__ . '/bootstrap.php';

class SieveRulesSetup
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
     * Main setup method - configures Sieve rules for all users
     */
    public function setupSieveRules(): void
    {
        $this->logger->info("Starting Sieve rules setup for spam filtering...");

        // Get all real users from the system
        $users = $this->getAllMailUsers();
        
        if (empty($users)) {
            $this->logger->warning("No mail users found on the system");
            return;
        }

        $this->logger->info("Found " . count($users) . " mail users: " . implode(', ', $users));

        foreach ($users as $user) {
            try {
                $this->setupUserSieveRules($user);
                $this->logger->info("Sieve rules configured for user: {$user}");
            } catch (Exception $e) {
                $this->logger->error("Failed to setup Sieve rules for user {$user}: " . $e->getMessage());
            }
        }

        $this->logger->info("Sieve rules setup completed");
    }

    /**
     * Setup Sieve rules for a specific user
     */
    private function setupUserSieveRules(string $user): void
    {
        $homeDir = "/home/{$user}";
        $sieveDir = "{$homeDir}/.dovecot/sieve";
        $sieveFile = "{$sieveDir}/cyford-spam-filter.sieve";
        $activeLink = "{$homeDir}/.dovecot.sieve";

        // Create sieve directory if it doesn't exist
        if (!is_dir($sieveDir)) {
            if (!mkdir($sieveDir, 0755, true)) {
                throw new RuntimeException("Failed to create sieve directory: {$sieveDir}");
            }
            // Set proper ownership
            exec("sudo chown -R {$user}:{$user} {$homeDir}/.dovecot");
        }

        // Generate Sieve rules content
        $sieveContent = $this->generateSieveRules();

        // Write Sieve rules file
        if (file_put_contents($sieveFile, $sieveContent) === false) {
            throw new RuntimeException("Failed to write Sieve rules file: {$sieveFile}");
        }

        // Set proper ownership and permissions
        exec("sudo chown {$user}:{$user} {$sieveFile}");
        chmod($sieveFile, 0644);

        // Create/update the active Sieve link
        if (file_exists($activeLink)) {
            unlink($activeLink);
        }
        
        if (!symlink($sieveFile, $activeLink)) {
            throw new RuntimeException("Failed to create Sieve active link: {$activeLink}");
        }

        exec("sudo chown -h {$user}:{$user} {$activeLink}");

        // Compile the Sieve script
        $compileCmd = "sudo -u {$user} sievec {$sieveFile}";
        exec($compileCmd, $output, $returnCode);
        
        if ($returnCode !== 0) {
            $this->logger->warning("Sieve compilation warning for {$user}: " . implode(' ', $output));
        }

        $this->logger->info("Sieve rules activated for user: {$user}");
    }

    /**
     * Generate Sieve rules content based on configuration
     */
    private function generateSieveRules(): string
    {
        $spamFolder = $this->config['postfix']['spam_handling']['quarantine_folder'] ?? 'Spam';
        
        return <<<SIEVE
# Cyford Web Armor - Spam Filter Rules
# Auto-generated on: {date('Y-m-d H:i:s')}

require ["envelope", "fileinto", "mailbox", "imap4flags"];

# Rule 1: Move emails with X-Spam-Flag: YES to Spam folder
if header :contains "X-Spam-Flag" "YES" {
    fileinto :create "{$spamFolder}";
    setflag "\\Seen";
    stop;
}

# Rule 2: Move emails with ***SPAM*** in subject to Spam folder
if header :contains "Subject" "***SPAM***" {
    fileinto :create "{$spamFolder}";
    setflag "\\Seen";
    stop;
}

# Rule 3: Move emails with high spam score to Spam folder
if header :matches "X-Spam-Score" "*" {
    if header :value "ge" :comparator "i;ascii-numeric" "X-Spam-Score" "5.0" {
        fileinto :create "{$spamFolder}";
        setflag "\\Seen";
        stop;
    }
}

# Rule 4: Move emails processed by security filter with spam status
if allof (
    header :contains "X-Processed-By-Security-Filter" "true",
    header :contains "X-Spam-Status" "Yes"
) {
    fileinto :create "{$spamFolder}";
    setflag "\\Seen";
    stop;
}

# Default: Keep all other emails in INBOX
SIEVE;
    }

    /**
     * Get all mail users from the system
     */
    private function getAllMailUsers(): array
    {
        $users = [];
        
        // Method 1: Get users from /etc/passwd with home directories
        if (file_exists('/etc/passwd')) {
            $passwdContent = file_get_contents('/etc/passwd');
            $lines = explode("\n", $passwdContent);
            
            foreach ($lines as $line) {
                if (preg_match('/^([^:]+):[^:]*:[^:]*:[^:]*:[^:]*:\/home\/([^:]+):/', $line, $matches)) {
                    $username = $matches[1];
                    $homeUser = $matches[2];
                    
                    // Skip system users
                    if (!in_array($username, ['root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc', 'gnats', 'nobody', 'systemd-network', 'systemd-resolve', 'syslog', 'messagebus', '_apt', 'lxd', 'uuidd', 'dnsmasq', 'landscape', 'pollinate', 'sshd', 'postfix', 'dovecot'])) {
                        $users[] = $username;
                    }
                }
            }
        }

        // Method 2: Check for existing Maildir users
        $homeDir = '/home';
        if (is_dir($homeDir)) {
            $homeDirs = scandir($homeDir);
            foreach ($homeDirs as $dir) {
                if ($dir !== '.' && $dir !== '..' && is_dir("{$homeDir}/{$dir}")) {
                    $maildirPath = "{$homeDir}/{$dir}/Maildir";
                    if (is_dir($maildirPath) && !in_array($dir, $users)) {
                        $users[] = $dir;
                    }
                }
            }
        }

        // Method 3: Get users from virtual aliases
        if (file_exists('/etc/postfix/virtual')) {
            $virtualContent = file_get_contents('/etc/postfix/virtual');
            $lines = explode("\n", $virtualContent);
            
            foreach ($lines as $line) {
                $line = trim($line);
                if (empty($line) || $line[0] === '#') continue;
                
                if (preg_match('/^[^@]+@[^@]+\s+([^@]+)@/', $line, $matches)) {
                    $targetUser = $matches[1];
                    if (!in_array($targetUser, $users) && is_dir("/home/{$targetUser}")) {
                        $users[] = $targetUser;
                    }
                }
            }
        }

        return array_unique($users);
    }

    /**
     * Test Sieve rules with a sample spam email
     */
    public function testSieveRules(string $user): bool
    {
        $this->logger->info("Testing Sieve rules for user: {$user}");
        
        $testEmail = $this->generateTestSpamEmail();
        $tempFile = "/tmp/test_spam_email_{$user}.eml";
        
        file_put_contents($tempFile, $testEmail);
        
        // Use sieve-test to validate rules
        $sieveFile = "/home/{$user}/.dovecot/sieve/cyford-spam-filter.sieve";
        $testCmd = "sieve-test {$sieveFile} {$tempFile}";
        
        exec($testCmd, $output, $returnCode);
        
        unlink($tempFile);
        
        if ($returnCode === 0) {
            $this->logger->info("Sieve rules test passed for user: {$user}");
            $this->logger->info("Test output: " . implode("\n", $output));
            return true;
        } else {
            $this->logger->error("Sieve rules test failed for user: {$user}");
            $this->logger->error("Test output: " . implode("\n", $output));
            return false;
        }
    }

    /**
     * Generate a test spam email for validation
     */
    private function generateTestSpamEmail(): string
    {
        return <<<EMAIL
From: test@example.com
To: testuser@cyfordtechnologies.com
Subject: ***SPAM*** Test Email
X-Spam-Flag: YES
X-Spam-Score: 7.5
X-Spam-Status: Yes, score=7.5 required=5.0 tests=CYFORD_SPAM
X-Processed-By-Security-Filter: true

This is a test spam email to validate Sieve filtering rules.
EMAIL;
    }

    /**
     * Remove Sieve rules for a user (cleanup)
     */
    public function removeSieveRules(string $user): void
    {
        $homeDir = "/home/{$user}";
        $sieveFile = "{$homeDir}/.dovecot/sieve/cyford-spam-filter.sieve";
        $activeLink = "{$homeDir}/.dovecot.sieve";

        if (file_exists($sieveFile)) {
            unlink($sieveFile);
            $this->logger->info("Removed Sieve rules file for user: {$user}");
        }

        if (is_link($activeLink)) {
            unlink($activeLink);
            $this->logger->info("Removed active Sieve link for user: {$user}");
        }
    }

    /**
     * Get status of Sieve rules for all users
     */
    public function getSieveStatus(): array
    {
        $users = $this->getAllMailUsers();
        $status = [];

        foreach ($users as $user) {
            $homeDir = "/home/{$user}";
            $sieveFile = "{$homeDir}/.dovecot/sieve/cyford-spam-filter.sieve";
            $activeLink = "{$homeDir}/.dovecot.sieve";

            $status[$user] = [
                'sieve_file_exists' => file_exists($sieveFile),
                'active_link_exists' => file_exists($activeLink),
                'active_link_target' => is_link($activeLink) ? readlink($activeLink) : null,
                'rules_active' => file_exists($sieveFile) && is_link($activeLink) && readlink($activeLink) === $sieveFile
            ];
        }

        return $status;
    }
}

// CLI execution
if (php_sapi_name() === 'cli') {
    try {
        $bootstrap = require __DIR__ . '/bootstrap.php';
        $config = $bootstrap['config'];
        $logger = $bootstrap['logger'];
        $systems = $bootstrap['systems'];

        $sieveSetup = new SieveRulesSetup($config, $logger, $systems);

        // Parse command line arguments
        $command = 'setup'; // default
        $user = null;

        foreach ($argv as $arg) {
            if (strpos($arg, '--command=') === 0) {
                $command = substr($arg, 10);
            } elseif (strpos($arg, '--user=') === 0) {
                $user = substr($arg, 7);
            }
        }

        switch ($command) {
            case 'setup':
                $sieveSetup->setupSieveRules();
                break;
            case 'test':
                if ($user) {
                    $sieveSetup->testSieveRules($user);
                } else {
                    echo "Error: --user parameter required for test command\n";
                    exit(1);
                }
                break;
            case 'status':
                $status = $sieveSetup->getSieveStatus();
                echo "Sieve Rules Status:\n";
                foreach ($status as $user => $userStatus) {
                    echo "User: {$user}\n";
                    echo "  Sieve file exists: " . ($userStatus['sieve_file_exists'] ? 'YES' : 'NO') . "\n";
                    echo "  Active link exists: " . ($userStatus['active_link_exists'] ? 'YES' : 'NO') . "\n";
                    echo "  Rules active: " . ($userStatus['rules_active'] ? 'YES' : 'NO') . "\n";
                    echo "\n";
                }
                break;
            case 'remove':
                if ($user) {
                    $sieveSetup->removeSieveRules($user);
                } else {
                    echo "Error: --user parameter required for remove command\n";
                    exit(1);
                }
                break;
            default:
                echo "Usage: php setup-sieve-rules.php [--command=setup|test|status|remove] [--user=username]\n";
                exit(1);
        }

        echo "Sieve rules operation completed successfully.\n";

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}