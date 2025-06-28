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
     * Show help information
     */
    private function showHelp(): void
    {
        echo "🛡️  Cyford Security Internal Commands\n";
        echo str_repeat("=", 50) . "\n";
        echo "Usage: php index.php --input_type=internal --command=<command> [options]\n\n";
        
        echo "Available Commands:\n";
        echo "  setup-database     - Initialize database with proper permissions\n";
        echo "  test-database      - Test database connection and functionality\n";
        echo "  view-spam-patterns - View spam patterns (--limit=20)\n";
        echo "  clear-spam-pattern - Remove spam pattern (--pattern_id=123)\n";
        echo "  stats              - Show system statistics\n";
        echo "  test-spam-filter   - Test spam filter (--subject='...' --body='...')\n";
        echo "  reload-lists       - Reload whitelist/blacklist files\n";
        echo "  help               - Show this help message\n\n";
        
        echo "Examples:\n";
        echo "  php index.php --input_type=internal --command=setup-database\n";
        echo "  php index.php --input_type=internal --command=stats\n";
        echo "  php index.php --input_type=internal --command=test-spam-filter --subject='Hello' --body='Test message'\n";
    }
}