<?php
namespace Cyford\Security\Classes;

use Exception;
use Cyford\Security\Classes\ApiClient;

class Internal
{
    private array $config;
    private $logger;
    private ApiClient $apiClient;


    public function __construct(array $config, $logger = null)
    {
        $this->config = $config;
        $this->logger = $logger;
        $this->apiClient = new ApiClient($config, $logger);


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
            case 'report-ip':
                $this->reportIp($args['ip'] ?? null, $args['jail'] ?? 'unknown', $args['reason'] ?? 'Manual report');
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
                
            case 'setup-user-permissions':
                $this->setupUserPermissions($args['username'] ?? '');
                break;
                
            case 'setup-sieve-rules':
                $this->setupSieveRules($args['username'] ?? '');
                break;
                
            case 'setup-dovecot-sieve':
                $this->setupDovecotSieve();
                break;
                
            case 'fix-dovecot-permissions':
                $this->fixDovecotPermissions();
                break;
                
            case 'system-inventory':
                $this->performSystemInventory();
                break;
                
            case 'setup-task-queue':
                $this->setupTaskQueue();
                break;
                
            case 'cron-status':
                $this->checkCronStatus();
                break;
                
            case 'queue-status':
                $this->checkQueueStatus();
                break;
                
            case 'cron-log':
                $this->checkCronLog();
                break;
                
            case 'backup-config':
                $this->backupConfig();
                break;
                
            case 'restore-config':
                $this->restoreConfig($args['backup'] ?? null);
                break;
                
            case 'merge-config':
                $this->mergeConfig();
                break;
                
            case 'list-backups':
                $this->listBackups();
                break;
                
            case ' we can add too':
                $this->viewDetectionAlgorithms($args['category'] ?? null);
                break;
                
            case 'export-algorithms':
                $this->exportDetectionAlgorithms($args['format'] ?? 'json');
                break;
                
            case 'algorithm-stats':
                $this->showAlgorithmStats();
                break;

            case 'update-algorithms':
                $this->apiClient->updateAlgorithms();
                break;

            case 'recreate-database':
                $this->recreateDatabase();
                break;
                
            case 'drop-table':
                $this->dropTable($args['table'] ?? 'detection_algorithms');
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
            
            // Check if we're in Docker environment
            $isDocker = Database::isDocker();
            
            if ($isDocker) {
                // In Docker, use direct commands without sudo
                exec("chown postfix:postfix " . escapeshellarg($dbPath) . " 2>/dev/null");
                exec("chmod 664 " . escapeshellarg($dbPath) . " 2>/dev/null");
                exec("chown postfix:postfix " . escapeshellarg($dbDir) . " 2>/dev/null");
                exec("chmod 755 " . escapeshellarg($dbDir) . " 2>/dev/null");
            } else {
                // On host system, use sudo
                exec("sudo chown postfix:postfix " . escapeshellarg($dbPath));
                exec("sudo chmod 664 " . escapeshellarg($dbPath));
                exec("sudo chown postfix:postfix " . escapeshellarg($dbDir));
                exec("sudo chmod 755 " . escapeshellarg($dbDir));
            }
            
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
                echo "ID: " . $pattern['id'] . "\n";
                echo "Subject: " . $pattern['sample_subject'] . "\n";
                echo "Body Preview: " . substr($pattern['sample_body_preview'], 0, 100) . "...\n";
                echo "Count: " . $pattern['count'] . " | First: " . $pattern['first_seen'] . " | Last: " . $pattern['last_seen'] . "\n";
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
                echo "  " . $stat['date'] . ": Total=" . $stat['total_emails'] . ", Spam=" . $stat['spam_emails'] . ", Clean=" . $stat['clean_emails'] . "\n";
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
            echo "Usage: --command=test-spam-filter --subject='Test Subject' --body='Test Body'\n";
            return;
        }
        
        try {
            $spamFilter = new SpamFilter($this->config);
            $headers = ['Subject' => $subject];
            
            $isSpam = $spamFilter->isSpam($headers, $body);
            
            echo "🔍 Spam Filter Test Results:\n";
            echo "Subject: $subject\n";
            echo "Body: " . substr($body, 0, 100) . "...\n";
            echo "Result: " . ($isSpam ? "❌ SPAM" : "✅ CLEAN") . "\n";
            
            if ($isSpam) {
                echo "Reason: " . $spamFilter->getLastSpamReason() . "\n";
            }
            
        } catch (\Exception $e) {
            echo "❌ Spam filter test failed: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * View detection algorithms
     */
    private function viewDetectionAlgorithms(?string $category): void
    {
        try {
            $database = new Database($this->config);
            $algorithms = $database->getDetectionAlgorithms($category);
            
            $title = $category ? "Detection Algorithms - Category: $category" : "All Detection Algorithms";
            echo "📋 $title\n";
            echo str_repeat("=", 80) . "\n";
            
            if (empty($algorithms)) {
                echo "No algorithms found.\n";
                return;
            }
            
            foreach ($algorithms as $algo) {
                echo "ID: " . $algo['id'] . " | Server ID: " . ($algo['server_id'] ?? 'N/A') . "\n";
                echo "Name: " . $algo['name'] . "\n";
                echo "Category: " . $algo['threat_category'] . " | Type: " . $algo['detection_type'] . "\n";
                echo "Target: " . $algo['target'] . " | Score: " . $algo['score'] . "\n";
                echo "Pattern: " . substr($algo['pattern'], 0, 60) . "...\n";
                echo "Enabled: " . ($algo['enabled'] ? 'Yes' : 'No') . " | Priority: " . $algo['priority'] . "\n";
                echo "Created: " . $algo['created_at'] . " | Updated: " . $algo['updated_at'] . "\n";
                echo str_repeat("-", 80) . "\n";
            }
            
            echo "Total: " . count($algorithms) . " algorithms\n";
            
        } catch (\Exception $e) {
            echo "❌ Failed to view algorithms: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * Export detection algorithms
     */
    private function exportDetectionAlgorithms(string $format): void
    {
        try {
            $database = new Database($this->config);
            $algorithms = $database->getDetectionAlgorithms();
            
            $filename = 'detection_algorithms_' . date('Y-m-d_H-i-s');
            
            switch (strtolower($format)) {
                case 'json':
                    $filename .= '.json';
                    $content = json_encode($algorithms, JSON_PRETTY_PRINT);
                    break;
                    
                case 'csv':
                    $filename .= '.csv';
                    $content = $this->arrayToCsv($algorithms);
                    break;
                    
                default:
                    echo "❌ Unsupported format. Use 'json' or 'csv'\n";
                    return;
            }
            
            file_put_contents($filename, $content);
            echo "✅ Algorithms exported to: $filename\n";
            echo "📊 Exported " . count($algorithms) . " algorithms\n";
            
        } catch (\Exception $e) {
            echo "❌ Export failed: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * Show algorithm statistics
     */
    private function showAlgorithmStats(): void
    {
        try {
            $database = new Database($this->config);
            $allAlgorithms = $database->getDetectionAlgorithms();
            
            $categories = [];
            $enabled = 0;
            
            foreach ($allAlgorithms as $algo) {
                $categories[$algo['threat_category']] = ($categories[$algo['threat_category']] ?? 0) + 1;
                if ($algo['enabled']) $enabled++;
            }
            
            echo "📊 Detection Algorithm Statistics:\n";
            echo "Total: " . count($allAlgorithms) . " | Enabled: $enabled\n";
            
            foreach ($categories as $category => $count) {
                echo "$category: $count\n";
            }
            
        } catch (\Exception $e) {
            echo "❌ Failed to get stats: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * Convert array to CSV
     */
    private function arrayToCsv(array $data): string
    {
        if (empty($data)) return '';
        
        $output = fopen('php://temp', 'r+');
        fputcsv($output, array_keys($data[0]));
        
        foreach ($data as $row) {
            fputcsv($output, $row);
        }
        
        rewind($output);
        $csv = stream_get_contents($output);
        fclose($output);
        
        return $csv;
    }


    
    /**
     * Recreate database with all tables
     */
    private function recreateDatabase(): void
    {
        echo "🗑️ Recreating database...\n";
        
        try {
            $dbPath = $this->config['database']['path'];
            
            // Remove existing database
            if (file_exists($dbPath)) {
                unlink($dbPath);
                echo "✅ Old database removed\n";
            }
            
            // Create new database with all tables
            $database = new Database($this->config);
            echo "✅ New database created with all tables\n";
            
            // Set permissions
            exec("sudo chown postfix:postfix " . escapeshellarg($dbPath));
            exec("sudo chmod 664 " . escapeshellarg($dbPath));
            echo "✅ Database permissions set\n";
            
            echo "🎉 Database recreation completed!\n";
            
        } catch (\Exception $e) {
            echo "❌ Database recreation failed: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * Drop a specific table
     */
    private function dropTable(string $tableName): void
    {
        echo "🗑️ Dropping table: $tableName...\n";
        
        try {
            $database = new Database($this->config);
            $pdo = $database->getPDO();
            
            $pdo->exec("DROP TABLE IF EXISTS $tableName");
            echo "✅ Table '$tableName' dropped successfully\n";
            
            // Recreate the table by reinitializing database
            $database = new Database($this->config);
            echo "✅ Table '$tableName' recreated with new structure\n";
            
        } catch (\Exception $e) {
            echo "❌ Failed to drop table: " . $e->getMessage() . "\n";
        }
    }
    
    private function testSpamFilterOld(string $subject, string $body): void
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
                echo "✅ Sudoers rule created: $sudoersFile\n";
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
                    if (!mkdir($dir, 0755, true) && !is_dir($dir)) {
                        throw new \RuntimeException(sprintf('Directory "%s" was not created', $dir));
                    }
                }
                exec("chown -R report-ip:report-ip {$dir}");
                exec("chmod -R 755 {$dir}");
                echo "✅ Log directory: $dir\n";
            }
            
            // 3. Setup database directory
            echo "🗄️ Setting up database...\n";
            $dbPath = $this->config['database']['path'];
            $dbDir = dirname($dbPath);
            
            if (!is_dir($dbDir)) {
                if (!mkdir($dbDir, 0755, true) && !is_dir($dbDir)) {
                    throw new \RuntimeException(sprintf('Directory "%s" was not created', $dbDir));
                }
            }
            
            if (file_exists($dbPath)) {
                exec("chown postfix:postfix {$dbPath}");
                exec("chmod 664 {$dbPath}");
                echo "✅ Database permissions: $dbPath\n";
            }
            
            exec("chown postfix:postfix {$dbDir}");
            exec("chmod 755 {$dbDir}");
            echo "✅ Database directory: $dbDir\n";
            
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
                    if (!mkdir($dir, 0755, true) && !is_dir($dir)) {
                        throw new \RuntimeException(sprintf('Directory "%s" was not created', $dir));
                    }
                }
                
                if (!file_exists($file)) {
                    file_put_contents($file, "# Add entries here\n");
                }
                
                exec("chown report-ip:report-ip {$file}");
                exec("chmod 644 {$file}");
                echo "✅ List file: $file\n";
            }
            
            // 5. Setup project directory
            echo "📂 Setting up project directory...\n";
            $projectDir = '/usr/local/share/cyford/security';
            exec("chown -R report-ip:postfix {$projectDir}");
            exec("find {$projectDir} -type d -exec chmod 775 {} \;");
            exec("find {$projectDir} -type f -exec chmod 664 {} \;");
            // Ensure tasks.json is group writable
            exec("chmod 664 {$projectDir}/tasks.json 2>/dev/null");
            echo "✅ Project directory: $projectDir (group writable)\n";
            
            // 6. Setup task queue permissions
            echo "📋 Setting up task queue permissions...\n";
            $queueDir = '/var/spool/cyford-security';
            if (!is_dir($queueDir)) {
                if (!mkdir($queueDir, 0755, true) && !is_dir($queueDir)) {
                    throw new \RuntimeException(sprintf('Directory "%s" was not created', $queueDir));
                }
            }
            exec("chown root:postfix {$queueDir}");
            exec("chmod 775 {$queueDir}");
            
            $tasksFile = $queueDir . '/tasks.json';
            if (!file_exists($tasksFile)) {
                file_put_contents($tasksFile, '[]');
            }
            exec("chown root:postfix {$tasksFile}");
            exec("chmod 664 {$tasksFile}");
            echo "✅ Task queue permissions: $queueDir\n";
            
            echo "\n🎉 Permission setup completed successfully!\n";
            echo "\n📋 Summary:\n";
            echo "  ✅ Sudoers rule created for report-ip user\n";
            echo "  ✅ Log directories configured\n";
            echo "  ✅ Database permissions set\n";
            echo "  ✅ List files initialized\n";
            echo "  ✅ Project directory permissions set\n";
            echo "  ✅ Task queue permissions configured\n";
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
        
        echo "👤 Creating mail user: $username\n";
        
        try {
            // 1. Create system user
            $userExists = exec("id {$username} 2>/dev/null");
            if (empty($userExists)) {
                exec("useradd -m -s /bin/bash {$username}");
                echo "✅ System user created: $username\n";
            } else {
                echo "ℹ️  System user already exists: $username\n";
            }
            
            // 2. Set password
            exec("echo '{$username}:{$password}' | chpasswd");
            echo "✅ Password set for user: $username\n";
            
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
                    if (!mkdir($dir, 0755, true) && !is_dir($dir)) {
                        throw new \RuntimeException(sprintf('Directory "%s" was not created', $dir));
                    }
                }
            }
            
            exec("chown -R {$username}:{$username} {$maildir}");
            echo "✅ Maildir created: $maildir\n";
            
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
            
            // 6. Reload services (skip in Docker)
            $isDocker = Database::isDocker();
            if (!$isDocker) {
                exec("systemctl reload postfix 2>/dev/null");
                exec("systemctl reload dovecot 2>/dev/null");
            } else {
                echo "ℹ️  Skipping service reload in Docker environment\n";
            }
            
            echo "\n🎉 User created successfully!\n";
            echo "\n📧 Email Details:\n";
            echo "  Email: $username@$domain\n";
            echo "  Password: $password\n";
            echo "  Maildir: $maildir\n";
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
     * Setup user directory permissions for postfix access
     */
    private function setupUserPermissions(string $username): void
    {
        if (empty($username)) {
            echo "❌ Username is required\n";
            echo "Usage: --command=setup-user-permissions --username=allen\n";
            echo "       --command=setup-user-permissions --username=all\n";
            return;
        }
        
        if ($username === 'all') {
            $this->setupAllUserPermissions();
            return;
        }
        
        echo "🔧 Setting up user directory permissions for: $username\n";
        
        try {
            $this->setupSingleUserPermissions($username);
            
            echo "\n🎉 User permissions setup completed!\n";
            echo "\n📧 Configuration:\n";
            echo "  - Postfix user added to {$username} group\n";
            echo "  - Group permissions set on home directory\n";
            echo "  - Maildir accessible to postfix group\n";
            echo "  - Spam folder ready for quarantine\n";
            echo "\n⚙️  Update config.php to use user_maildir method:\n";
            echo "  'quarantine_method' => 'user_maildir'\n";
            
        } catch (Exception $e) {
            echo "❌ User permission setup failed: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * Setup permissions for all users in /home directory
     */
    private function setupAllUserPermissions(): void
    {
        echo "🔧 Setting up user directory permissions for ALL users in /home...\n";
        
        // Get all directories in /home
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
            if (is_dir($userPath)) {
                // Check if it's a real user (has a valid home directory structure)
                if ($this->isValidUserDirectory($userPath)) {
                    $users[] = $dir;
                }
            }
        }
        
        if (empty($users)) {
            echo "ℹ️  No valid user directories found in /home\n";
            return;
        }
        
        echo "👥 Found " . count($users) . " users: " . implode(', ', $users) . "\n\n";
        
        $successCount = 0;
        $failCount = 0;
        
        foreach ($users as $username) {
            echo "🔧 Processing user: $username\n";
            
            try {
                $this->setupSingleUserPermissions($username);
                echo "✅ $username: SUCCESS\n";
                $successCount++;
            } catch (Exception $e) {
                echo "❌ $username: FAILED - " . $e->getMessage() . "\n";
                $failCount++;
            }
            
            echo "\n";
        }
        
        echo "🎉 Bulk user permissions setup completed!\n";
        echo "\n📊 Summary:\n";
        echo "  ✅ Successful: {$successCount} users\n";
        echo "  ❌ Failed: {$failCount} users\n";
        echo "  📊 Total: " . count($users) . " users\n";
        echo "\n⚙️  Update config.php to use user_maildir method:\n";
        echo "  'quarantine_method' => 'user_maildir'\n";
    }
    
    /**
     * Setup permissions for a single user
     */
    private function setupSingleUserPermissions(string $username): void
    {
        // Get maildir path from config
        $maildirTemplate = $this->config['postfix']['spam_handling']['maildir_path'] ?? '/home/{user}/Maildir';
        $userMaildir = str_replace('{user}', $username, $maildirTemplate);
        
        // Add postfix and report-ip users to user's group
        exec("usermod -a -G {$username} postfix 2>&1", $output, $returnCode);
        if ($returnCode === 0) {
            echo "  ✅ Added postfix user to $username group\n";
        } else {
            echo "  ❌ Failed to add postfix to $username group: " . implode(' ', $output) . "\n";
        }
        
        exec("usermod -a -G {$username} report-ip 2>&1", $output2, $returnCode2);
        if ($returnCode2 === 0) {
            echo "  ✅ Added report-ip user to $username group\n";
        } else {
            echo "  ❌ Failed to add report-ip to $username group: " . implode(' ', $output2) . "\n";
        }
        
        // Verify group memberships
        exec("groups postfix", $postfixGroups);
        exec("groups report-ip", $reportIpGroups);
        
        $postfixGroupsStr = implode(' ', $postfixGroups);
        $reportIpGroupsStr = implode(' ', $reportIpGroups);
        
        if (strpos($postfixGroupsStr, $username) !== false) {
            echo "  ✅ Verified: postfix is in $username group\n";
        } else {
            echo "  ❌ Warning: postfix not found in $username group\n";
            echo "  📝 postfix groups: $postfixGroupsStr\n";
        }
        
        if (strpos($reportIpGroupsStr, $username) !== false) {
            echo "  ✅ Verified: report-ip is in $username group\n";
        } else {
            echo "  ❌ Warning: report-ip not found in $username group\n";
            echo "  📝 report-ip groups: $reportIpGroupsStr\n";
        }
        
        // Set group permissions on user's home directory
        if (is_dir("/home/{$username}")) {
            exec("chmod g+rx /home/{$username}");
            echo "  ✅ Set group read/execute on /home/$username\n";
        }
        
        // Set group permissions on maildir - change group to postfix for all subdirectories
        if (is_dir($userMaildir)) {
            exec("chmod -R g+rwx {$userMaildir}");
            exec("find {$userMaildir} -type d -name '.*' -exec chgrp postfix {} \;");
            echo "  ✅ Set group permissions and changed subdirectory groups to postfix: $userMaildir\n";
        } else {
            echo "  ℹ️  Maildir $userMaildir doesn't exist yet\n";
        }
        
        // Detect existing spam folders
        $spamFolderCandidates = [
            '.Spambox',     // Existing folder
            '.Spam',        // Common name
            '.Junk',        // Thunderbird
            '.Junk Email',  // Outlook
            '.INBOX.Spam',  // IMAP
            '.INBOX.Junk'   // IMAP
        ];
        
        $existingSpamFolder = null;
        foreach ($spamFolderCandidates as $candidate) {
            $candidatePath = $userMaildir . '/' . $candidate;
            if (is_dir($candidatePath)) {
                $existingSpamFolder = $candidatePath;
                echo "  📬 Found existing spam folder: $candidate\n";
                break;
            }
        }
        
        if ($existingSpamFolder) {
            // Fix permissions on existing folder - use postfix group
            exec("chown -R {$username}:postfix {$existingSpamFolder}");
            exec("chmod -R g+rwx {$existingSpamFolder}");
            echo "  ✅ Fixed permissions on existing spam folder (postfix group): $existingSpamFolder\n";
        } else {
            // Create default spam folder using sudo for proper ownership
            $spamFolder = $userMaildir . '/.Spam';
            if (is_dir($userMaildir)) {
                $createCommands = [
                    "sudo -u {$username} mkdir -p {$spamFolder}",
                    "sudo -u {$username} mkdir -p {$spamFolder}/cur",
                    "sudo -u {$username} mkdir -p {$spamFolder}/new",
                    "sudo -u {$username} mkdir -p {$spamFolder}/tmp"
                ];
                
                $success = true;
                foreach ($createCommands as $cmd) {
                    exec($cmd, $output, $returnCode);
                    if ($returnCode !== 0) {
                        $success = false;
                        break;
                    }
                }
                
                if ($success) {
                    exec("chgrp -R postfix {$spamFolder}");
                    exec("chmod -R g+rwx {$spamFolder}");
                    echo "  ✅ Created spam folder with postfix group: $spamFolder\n";
                } else {
                    echo "  ❌ Failed to create spam folder\n";
                }
            }
        }
    }
    
    /**
     * Check if a directory is a valid user directory
     */
    private function isValidUserDirectory(string $userPath): bool
    {
        // Check if it has typical user directory characteristics
        $username = basename($userPath);
        
        // Skip system directories
        $systemDirs = ['lost+found', 'ftp', 'www', 'backup', 'tmp', 'skel'];
        if (in_array($username, $systemDirs)) {
            return false;
        }
        
        // Skip usernames that are too short or contain invalid characters
        if (strlen($username) < 2 || !preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
            return false;
        }
        
        // Check if user exists in system using id command
        exec("id {$username} 2>/dev/null", $output, $returnCode);
        if ($returnCode !== 0) {
            return false;
        }
        
        // Check if directory looks like a home directory (has typical structure)
        $hasHomeStructure = false;
        $homeIndicators = ['.bashrc', '.profile', '.bash_profile', 'Maildir', 'Maildir-cyford', '.ssh'];
        
        foreach ($homeIndicators as $indicator) {
            if (file_exists($userPath . '/' . $indicator)) {
                $hasHomeStructure = true;
                break;
            }
        }
        
        return $hasHomeStructure;
    }

    /**
     * Setup Sieve rules for spam filtering
     */
    private function setupSieveRules(string $username): void
    {
        if (empty($username)) {
            echo "❌ Username is required\n";
            echo "Usage: --command=setup-sieve-rules --username=allen\n";
            echo "       --command=setup-sieve-rules --username=all\n";
            return;
        }
        
        // Check and install Dovecot Sieve requirements first
        if (!$this->checkAndInstallSieveRequirements()) {
            echo "❌ Failed to install Sieve requirements\n";
            return;
        }
        
        if ($username === 'all') {
            $this->setupSieveRulesForAllUsers();
            return;
        }
        
        echo "📧 Setting up Sieve spam filtering rules for: $username\n";
        
        try {
            $this->setupSingleUserSieveRules($username);
            echo "\n🎉 Sieve rules setup completed for $username!\n";
        } catch (Exception $e) {
            echo "❌ Sieve rules setup failed: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * Check and install Dovecot Sieve requirements
     */
    private function checkAndInstallSieveRequirements(): bool
    {
        echo "🔍 Checking Dovecot Sieve requirements...\n";
        
        // Check if Dovecot is installed
        $isDocker = Database::isDocker();
        if (!$isDocker) {
            exec("systemctl is-active dovecot 2>/dev/null", $output, $returnCode);
            if ($returnCode !== 0) {
                echo "❌ Dovecot is not running. Please install and start Dovecot first.\n";
                return false;
            }
        }
        echo "✅ Dovecot is running\n";
        
        // Check if sievec command exists
        exec("which sievec 2>/dev/null", $sievecPath, $sievecReturn);
        if ($sievecReturn !== 0) {
            echo "📦 Installing Dovecot Pigeonhole (Sieve)...\n";
            
            // Try different package managers
            $installCommands = [
                'dnf install -y dovecot-pigeonhole',
                'yum install -y dovecot-pigeonhole',
                'apt-get install -y dovecot-sieve dovecot-managesieved'
            ];
            
            $installed = false;
            foreach ($installCommands as $cmd) {
                exec($cmd . ' 2>/dev/null', $installOutput, $installReturn);
                if ($installReturn === 0) {
                    echo "✅ Installed Dovecot Sieve successfully\n";
                    $installed = true;
                    break;
                }
            }
            
            if (!$installed) {
                echo "❌ Failed to install Dovecot Sieve. Please install manually:\n";
                echo "  Rocky/RHEL: dnf install dovecot-pigeonhole\n";
                echo "  Ubuntu/Debian: apt-get install dovecot-sieve dovecot-managesieved\n";
                return false;
            }
        } else {
            echo "✅ Dovecot Sieve command is available\n";
        }
        
        // Verify Sieve plugin files exist
        $sievePluginPaths = [
            '/usr/lib64/dovecot/lib90_sieve_plugin.so',
            '/usr/lib64/dovecot/lib20_sieve_plugin.so',
            '/usr/lib/dovecot/lib90_sieve_plugin.so',
            '/usr/lib/dovecot/lib20_sieve_plugin.so'
        ];
        
        $pluginFound = false;
        foreach ($sievePluginPaths as $pluginPath) {
            if (file_exists($pluginPath)) {
                echo "✅ Found Sieve plugin: $pluginPath\n";
                $pluginFound = true;
                break;
            }
        }
        
        if (!$pluginFound) {
            echo "❌ Sieve plugin files not found. Checking what was installed...\n";
            exec('find /usr/lib* -name "*sieve*" 2>/dev/null', $findOutput);
            if (!empty($findOutput)) {
                echo "ℹ️  Found Sieve-related files:\n";
                foreach ($findOutput as $file) {
                    echo "    $file\n";
                }
            }
            echo "⚠️  Sieve plugin may not work properly\n";
        }
        
        // Check version compatibility
        exec('dovecot --version 2>/dev/null', $dovecotVersion);
        exec('rpm -q dovecot dovecot-pigeonhole 2>/dev/null', $packageVersions);
        
        if (!empty($dovecotVersion) && !empty($packageVersions)) {
            echo "ℹ️  Dovecot version: " . implode(' ', $dovecotVersion) . "\n";
            foreach ($packageVersions as $pkg) {
                echo "ℹ️  Package: $pkg\n";
            }
            
            // Check for version mismatch
            $dovecotPkg = array_filter($packageVersions, function($pkg) { return strpos($pkg, 'dovecot-2') === 0; });
            $pigeonholePkg = array_filter($packageVersions, function($pkg) { return strpos($pkg, 'dovecot-pigeonhole') === 0; });
            
            if (!empty($dovecotPkg) && !empty($pigeonholePkg)) {
                $dovecotVer = reset($dovecotPkg);
                $pigeonholeVer = reset($pigeonholePkg);
                
                // Extract version numbers for comparison
                preg_match('/dovecot-([0-9.]+)/', $dovecotVer, $doveMatches);
                preg_match('/dovecot-pigeonhole-([0-9.]+)/', $pigeonholeVer, $pigeonMatches);
                
                if (!empty($doveMatches[1]) && !empty($pigeonMatches[1])) {
                    if ($doveMatches[1] !== $pigeonMatches[1]) {
                        echo "⚠️  WARNING: Version mismatch detected!\n";
                        echo "    Dovecot: " . $doveMatches[1] . "\n";
                        echo "    Pigeonhole: " . $pigeonMatches[1] . "\n";
                        echo "    This may cause symbol errors. Consider reinstalling matching versions.\n";
                        
                        // Offer to fix version mismatch
                        echo "🔧 Attempting to fix version mismatch...\n";
                        exec('dnf reinstall -y dovecot dovecot-pigeonhole 2>/dev/null', $reinstallOutput, $reinstallReturn);
                        if ($reinstallReturn === 0) {
                            echo "✅ Reinstalled packages with matching versions\n";
                        } else {
                            echo "❌ Failed to reinstall packages\n";
                        }
                    } else {
                        echo "✅ Dovecot and Pigeonhole versions match\n";
                    }
                }
            }
        }
        
        // Configure Dovecot for Sieve
        $this->configureDovecotSieve();
        
        // Configure Postfix for dovecot-lda if needed
        $this->configurePostfixForDovecotLDA();
        
        return true;
    }
    
    /**
     * Configure Dovecot for Sieve support
     */
    private function configureDovecotSieve(): void
    {
        echo "⚙️  Configuring Dovecot Sieve...\n";
        
        // Enable ManageSieve protocol in main dovecot.conf
        $dovecotConf = '/etc/dovecot/dovecot.conf';
        if (file_exists($dovecotConf)) {
            $content = file_get_contents($dovecotConf);
            if (strpos($content, 'protocols') !== false) {
                // Add sieve to protocols if not already there
                if (strpos($content, 'sieve') === false) {
                    $content = preg_replace('/^(#?protocols\s*=.*?)$/m', '$1 sieve', $content);
                    $content = str_replace('#protocols', 'protocols', $content);
                    file_put_contents($dovecotConf, $content);
                    echo "✅ Enabled sieve protocol in dovecot.conf\n";
                }
            }
        }
        
        // Enable ManageSieve service in 20-managesieve.conf
        $managesieveConf = '/etc/dovecot/conf.d/20-managesieve.conf';
        if (file_exists($managesieveConf)) {
            $content = file_get_contents($managesieveConf);
            
            // Uncomment ManageSieve service configuration with proper braces
            // Also enable the protocols line
            $content = str_replace(array('#  inet_listener sieve {', '#    port = 4190', '#  }', '#protocols = $protocols sieve'), array('  inet_listener sieve {', '    port = 4190', '  }', 'protocols = $protocols sieve'), $content);
            
            file_put_contents($managesieveConf, $content);
            echo "✅ Enabled ManageSieve service in 20-managesieve.conf\n";
        }
        
        // Create Sieve configuration file
        $sieveConfigFile = '/etc/dovecot/conf.d/99-cyford-sieve.conf';
        
        if (!file_exists($sieveConfigFile)) {
            $sieveConfig = <<<'DOVECOT'
# Cyford Web Armor Sieve Configuration
# Auto-generated - Safe to remove if not needed

# CRITICAL: Explicitly override IMAP to NOT load sieve plugin
protocol imap {
  mail_plugins = 
}

# Enable Sieve plugin for LDA (Local Delivery Agent)
protocol lda {
  mail_plugins = $mail_plugins sieve
}

# Enable Sieve plugin for LMTP
protocol lmtp {
  mail_plugins = $mail_plugins sieve
}

# Sieve plugin settings
plugin {
  sieve = ~/.dovecot.sieve
  sieve_dir = ~/sieve
  sieve_max_script_size = 1M
  sieve_max_actions = 32
  sieve_max_redirects = 4
}
DOVECOT;
            
            file_put_contents($sieveConfigFile, $sieveConfig);
            echo "✅ Created Sieve configuration file: $sieveConfigFile\n";
        } else {
            echo "ℹ️  Sieve configuration already exists\n";
        }
        
        // Test configuration before restarting
        exec('doveconf -n > /dev/null 2>&1', $testOutput, $testReturn);
        if ($testReturn !== 0) {
            echo "❌ Dovecot configuration test failed, rolling back changes\n";
            unlink($sieveConfigFile);
            return;
        }
        
        // Restart Dovecot to apply changes (skip in Docker)
        $isDocker = Database::isDocker();
        if (!$isDocker) {
            exec('systemctl restart dovecot 2>/dev/null', $restartOutput, $restartReturn);
            if ($restartReturn === 0) {
                echo "✅ Restarted Dovecot successfully\n";
            } else {
                echo "❌ Dovecot restart failed, rolling back changes\n";
                unlink($sieveConfigFile);
                exec('systemctl restart dovecot 2>/dev/null');
                return;
            }
        } else {
            echo "ℹ️ Skipping Dovecot restart in Docker environment\n";
        }
        
        // Verify Dovecot is running without errors
        sleep(2);
        exec('systemctl is-active dovecot 2>/dev/null', $statusOutput, $statusReturn);
        if ($statusReturn !== 0) {
            echo "❌ Dovecot failed to start properly, rolling back changes\n";
            unlink($sieveConfigFile);
            exec('systemctl restart dovecot 2>/dev/null');
            return;
        }
        
        // Check for global sieve plugins that cause IMAP loading issues
        $globalSieveFiles = [
            '/etc/dovecot/conf.d/10-mail.conf',
            '/etc/dovecot/conf.d/20-lmtp.conf',
            '/etc/dovecot/conf.d/15-lda.conf'
        ];
        
        foreach ($globalSieveFiles as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                if (strpos($content, 'mail_plugins') !== false && strpos($content, 'sieve') !== false) {
                    echo "⚠️  Found global sieve plugin in $file\n";
                    // Remove sieve from global mail_plugins to prevent IMAP loading
                    $content = preg_replace('/mail_plugins\s*=\s*\$mail_plugins\s+sieve/', 'mail_plugins = $mail_plugins', $content);
                    $content = preg_replace('/mail_plugins\s*=\s*sieve/', 'mail_plugins = ', $content);
                    file_put_contents($file, $content);
                    echo "✅ Removed global sieve plugin from $file\n";
                }
            }
        }
        
        // Test for IMAP sieve loading errors
        exec('journalctl -u dovecot --since "1 minute ago" | grep -i "sieve.*symbol" 2>/dev/null', $errorCheck);
        if (!empty($errorCheck)) {
            echo "❌ Detected sieve symbol errors, rolling back changes\n";
            unlink($sieveConfigFile);
            exec('systemctl restart dovecot 2>/dev/null');
            return;
        }
        
        echo "✅ Dovecot Sieve configuration completed successfully\n";
    }
    
    /**
     * Configure Postfix for dovecot-lda requeue method
     */
    private function configurePostfixForDovecotLDA(): void
    {
        $requeueMethod = $this->config['postfix']['requeue_method'] ?? 'smtp';
        if ($requeueMethod !== 'dovecot-lda') {
            return;
        }
        
        $allowModification = $this->config['postfix']['allow_modification'] ?? false;
        if (!$allowModification) {
            echo "ℹ️  To enable Sieve filtering, set 'allow_modification' => true or manually add:\n";
            echo "mailbox_command = /usr/lib/dovecot/dovecot-lda -f \$SENDER -a \$RECIPIENT\n";
            return;
        }
        
        echo "📧 Configuring Postfix for dovecot-lda delivery...\n";
        
        $mainConfig = $this->config['postfix']['main_config'];
        if (!file_exists($mainConfig)) {
            echo "❌ Postfix main.cf not found\n";
            return;
        }
        
        $content = file_get_contents($mainConfig);
        
        // Check if already configured with wrapper
        if (strpos($content, 'cyford-dovecot-lda') !== false) {
            echo "✅ Postfix already configured with Cyford dovecot-lda wrapper\n";
            return;
        }
        
        // Find dovecot-lda path
        $ldaPaths = ['/usr/lib/dovecot/dovecot-lda', '/usr/libexec/dovecot/dovecot-lda'];
        $ldaPath = null;
        foreach ($ldaPaths as $path) {
            if (file_exists($path)) {
                $ldaPath = $path;
                break;
            }
        }
        
        if (!$ldaPath) {
            echo "❌ dovecot-lda not found\n";
            return;
        }
        
        // Remove existing mailbox_command and home_mailbox
        $content = preg_replace('/^mailbox_command\s*=.*$/m', '', $content);
        $content = preg_replace('/^home_mailbox\s*=.*$/m', '', $content);
        
        // Create wrapper script for dovecot-lda
        $wrapperScript = '/usr/local/bin/cyford-dovecot-lda';
        $this->createDovecotLDAWrapper($ldaPath, $wrapperScript);
        
        // Add dovecot-lda configuration using wrapper
        $content .= "\n# Dovecot LDA for Sieve filtering\nmailbox_command = {$wrapperScript} \$SENDER \$USER\n";
        
        file_put_contents($mainConfig, $content);
        echo "✅ Configured Postfix for dovecot-lda: $ldaPath\n";
        
        $isDocker = Database::isDocker();
        if (!$isDocker) {
            exec('systemctl reload postfix 2>/dev/null');
            echo "✅ Postfix reloaded\n";
        } else {
            echo "ℹ️ Skipping Postfix reload in Docker environment\n";
        }
    }
    
    /**
     * Complete Dovecot Sieve setup
     */
    private function setupDovecotSieve(): void
    {
        echo "🚀 Starting complete Dovecot Sieve setup...\n";
        
        $systems = new Systems();
        $osInfo = $systems->getOSInfo();
        echo "🔍 Detected OS: " . $osInfo['os'] . "\n";
        
        $allowModification = $this->config['postfix']['allow_modification'] ?? false;
        if (!$allowModification) {
            echo "❌ Auto-configuration disabled. Set 'allow_modification' => true in config.php\n";
            return;
        }
        
        try {
            // 1. Check/Install Dovecot
            echo "\n📦 Step 1: Installing Dovecot and Sieve...\n";
            $this->installDovecotAndSieve($systems);
            
            // 2. Configure Dovecot Sieve
            echo "\n⚙️  Step 2: Configuring Dovecot Sieve...\n";
            $this->configureDovecotSieve();
            
            // 3. Setup permissions
            echo "\n🔒 Step 3: Setting up permissions...\n";
            $this->setupDovecotPermissions();
            
            // 4. Configure Postfix for dovecot-lda
            echo "\n📧 Step 4: Configuring Postfix...\n";
            $this->configurePostfixForDovecotLDA();
            
            echo "\n🎉 Dovecot Sieve setup completed successfully!\n";
            echo "\n📝 Next steps:\n";
            echo "  1. Run: --command=setup-sieve-rules --username=all\n";
            echo "  2. Test spam filtering\n";
            echo "\nℹ️  Note: Postfix configured to use dovecot-lda for local delivery\n";
            echo "  Spam emails will be filtered by Sieve rules automatically\n";
            
        } catch (Exception $e) {
            echo "❌ Setup failed: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * Install Dovecot and Sieve
     */
    private function installDovecotAndSieve(Systems $systems): void
    {
        // Check if Dovecot is installed
        exec('which dovecot 2>/dev/null', $dovecotPath, $dovecotExists);
        if ($dovecotExists !== 0) {
            echo "📦 Installing Dovecot...\n";
            if (!$this->installPackage('dovecot', $systems)) {
                throw new Exception('Failed to install Dovecot');
            }
        } else {
            echo "✅ Dovecot is already installed\n";
        }
        
        // Check if Sieve is installed
        exec('which sievec 2>/dev/null', $sievecPath, $sievecExists);
        if ($sievecExists !== 0) {
            echo "📦 Installing Dovecot Sieve...\n";
            if (!$this->installDovecotSieve($systems)) {
                throw new Exception('Failed to install Dovecot Sieve');
            }
        } else {
            echo "✅ Dovecot Sieve is already installed\n";
        }
        
        // Start Dovecot if not running (skip in Docker)
        $isDocker = Database::isDocker();
        if (!$isDocker) {
            exec('systemctl is-active dovecot 2>/dev/null', $output, $returnCode);
            if ($returnCode !== 0) {
                echo "🚀 Starting Dovecot...\n";
                exec('systemctl enable dovecot && systemctl start dovecot 2>/dev/null');
            }
        }
    }
    
    /**
     * Install package based on OS
     */
    private function installPackage(string $package, Systems $systems): bool
    {
        $osInfo = $systems->getOSInfo();
        $osName = strtolower($osInfo['os']);
        
        if (stripos($osName, 'linux') !== false) {
            // Try Rocky/RHEL first
            exec("dnf install -y {$package} 2>/dev/null", $output, $return);
            if ($return === 0) return true;
            
            // Try older RHEL
            exec("yum install -y {$package} 2>/dev/null", $output, $return);
            if ($return === 0) return true;
            
            // Try Debian/Ubuntu
            exec("apt-get update && apt-get install -y {$package} 2>/dev/null", $output, $return);
            if ($return === 0) return true;
        }
        
        return false;
    }
    
    /**
     * Aggressively fix all Dovecot permission issues
     */
    private function fixDovecotPermissions(): void
    {
        echo "🔧 Aggressively fixing all Dovecot permission issues...\n";
        
        // Stop dovecot first (skip in Docker)
        $isDocker = Database::isDocker();
        if (!$isDocker) {
            exec('systemctl stop dovecot 2>/dev/null');
            echo "⏹️  Stopped Dovecot\n";
        }
        
        // Fix all log files and directories
        $commands = [
            'mkdir -p /var/log/dovecot /var/log/dovcot',
            'touch /var/log/dovecot/error.log /var/log/dovcot/error.log',
            'touch /var/log/dovecot/info.log /var/log/dovcot/info.log',
            'chown -R dovecot:mail /var/log/dovecot /var/log/dovcot',
            'chmod -R 777 /var/log/dovecot /var/log/dovcot',
            'find /var/log -name "*dovecot*" -o -name "*dovcot*" | xargs chmod 777 2>/dev/null',
            'find /var/log -name "*dovecot*" -o -name "*dovcot*" | xargs chown dovecot:mail 2>/dev/null'
        ];
        
        foreach ($commands as $cmd) {
            exec($cmd . ' 2>/dev/null');
        }
        echo "✅ Fixed all log file permissions (777)\n";
        
        // Start dovecot (skip in Docker)
        if (!$isDocker) {
            exec('systemctl start dovecot 2>/dev/null');
            echo "▶️  Started Dovecot\n";
        }
        
        // Wait and fix runtime permissions
        sleep(3);
        
        $runtimeCommands = [
            'chown -R dovecot:mail /run/dovecot 2>/dev/null',
            'chmod -R 777 /run/dovecot 2>/dev/null',
            'find /run/dovecot -type s -exec chmod 777 {} \; 2>/dev/null',
            'find /run/dovecot -type f -exec chmod 777 {} \; 2>/dev/null'
        ];
        
        foreach ($runtimeCommands as $cmd) {
            exec($cmd);
        }
        echo "✅ Fixed all runtime socket permissions (777)\n";
        
        // Test dovecot-lda manually
        echo "\n🧪 Testing dovecot-lda manually...\n";
        exec('echo "test" | /usr/libexec/dovecot/dovecot-lda -d allen -f test@example.com 2>&1', $testOutput, $testReturn);
        
        if ($testReturn === 0) {
            echo "✅ dovecot-lda test successful\n";
        } else {
            echo "❌ dovecot-lda test failed:\n";
            foreach ($testOutput as $line) {
                echo "  {$line}\n";
            }
        }
        
        echo "\n🎉 Aggressive permission fix completed!\n";
        echo "All permissions set to 777 for maximum compatibility.\n";
    }
    
    /**
     * Create dovecot-lda wrapper script
     */
    private function createDovecotLDAWrapper(?string $ldaPath = null, string $wrapperScript = '/usr/local/bin/cyford-dovecot-lda'): void
    {
        if (!$ldaPath) {
            // Find dovecot-lda path
            $ldaPaths = ['/usr/lib/dovecot/dovecot-lda', '/usr/libexec/dovecot/dovecot-lda'];
            foreach ($ldaPaths as $path) {
                if (file_exists($path)) {
                    $ldaPath = $path;
                    break;
                }
            }
        }
        
        if (!$ldaPath) {
            echo "❌ dovecot-lda not found, skipping wrapper creation\n";
            return;
        }
        
        $wrapperContent = <<<BASH
#!/bin/bash
# Cyford Security dovecot-lda wrapper
# Extracts username from email address for proper delivery

# \$1 = sender, \$2 = recipient (full email)
SENDER="\$1"
RECIPIENT="\$2"

# Extract username from email address
USERNAME=\$(echo "\$RECIPIENT" | cut -d'@' -f1)

# Run dovecot-lda with proper arguments
exec {$ldaPath} -d "\$USERNAME" -f "\$SENDER"
BASH;
        
        file_put_contents($wrapperScript, $wrapperContent);
        chmod($wrapperScript, 0755);
        echo "✅ Created dovecot-lda wrapper: {$wrapperScript}\n";
    }
    
    /**
     * Setup Dovecot permissions for report-ip user
     */
    private function setupDovecotPermissions(): void
    {
        // Add report-ip to mail and dovecot groups
        exec('usermod -a -G mail report-ip 2>/dev/null');
        exec('usermod -a -G dovecot report-ip 2>/dev/null');
        echo "✅ Added report-ip to mail and dovecot groups\n";
        
        // Set group permissions on dovecot-lda binary
        $ldaPaths = ['/usr/lib/dovecot/dovecot-lda', '/usr/libexec/dovecot/dovecot-lda'];
        foreach ($ldaPaths as $ldaPath) {
            if (file_exists($ldaPath)) {
                exec("chgrp mail {$ldaPath}");
                exec("chmod g+x {$ldaPath}");
                echo "✅ Set group permissions on $ldaPath\n";
                break;
            }
        }
        
        // Fix dovecot log files and directories (handle typo in dovecot config)
        $logDirs = ['/var/log/dovecot', '/var/log/dovcot'];
        $logFiles = [
            '/var/log/dovecot/error.log',
            '/var/log/dovcot/error.log',
            '/var/log/dovecot/info.log',
            '/var/log/dovcot/info.log',
            '/var/log/dovecot/debug.log',
            '/var/log/dovcot/debug.log'
        ];
        
        // Create and fix log directories
        foreach ($logDirs as $dir) {
            if (!is_dir($dir)) {
                if (!mkdir($dir, 0775, true) && !is_dir($dir)) {
                    throw new \RuntimeException(sprintf('Directory "%s" was not created', $dir));
                }
            }
            exec("chown dovecot:mail {$dir}");
            exec("chmod 775 {$dir}");
        }
        
        // Fix existing log files and create missing ones
        foreach ($logFiles as $file) {
            $dir = dirname($file);
            if (!is_dir($dir)) {
                if (!mkdir($dir, 0775, true) && !is_dir($dir)) {
                    throw new \RuntimeException(sprintf('Directory "%s" was not created', $dir));
                }
                exec("chown dovecot:mail {$dir}");
            }
            
            if (!file_exists($file)) {
                touch($file);
            }
            exec("chown dovecot:mail {$file}");
            exec("chmod 666 {$file}");
        }
        echo "✅ Fixed Dovecot log file permissions\n";
        
        // Set permissions on dovecot socket directory and files
        $socketDir = '/run/dovecot';
        if (is_dir($socketDir)) {
            exec("chgrp -R mail {$socketDir}");
            exec("chmod -R g+rw {$socketDir}");
            // Fix specific socket files that may exist
            exec("find {$socketDir} -type s -exec chmod g+rw {} \;");
            exec("find {$socketDir} -type f -exec chmod g+rw {} \;");
            echo "✅ Fixed Dovecot socket directory permissions\n";
        }
        
        // Create dovecot-lda wrapper script
        $this->createDovecotLDAWrapper();
        
        // Fix any remaining permission issues
        exec('find /var/log -name "*dovecot*" -o -name "*dovcot*" | xargs chown dovecot:mail 2>/dev/null');
        exec('find /var/log -name "*dovecot*" -o -name "*dovcot*" | xargs chmod 666 2>/dev/null');
        
        // Restart dovecot to apply permission changes (skip in Docker)
        $isDocker = Database::isDocker();
        if (!$isDocker) {
            exec('systemctl restart dovecot 2>/dev/null');
            echo "✅ Restarted Dovecot to apply permissions\n";
        }
        
        // Wait for dovecot to start and fix runtime permissions
        sleep(2);
        if (is_dir('/run/dovecot')) {
            exec('chgrp -R mail /run/dovecot 2>/dev/null');
            exec('chmod -R g+rw /run/dovecot 2>/dev/null');
            echo "✅ Fixed runtime socket permissions\n";
        }
    }

    /**
     * Setup Sieve rules for all users
     */
    private function setupSieveRulesForAllUsers(): void
    {
        echo "📧 Setting up Sieve spam filtering rules for ALL users...\n";
        
        // Get all users from /home directory
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
        
        if (empty($users)) {
            echo "ℹ️  No valid user directories found in /home\n";
            return;
        }
        
        echo "👥 Found " . count($users) . " users: " . implode(', ', $users) . "\n\n";
        
        $successCount = 0;
        $failCount = 0;
        
        foreach ($users as $user) {
            echo "📧 Processing user: $user\n";
            
            try {
                $this->setupSingleUserSieveRules($user);
                echo "✅ $user: SUCCESS\n";
                $successCount++;
            } catch (Exception $e) {
                echo "❌ $user: FAILED - " . $e->getMessage() . "\n";
                $failCount++;
            }
            
            echo "\n";
        }
        
        echo "🎉 Bulk Sieve rules setup completed!\n";
        echo "\n📊 Summary:\n";
        echo "  ✅ Successful: {$successCount} users\n";
        echo "  ❌ Failed: {$failCount} users\n";
        echo "  📊 Total: " . count($users) . " users\n";
    }
    
    /**
     * Setup Sieve rules for a single user
     */
    private function setupSingleUserSieveRules(string $username): void
    {
        // Check if user exists
        exec("id {$username} 2>/dev/null", $output, $returnCode);
        if ($returnCode !== 0) {
            throw new Exception("User $username does not exist");
        }
        
        // Get user's home directory
        $homeDir = "/home/{$username}";
        if (!is_dir($homeDir)) {
            throw new Exception("Home directory $homeDir does not exist");
        }
        
        // Create sieve directory if it doesn't exist
        $sieveDir = "{$homeDir}/.dovecot.sieve.d";
        if (!is_dir($sieveDir)) {
            exec("sudo -u {$username} mkdir -p {$sieveDir}");
            echo "  📁 Created sieve directory: {$sieveDir}\n";
        }
        
        // Path to main sieve script
        $sieveScript = "{$homeDir}/.dovecot.sieve";
        $spamSieveScript = "{$sieveDir}/spam-filter.sieve";
        
        // Create simple main sieve script directly (no subdirectory approach)
        $spamRules = $this->generateSpamSieveRules();
        
        if (file_exists($sieveScript)) {
            $existingContent = file_get_contents($sieveScript);
            if (strpos($existingContent, 'X-Spam-Flag') !== false) {
                echo "  ℹ️  Spam filtering rules already exist in: $sieveScript\n";
                return;
            }
        }
        
        // Write spam filtering rules directly to main sieve script
        file_put_contents($sieveScript, $spamRules);
        exec("chown {$username}:{$username} {$sieveScript}");
        exec("chmod 644 {$sieveScript}");
        echo "  ✅ Created sieve script: $sieveScript\n";
        
        // Create sieve directory for future use
        $sieveDir = "{$homeDir}/sieve";
        if (!is_dir($sieveDir)) {
            exec("sudo -u {$username} mkdir -p {$sieveDir}");
            echo "  📁 Created sieve directory: {$sieveDir}\n";
        }
        
        // Compile sieve script
        exec("sudo -u {$username} sievec {$sieveScript} 2>/dev/null", $compileOutput, $compileReturn);
        if ($compileReturn === 0) {
            echo "  ✅ Compiled sieve script successfully\n";
        } else {
            echo "  ⚠️  Sieve compilation may have issues\n";
            // Try manual compilation
            exec("sievec {$sieveScript} 2>&1", $manualCompile, $manualReturn);
            if ($manualReturn === 0) {
                exec("chown {$username}:{$username} {$sieveScript}c");
                echo "  ✅ Manual compilation successful\n";
            } else {
                echo "  ❌ Compilation failed: " . implode(' ', $manualCompile) . "\n";
            }
        }
        
        // Reload Dovecot to pick up changes (skip in Docker)
        $isDocker = Database::isDocker();
        if (!$isDocker) {
            exec("systemctl reload dovecot 2>/dev/null");
            echo "  🔄 Reloaded Dovecot configuration\n";
        }
    }
    
    /**
     * Generate spam filtering Sieve rules
     */
    private function generateSpamSieveRules(): string
    {
        return <<<'SIEVE'
# Cyford Web Armor Spam Filtering Rules
# Auto-generated - Do not edit manually

require ["fileinto", "mailbox"];

# Move emails marked as spam by Cyford Web Armor
if header :contains "X-Spam-Flag" "YES" {
    # Create Spambox folder if it doesn't exist
    if not mailboxexists "Spambox" {
        mailboxcreate "Spambox";
    }
    fileinto "Spambox";
    stop;
}

# Also check for SpamAssassin compatibility
if header :contains "X-Spam-Status" "Yes" {
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
    }
    
    /**
     * Generate main Sieve script that includes spam filter
     */
    private function generateMainSieveScript(): string
    {
        return <<<'SIEVE'
# Main Sieve Script - Auto-generated by Cyford Web Armor
require ["include"];

# Include spam filtering rules
include :personal "spam-filter";

# Add your custom rules below this line
SIEVE;
    }

    /**
     * Perform complete system inventory
     */
    private function performSystemInventory(): void
    {
        $systems = new Systems();
        $systems->performSystemInventory();
    }
    
    /**
     * Setup task queue system
     */
    private function setupTaskQueue(): void
    {
        $systems = new Systems();
        $systems->setupTaskQueue($this->config);
    }
    
    /**
     * Check cron job status
     */
    private function checkCronStatus(): void
    {
        $systems = new Systems();
        $systems->checkCronStatus();
    }
    
    /**
     * Check task queue status
     */
    private function checkQueueStatus(): void
    {
        $systems = new Systems();
        $systems->checkQueueStatus();
    }
    
    /**
     * Check cron job processing log
     */
    private function checkCronLog(): void
    {
        $systems = new Systems();
        $systems->checkCronLog();
    }
    
    /**
     * Backup config settings
     */
    private function backupConfig(): void
    {
        $systems = new Systems();
        $systems->backupConfig();
    }
    
    /**
     * Restore config from backup
     */
    private function restoreConfig(?string $backupFile): void
    {
        $systems = new Systems();
        $systems->restoreConfig($backupFile);
    }
    
    /**
     * Merge config after git pull
     */
    private function mergeConfig(): void
    {
        $systems = new Systems();
        $systems->mergeConfigAfterGitPull();
    }
    
    /**
     * List config backups
     */
    private function listBackups(): void
    {
        $systems = new Systems();
        $systems->listConfigBackups();
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
        echo "  setup-user-permissions - Setup user directory permissions for postfix (--username=user or --username=all)\n";
        echo "  setup-sieve-rules      - Setup Dovecot Sieve spam filtering rules (--username=user or --username=all)\n";
        echo "  setup-dovecot-sieve    - Complete Dovecot Sieve setup (install, configure, permissions)\n";
        echo "  fix-dovecot-permissions - Fix Dovecot permission issues\n";
        echo "  system-inventory       - Perform complete system inventory\n";
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
        echo "  php index.php --input_type=internal --command=setup-user-permissions --username=all\n";
        echo "  php index.php --input_type=internal --command=setup-sieve-rules --username=all\n";
        echo "  php index.php --input_type=internal --command=setup-dovecot-sieve\n";
        echo "  php index.php --input_type=internal --command=fix-dovecot-permissions\n";
        echo "  php index.php --input_type=internal --command=setup-database\n";
        echo "  php index.php --input_type=internal --command=stats\n";
        echo "  php index.php --input_type=internal --command=test-spam-filter --subject='Hello' --body='Test message'\n";
    }












    /**
     * Report an IP to your script via command line
     *
     * @param string $ip The IP address to report
     * @param string $jail The jail that banned the IP
     * @param string $reason Optional reason for the ban
     * @return bool Success status
     */
    public function reportIpToScript(string $ip, string $jail, string $reason = ''): bool
    {
        // Validate IP address
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new RuntimeException("Invalid IP address: {$ip}");
        }

        // Path to your script
        $scriptPath = "/usr/local/share/cyford/security/index.php";

        // If the script path doesn't exist, try to find it
        if (!file_exists($scriptPath)) {
            // Try common locations
            $possiblePaths = [
                "/opt/cyford/security/index.php",
                "/var/www/cyford/security/index.php",
                __DIR__ . "/../../index.php" // Relative to the current class file
            ];

            foreach ($possiblePaths as $path) {
                if (file_exists($path)) {
                    $scriptPath = $path;
                    break;
                }
            }
        }

        // Build command with proper escaping
        $command = sprintf(
            "/usr/bin/php %s --input_type=internal --command=report-ip --ip=%s --jail=%s",
            escapeshellarg($scriptPath),
            escapeshellarg($ip),
            escapeshellarg($jail)
        );

        // Add reason if provided
        if (!empty($reason)) {
            $command .= " --reason=" . escapeshellarg($reason);
        }

        // Execute the command
        exec($command . " 2>&1", $output, $returnCode);

        return $returnCode === 0;
    }

    /**
     * Set up Fail2Ban to report IPs to your script
     *
     * @param string $scriptPath Path to your script
     * @return bool Success status
     */
    public function setupScriptReporting(string $scriptPath = "/usr/local/share/cyford/security/index.php"): bool
    {
        // Create a custom action configuration for Fail2Ban
        $actionFile = '/etc/fail2ban/action.d/cyford-report-script.conf';

        // Create the action configuration content
        $actionContent = <<<CONF
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = /usr/bin/php $scriptPath --input_type=internal --command=report-ip --ip=<ip> --jail=<name> --reason="Banned by Fail2Ban"
actionunban = 

[Init]
CONF;

        try {
            // Write the action configuration file
            if (file_put_contents($actionFile, $actionContent) === false) {
                throw new RuntimeException("Failed to create action configuration file: {$actionFile}");
            }

            // Update jail.local to include the new action
            $jailLocalFile = '/etc/fail2ban/jail.local';
            $jailLocalContent = '';

            if (file_exists($jailLocalFile)) {
                $jailLocalContent = file_get_contents($jailLocalFile);
            }

            // Check if we need to add the global configuration
            if (strpos($jailLocalContent, 'cyford-report-script') === false) {
                // Add global configuration to use our action
                $jailLocalContent .= "\n\n[DEFAULT]\n";
                $jailLocalContent .= "# Cyford IP reporting action\n";
                $jailLocalContent .= "action = %(action_)s\n";
                $jailLocalContent .= "         cyford-report-script\n";

                // Write the updated jail.local file
                if (file_put_contents($jailLocalFile, $jailLocalContent) === false) {
                    throw new RuntimeException("Failed to update jail.local configuration file");
                }
            }

            // Restart Fail2Ban to apply changes
            return $this->restart();
        } catch (RuntimeException $e) {
            // Log the error
            error_log('Failed to set up script reporting: ' . $e->getMessage());
            return false;
        }
    }
















}