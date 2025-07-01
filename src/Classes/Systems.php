<?php
namespace Cyford\Security\Classes;

class Systems
{
    /**
     * Get the Operating System name and version.
     *
     * @return array
     */
    public function getOSInfo(): array
    {
        return [
            'os' => php_uname('s'), // Operating System name
            'hostname' => php_uname('n'), // Hostname
            'release' => php_uname('r'), // OS release version
            'version' => php_uname('v'), // OS version
            'architecture' => php_uname('m') // Machine architecture
        ];
    }

    /**
     * Get PHP version.
     *
     * @return string
     */
    public function getPHPVersion(): string
    {
        return PHP_VERSION;
    }

    /**
     * Get installed and active software on the system, based on common commands.
     *
     * @return array
     */
    public function getInstalledSoftware(): array
    {
        $software = [
            'nginx' => $this->getSoftwareVersion('nginx -v'), // Nginx
            'apache' => $this->getSoftwareVersion('apache2 -v'), // Apache
            'mysql' => $this->getSoftwareVersion('mysql --version'), // MySQL
            'php' => $this->getPHPVersion(), // PHP as default
            'fail2ban' => $this->getSoftwareVersion('fail2ban-client --version'), // Fail2Ban
            'iptables' => $this->getSoftwareVersion('iptables -V'), // iptables
            'firewalld' => $this->getSoftwareVersion('firewalld --version'), // Firewalld
        ];

        // Filter out any null or empty versions
        return array_filter($software, fn($version) => $version !== null);
    }

    /**
     * Helper method to execute a shell command and parse the version.
     *
     * @param string $command
     * @return string|null
     */
    private function getSoftwareVersion(string $command): ?string
    {
        $output = null;
        exec($command . ' 2>&1', $output, $status);

        if ($status === 0 && !empty($output)) {
            return implode(' ', $output);
        }

        return null; // Return null if command fails or output is empty
    }

    /**
     * Get system disk usage.
     *
     * @return array
     */
    public function getDiskUsage(): array
    {
        $totalSpace = disk_total_space('/');
        $freeSpace = disk_free_space('/');

        return [
            'total_space' => $this->formatSize($totalSpace),
            'free_space' => $this->formatSize($freeSpace),
            'used_space' => $this->formatSize($totalSpace - $freeSpace),
            'usage_percentage' => round((($totalSpace - $freeSpace) / $totalSpace) * 100, 2) . '%',
        ];
    }

    /**
     * Get available system memory.
     *
     * @return array
     */
    public function getMemoryInfo(): array
    {
        if (stristr(PHP_OS, 'linux')) {
            $output = null;
            exec('free -m', $output);

            if (!empty($output)) {
                $lines = array_slice($output, 1, 1); // Extract the second line (memory stats)
                $memoryStats = preg_split('/\s+/', $lines[0]);

                return [
                    'total_memory' => $this->formatSize($memoryStats[1] * 1024),
                    'used_memory' => $this->formatSize($memoryStats[2] * 1024),
                    'free_memory' => $this->formatSize($memoryStats[3] * 1024),
                    'usage_percentage' => round(($memoryStats[2] / $memoryStats[1]) * 100, 2) . '%',
                ];
            }
        }

        return [
            'error' => 'Memory information is not available on this OS.'
        ];
    }

    /**
     * Get server's public IP address.
     *
     * @return string|null
     */
    public function getPublicIP(): ?string
    {
        // Try multiple methods to get public IP
        $methods = [
            'curl -s ifconfig.me',
            'curl -s ipinfo.io/ip',
            'curl -s icanhazip.com',
            'hostname -I | awk "{print \$1}"'
        ];
        
        foreach ($methods as $method) {
            $ip = trim(shell_exec($method));
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE)) {
                return $ip;
            }
        }
        
        return null;
    }

    /**
     * Get cached alias mapping or load from files
     */
    public function getAliasMapping(string $email): ?string
    {
        $cacheFile = '/tmp/cyford_alias_cache.json';
        $aliases = $this->loadAliasCache($cacheFile);
        
        $username = explode('@', $email)[0];
        
        // Check direct email mapping first
        if (isset($aliases[$email])) {
            return $aliases[$email];
        }
        
        // Check username mapping
        if (isset($aliases[$username])) {
            return $aliases[$username];
        }
        
        return null;
    }
    
    /**
     * Load alias cache from memory or rebuild if needed
     */
    private function loadAliasCache(string $cacheFile): array
    {
        // Check if cache exists and is recent (less than 5 minutes old)
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 300) {
            $cached = json_decode(file_get_contents($cacheFile), true);
            if ($cached !== null) {
                return $cached;
            }
        }
        
        // Rebuild cache
        $aliases = $this->buildAliasCache();
        file_put_contents($cacheFile, json_encode($aliases));
        
        return $aliases;
    }
    
    /**
     * Build alias cache from system files
     */
    private function buildAliasCache(): array
    {
        $aliases = [];
        
        // Load real users first
        $realUsers = $this->getRealUsers();
        
        // Load system aliases (/etc/aliases)
        if (file_exists('/etc/aliases')) {
            $content = file_get_contents('/etc/aliases');
            $lines = explode("\n", $content);
            
            foreach ($lines as $line) {
                $line = trim($line);
                if (empty($line) || $line[0] === '#') continue;
                
                if (preg_match('/^([^:]+):\s*(.+)$/', $line, $matches)) {
                    $alias = trim($matches[1]);
                    $target = trim($matches[2]);
                    
                    // Handle multiple targets, find first real user
                    $targets = preg_split('/[,\s]+/', $target);
                    foreach ($targets as $t) {
                        $t = trim($t);
                        if (in_array($t, $realUsers)) {
                            $aliases[$alias] = $t;
                            break;
                        }
                    }
                }
            }
        }
        
        // Load virtual aliases (/etc/postfix/virtual)
        if (file_exists('/etc/postfix/virtual')) {
            $content = file_get_contents('/etc/postfix/virtual');
            $lines = explode("\n", $content);
            
            foreach ($lines as $line) {
                $line = trim($line);
                if (empty($line) || $line[0] === '#') continue;
                
                if (preg_match('/^([^\s]+)\s+(.+)$/', $line, $matches)) {
                    $virtual = trim($matches[1]);
                    $target = trim($matches[2]);
                    $targetUser = explode('@', $target)[0];
                    
                    if (in_array($targetUser, $realUsers)) {
                        $aliases[$virtual] = $targetUser;
                    }
                }
            }
        }
        
        return $aliases;
    }
    
    /**
     * Get list of real system users
     */
    private function getRealUsers(): array
    {
        $users = [];
        
        if (file_exists('/etc/passwd')) {
            $content = file_get_contents('/etc/passwd');
            $lines = explode("\n", $content);
            
            foreach ($lines as $line) {
                if (preg_match('/^([^:]+):/', $line, $matches)) {
                    $users[] = $matches[1];
                }
            }
        }
        
        return $users;
    }
    
    /**
     * Check if user is real system user
     */
    public function isRealUser(string $username): bool
    {
        $realUsers = $this->getRealUsers();
        return in_array($username, $realUsers);
    }
    
    /**
     * Clear alias cache (for manual refresh)
     */
    public function clearAliasCache(): void
    {
        $cacheFile = '/tmp/cyford_alias_cache.json';
        if (file_exists($cacheFile)) {
            unlink($cacheFile);
        }
    }

    /**
     * Get complete system specifications
     */
    public function getSystemSpecs(): array
    {
        $osInfo = $this->getOSInfo();
        $memInfo = $this->getMemoryInfo();
        $diskInfo = $this->getDiskUsage();
        
        return [
            'os' => $osInfo['os'] . ' ' . $osInfo['release'],
            'hostname' => $osInfo['hostname'],
            'architecture' => $osInfo['architecture'],
            'cpu_count' => $this->getCPUCount(),
            'memory_total' => $memInfo['total_memory'] ?? 'Unknown',
            'memory_free' => $memInfo['free_memory'] ?? 'Unknown',
            'disk_total' => $diskInfo['total_space'],
            'disk_free' => $diskInfo['free_space']
        ];
    }
    
    /**
     * Get network information including all interface IPs
     */
    public function getNetworkInfo(): array
    {
        return [
            'public_ip' => $this->getPublicIP(),
            'interfaces' => $this->getAllInterfaceIPs()
        ];
    }
    
    /**
     * Get CPU count
     */
    private function getCPUCount(): int
    {
        if (stristr(PHP_OS, 'linux')) {
            $output = shell_exec('nproc');
            return (int)trim($output);
        }
        return 1;
    }
    
    /**
     * Get all network interface IPs
     */
    private function getAllInterfaceIPs(): array
    {
        $interfaces = [];
        
        if (stristr(PHP_OS, 'linux')) {
            exec('ip addr show', $output);
            $currentInterface = null;
            
            foreach ($output as $line) {
                // Match interface name
                if (preg_match('/^\d+:\s+([^:]+):/', $line, $matches)) {
                    $currentInterface = trim($matches[1]);
                }
                
                // Match IP address
                if ($currentInterface && preg_match('/inet\s+([0-9.]+)/', $line, $matches)) {
                    $interfaces[$currentInterface] = $matches[1];
                }
            }
        }
        
        return $interfaces;
    }

    /**
     * Perform complete system inventory
     */
    public function performSystemInventory(): void
    {
        echo "🔍 Performing system inventory...\n";
        
        try {
            // Get system specifications
            $systemInfo = [
                'timestamp' => date('Y-m-d H:i:s'),
                'system' => $this->getSystemSpecs(),
                'network' => $this->getNetworkInfo(),
                'software' => $this->getInstalledSoftware()
            ];
            
            // Save to JSON file
            $inventoryFile = './system_inventory.json';
            file_put_contents($inventoryFile, json_encode($systemInfo, JSON_PRETTY_PRINT));
            
            echo "✅ System inventory completed\n";
            echo "📄 Saved to: {$inventoryFile}\n";
            
            // Display summary
            echo "\n📊 System Summary:\n";
            echo "  OS: {$systemInfo['system']['os']}\n";
            echo "  CPUs: {$systemInfo['system']['cpu_count']}\n";
            echo "  Memory: {$systemInfo['system']['memory_total']}\n";
            echo "  Public IP: {$systemInfo['network']['public_ip']}\n";
            echo "  Software Found: " . count($systemInfo['software']) . " packages\n";
            
        } catch (Exception $e) {
            echo "❌ System inventory failed: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Setup task queue system with cron job
     */
    public function setupTaskQueue(array $config): void
    {
        echo "🔧 Setting up task queue system...\n";
        
        // Create task queue in project directory (chroot accessible)
        $projectTasksFile = '/usr/local/share/cyford/security/tasks.json';
        if (!file_exists($projectTasksFile)) {
            file_put_contents($projectTasksFile, '[]');
        }
        exec("chown report-ip:postfix {$projectTasksFile}");
        exec("chmod 664 {$projectTasksFile}");
        echo "✅ Created task queue in project directory: {$projectTasksFile}\n";
        
        // Create symlink from expected location to project file
        $queueDir = '/var/spool/cyford-security';
        if (!is_dir($queueDir)) {
            mkdir($queueDir, 0755, true);
        }
        
        $symlinkTarget = $queueDir . '/tasks.json';
        if (file_exists($symlinkTarget)) {
            unlink($symlinkTarget);
        }
        
        if (symlink($projectTasksFile, $symlinkTarget)) {
            echo "✅ Created symlink: {$symlinkTarget} -> {$projectTasksFile}\n";
        } else {
            echo "⚠️  Failed to create symlink, using project file directly\n";
        }
        
        // Create task processor script
        $this->createTaskProcessor($config);
        
        // Setup cron job
        $this->setupCronJob();
        
        echo "🎉 Task queue system setup complete!\n";
    }
    
    /**
     * Check cron job status
     */
    public function checkCronStatus(): void
    {
        echo "📋 Checking cron job status...\n";
        
        exec('crontab -l 2>/dev/null | grep cyford-task-processor', $output, $returnCode);
        
        if ($returnCode === 0 && !empty($output)) {
            echo "✅ Cron job is installed:\n";
            foreach ($output as $line) {
                echo "  {$line}\n";
            }
        } else {
            echo "❌ Cron job not found\n";
        }
        
        // Check if processor is running
        exec('pgrep -f cyford-task-processor', $processes);
        if (!empty($processes)) {
            echo "✅ Task processor is running (PID: " . implode(', ', $processes) . ")\n";
        } else {
            echo "⚠️  Task processor not currently running\n";
        }
    }
    
    /**
     * Check task queue status
     */
    public function checkQueueStatus(): void
    {
        echo "📊 Checking task queue status...\n";
        
        $queueFile = '/var/spool/postfix/cyford-tasks.json';
        
        if (file_exists($queueFile)) {
            $tasks = json_decode(file_get_contents($queueFile), true) ?: [];
            echo "📋 Queue file exists: {$queueFile}\n";
            echo "📊 Pending tasks: " . count($tasks) . "\n";
            
            if (!empty($tasks)) {
                echo "\n🔍 Recent tasks:\n";
                foreach (array_slice($tasks, -5) as $task) {
                    $status = $task['status'] ?? 'unknown';
                    $schedule = isset($task['run_after']) ? " | Run after: {$task['run_after']}" : '';
                    echo "  ID: {$task['id']} | Type: {$task['type']} | Status: {$status} | Created: {$task['created']}{$schedule}\n";
                }
            }
        } else {
            echo "❌ Queue file not found: {$queueFile}\n";
        }
        
        // Check log file
        $logFile = '/var/log/cyford-security/task-processor.log';
        if (file_exists($logFile)) {
            $logSize = filesize($logFile);
            echo "📄 Log file: {$logFile} (" . $this->formatSize($logSize) . ")\n";
        }
    }
    
    /**
     * Check cron job processing log
     */
    public function checkCronLog(): void
    {
        echo "📅 Checking cron job processing log...\n";
        
        $logFile = '/var/log/cyford-security/task-processor.log';
        
        if (file_exists($logFile)) {
            $logSize = filesize($logFile);
            echo "📄 Log file: {$logFile} (" . $this->formatSize($logSize) . ")\n";
            
            // Show last 20 lines
            exec("tail -20 {$logFile} 2>/dev/null", $logLines);
            if (!empty($logLines)) {
                echo "\n📜 Recent log entries:\n";
                foreach ($logLines as $line) {
                    echo "  {$line}\n";
                }
            } else {
                echo "⚠️  No recent log entries found\n";
            }
            
            // Count total processed tasks
            exec("grep -c 'completed\|failed' {$logFile} 2>/dev/null", $processedCount);
            if (!empty($processedCount)) {
                echo "\n📊 Total tasks processed: " . $processedCount[0] . "\n";
            }
            
            // Show last processing time
            exec("tail -1 {$logFile} 2>/dev/null | grep -o '\[.*\]'", $lastTime);
            if (!empty($lastTime)) {
                echo "🕰️  Last activity: " . trim($lastTime[0], '[]') . "\n";
            }
            
        } else {
            echo "❌ Log file not found: {$logFile}\n";
            echo "Cron job may not have run yet or logging is not working\n";
        }
    }
    
    /**
     * Add task to queue with optional scheduling
     */
    public function addTask(string $type, array $data, string $schedule = 'now'): string
    {
        // Use chroot-accessible directory
        $queueFile = '/var/spool/postfix/cyford-tasks.json';
        $tasks = [];
        
        if (file_exists($queueFile)) {
            $tasks = json_decode(file_get_contents($queueFile), true) ?: [];
        }
        
        $taskId = uniqid('task_', true);
        $task = [
            'id' => $taskId,
            'type' => $type,
            'data' => $data,
            'created' => date('Y-m-d H:i:s'),
            'status' => 'pending',
            'schedule' => $schedule,
            'run_after' => $this->calculateRunTime($schedule)
        ];
        
        $tasks[] = $task;
        file_put_contents($queueFile, json_encode($tasks, JSON_PRETTY_PRINT), LOCK_EX);
        
        return $taskId;
    }
    
    /**
     * Calculate when task should run based on schedule
     */
    private function calculateRunTime(string $schedule): string
    {
        $now = time();
        
        switch ($schedule) {
            case 'now':
                return date('Y-m-d H:i:s', $now);
            case '1hour':
            case 'hourly':
                return date('Y-m-d H:i:s', $now + 3600);
            case '1day':
            case 'daily':
                return date('Y-m-d H:i:s', $now + 86400);
            case '1week':
            case 'weekly':
                return date('Y-m-d H:i:s', $now + 604800);
            default:
                // Handle custom formats like '30min', '2hours', '3days'
                if (preg_match('/^(\d+)(min|hour|day)s?$/', $schedule, $matches)) {
                    $amount = (int)$matches[1];
                    $unit = $matches[2];
                    
                    $multiplier = [
                        'min' => 60,
                        'hour' => 3600,
                        'day' => 86400
                    ];
                    
                    $seconds = $amount * ($multiplier[$unit] ?? 60);
                    return date('Y-m-d H:i:s', $now + $seconds);
                }
                
                return date('Y-m-d H:i:s', $now);
        }
    }
    
    /**
     * Schedule a command to run later
     */
    public function scheduleCommand(string $command, array $args, string $schedule): string
    {
        return $this->addTask('scheduled_command', [
            'command' => $command,
            'args' => $args
        ], $schedule);
    }
    
    /**
     * Backup current config settings
     */
    public function backupConfig(): void
    {
        echo "💾 Backing up config settings...\n";
        
        $configFile = './config.php';
        $backupDir = './config-backups';
        
        if (!is_dir($backupDir)) {
            mkdir($backupDir, 0755, true);
        }
        
        $timestamp = date('Y-m-d_H-i-s');
        $backupFile = "{$backupDir}/config.php.backup_{$timestamp}";
        
        if (file_exists($configFile)) {
            if (copy($configFile, $backupFile)) {
                echo "✅ Config backed up to: {$backupFile}\n";
                
                // Keep only last 10 backups
                $this->cleanupOldBackups($backupDir, 10);
            } else {
                echo "❌ Failed to backup config\n";
            }
        } else {
            echo "❌ Config file not found: {$configFile}\n";
        }
    }
    
    /**
     * Restore config from backup or preserve user settings after git pull
     */
    public function restoreConfig(?string $backupFile = null): void
    {
        echo "🔄 Restoring config settings...\n";
        
        $configFile = './config.php';
        $backupDir = './config-backups';
        
        if ($backupFile) {
            // Restore from specific backup
            if (file_exists($backupFile)) {
                if (copy($backupFile, $configFile)) {
                    echo "✅ Config restored from: {$backupFile}\n";
                } else {
                    echo "❌ Failed to restore config from backup\n";
                }
            } else {
                echo "❌ Backup file not found: {$backupFile}\n";
            }
        } else {
            // Auto-restore from latest backup
            $latestBackup = $this->getLatestBackup($backupDir);
            if ($latestBackup) {
                if (copy($latestBackup, $configFile)) {
                    echo "✅ Config auto-restored from: {$latestBackup}\n";
                } else {
                    echo "❌ Failed to auto-restore config\n";
                }
            } else {
                echo "❌ No backup found to restore from\n";
            }
        }
    }
    
    /**
     * Merge user settings with new config after git pull
     */
    public function mergeConfigAfterGitPull(): void
    {
        echo "🔀 Merging user settings with updated config...\n";
        
        $configFile = './config.php';
        $backupDir = './config-backups';
        $latestBackup = $this->getLatestBackup($backupDir);
        
        if (!$latestBackup) {
            echo "❌ No backup found to merge from\n";
            return;
        }
        
        // Load current (new) config
        $newConfig = include $configFile;
        
        // Load backup (user) config
        $userConfig = include $latestBackup;
        
        // Merge user settings into new config
        $mergedConfig = $this->mergeConfigArrays($newConfig, $userConfig);
        
        // Write merged config
        $configContent = "<?php\n\n// Merged config - User settings preserved after git pull\n// Generated: " . date('Y-m-d H:i:s') . "\n\nreturn " . var_export($mergedConfig, true) . ";\n";
        
        if (file_put_contents($configFile, $configContent)) {
            echo "✅ Config merged successfully\n";
            echo "💾 Creating backup of merged config...\n";
            $this->backupConfig();
        } else {
            echo "❌ Failed to write merged config\n";
        }
    }
    
    /**
     * List available config backups
     */
    public function listConfigBackups(): void
    {
        echo "📋 Available config backups:\n";
        
        $backupDir = './config-backups';
        
        if (!is_dir($backupDir)) {
            echo "❌ No backup directory found\n";
            return;
        }
        
        $backups = glob($backupDir . '/config.php.backup_*');
        
        if (empty($backups)) {
            echo "❌ No backups found\n";
            return;
        }
        
        // Sort by modification time (newest first)
        usort($backups, function($a, $b) {
            return filemtime($b) - filemtime($a);
        });
        
        foreach ($backups as $backup) {
            $timestamp = date('Y-m-d H:i:s', filemtime($backup));
            $size = $this->formatSize(filesize($backup));
            echo "  • " . basename($backup) . " ({$timestamp}, {$size})\n";
        }
    }
    
    /**
     * Recursively merge config arrays, preserving user settings
     */
    private function mergeConfigArrays(array $new, array $user): array
    {
        $merged = $new;
        
        foreach ($user as $key => $value) {
            if (is_array($value) && isset($merged[$key]) && is_array($merged[$key])) {
                // Recursively merge arrays
                $merged[$key] = $this->mergeConfigArrays($merged[$key], $value);
            } else {
                // Preserve user setting
                $merged[$key] = $value;
            }
        }
        
        return $merged;
    }
    
    /**
     * Get latest backup file
     */
    private function getLatestBackup(string $backupDir): ?string
    {
        if (!is_dir($backupDir)) {
            return null;
        }
        
        $backups = glob($backupDir . '/config.php.backup_*');
        
        if (empty($backups)) {
            return null;
        }
        
        // Sort by modification time (newest first)
        usort($backups, function($a, $b) {
            return filemtime($b) - filemtime($a);
        });
        
        return $backups[0];
    }
    
    /**
     * Clean up old backup files
     */
    private function cleanupOldBackups(string $backupDir, int $keepCount): void
    {
        $backups = glob($backupDir . '/config.php.backup_*');
        
        if (count($backups) <= $keepCount) {
            return;
        }
        
        // Sort by modification time (oldest first)
        usort($backups, function($a, $b) {
            return filemtime($a) - filemtime($b);
        });
        
        // Remove oldest backups
        $toRemove = array_slice($backups, 0, count($backups) - $keepCount);
        
        foreach ($toRemove as $backup) {
            if (unlink($backup)) {
                echo "🗑️  Removed old backup: " . basename($backup) . "\n";
            }
        }
    }
    
    /**
     * Create task processor script
     */
    private function createTaskProcessor(array $config): void
    {
        $processorScript = '/usr/local/bin/cyford-task-processor';
        
        $script = <<<'PHP'
#!/usr/bin/php
<?php
// Cyford Security Task Processor
// Runs as root to handle chroot limitations

$queueFile = '/var/spool/postfix/cyford-tasks.json';
$logFile = '/var/log/cyford-security/task-processor.log';

function logMessage($message) {
    global $logFile;
    $timestamp = date('Y-m-d H:i:s');
    file_put_contents($logFile, "[{$timestamp}] {$message}\n", FILE_APPEND | LOCK_EX);
}

if (!file_exists($queueFile)) {
    exit(0);
}

$tasks = json_decode(file_get_contents($queueFile), true) ?: [];
if (empty($tasks)) {
    exit(0);
}

$processed = [];
foreach ($tasks as $task) {
    if ($task['status'] !== 'pending') {
        $processed[] = $task;
        continue;
    }
    
    // Check if task is scheduled for later
    if (isset($task['run_after']) && strtotime($task['run_after']) > time()) {
        $processed[] = $task; // Keep pending until time comes
        continue;
    }
    
    try {
        switch ($task['type']) {
            case 'move_spam':
                $success = moveSpamEmail($task['data']);
                break;
            case 'scheduled_command':
                $success = runScheduledCommand($task['data']);
                break;
            default:
                logMessage("Unknown task type: {$task['type']}");
                $success = false;
        }
        
        $task['status'] = $success ? 'completed' : 'failed';
        $task['processed'] = date('Y-m-d H:i:s');
        
        logMessage("Task {$task['id']} {$task['status']}");
        
    } catch (Exception $e) {
        $task['status'] = 'failed';
        $task['error'] = $e->getMessage();
        logMessage("Task {$task['id']} failed: " . $e->getMessage());
    }
    
    $processed[] = $task;
}

// Keep only last 100 tasks
$processed = array_slice($processed, -100);
file_put_contents($queueFile, json_encode($processed, JSON_PRETTY_PRINT), LOCK_EX);

function moveSpamEmail($data) {
    $spamDir = dirname($data['target_path']);
    
    if (!is_dir($spamDir)) {
        mkdir($spamDir . '/cur', 0755, true);
        mkdir($spamDir . '/new', 0755, true);
        mkdir($spamDir . '/tmp', 0755, true);
    }
    
    return file_put_contents($data['target_path'], $data['email_content']) !== false;
}

function runScheduledCommand($data) {
    $command = $data['command'];
    $args = $data['args'] ?? [];
    
    // Build command string
    $cmdStr = 'php /usr/local/share/cyford/security/index.php --input_type=internal --command=' . escapeshellarg($command);
    
    foreach ($args as $key => $value) {
        $cmdStr .= ' --' . escapeshellarg($key) . '=' . escapeshellarg($value);
    }
    
    exec($cmdStr . ' 2>&1', $output, $returnCode);
    
    logMessage("Scheduled command '{$command}' executed with return code: {$returnCode}");
    
    return $returnCode === 0;
}
PHP;
        
        file_put_contents($processorScript, $script);
        chmod($processorScript, 0755);
        echo "✅ Created task processor: {$processorScript}\n";
    }
    
    /**
     * Setup cron job for task processor
     */
    private function setupCronJob(): void
    {
        $cronEntry = '* * * * * /usr/local/bin/cyford-task-processor >/dev/null 2>&1';
        
        exec('crontab -l 2>/dev/null', $currentCron);
        
        if (!in_array($cronEntry, $currentCron)) {
            $currentCron[] = $cronEntry;
            $cronContent = implode("\n", $currentCron) . "\n";
            
            $tempFile = tempnam('/tmp', 'cron');
            file_put_contents($tempFile, $cronContent);
            exec("crontab {$tempFile}");
            unlink($tempFile);
            
            echo "✅ Added cron job (runs every minute)\n";
        } else {
            echo "ℹ️  Cron job already exists\n";
        }
    }

    /**
     * Format bytes into a readable size.
     *
     * @param int $bytes
     * @return string
     */
    private function formatSize(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $power = $bytes > 0 ? floor(log($bytes, 1024)) : 0;

        return number_format($bytes / pow(1024, $power), 2) . ' ' . $units[$power];
    }
}