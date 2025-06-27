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