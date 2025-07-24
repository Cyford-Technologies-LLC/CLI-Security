<?php
namespace Cyford\Security\Classes;

use RuntimeException;

class Fail2Ban
{
    private string $fail2banCommand;
    private ?array $cachedJails = null;

    /**
     * Constructor
     *
     * @param string $fail2banClientPath Path to fail2ban-client
     */
    public function __construct(string $fail2banClientPath = '/usr/bin/fail2ban-client')
    {
        $this->fail2banCommand = $fail2banClientPath;

        if (!file_exists($this->fail2banCommand)) {
            throw new RuntimeException("Fail2Ban client not found at: {$this->fail2banClientPath}");
        }
    }

    /**
     * Get list of enabled jails
     *
     * @param bool $useCache Whether to use cached results
     * @return array List of enabled jails
     * @throws RuntimeException
     */
    public function getEnabledJails(bool $useCache = true): array
    {
        if ($useCache && $this->cachedJails !== null) {
            return $this->cachedJails;
        }

        $command = "{$this->fail2banCommand} status";
        exec($command . ' 2>&1', $output, $returnCode);

        if ($returnCode !== 0 || empty($output)) {
            throw new RuntimeException('Failed to execute Fail2Ban status command: ' . implode("\n", $output));
        }

        $jails = [];
        foreach ($output as $line) {
            if (preg_match('/Jail list:\s*(.*)/', $line, $matches)) {
                $jailList = trim($matches[1]);
                if (!empty($jailList)) {
                    $jails = array_map('trim', explode(',', $jailList));
                }
                break;
            }
        }

        $this->cachedJails = $jails;
        return $jails;
    }

    /**
     * Get the status of a specific jail
     *
     * @param string $jail
     * @return array Jail status information
     * @throws RuntimeException
     */
    public function getJailStatus(string $jail): array
    {
        $command = "{$this->fail2banCommand} status {$jail}";
        exec($command . ' 2>&1', $output, $returnCode);

        if ($returnCode !== 0) {
            throw new RuntimeException("Failed to retrieve status for jail '{$jail}': " . implode("\n", $output));
        }

        // Parse the output into a structured array
        $status = [
            'name' => $jail,
            'currently_failed' => 0,
            'total_failed' => 0,
            'banned_ips' => [],
            'file_list' => [],
            'filter' => '',
            'actions' => []
        ];

        foreach ($output as $line) {
            $line = trim($line);

            // Extract currently failed
            if (preg_match('/Currently failed:\s+(\d+)/', $line, $matches)) {
                $status['currently_failed'] = (int)$matches[1];
            }

            // Extract total failed
            elseif (preg_match('/Total failed:\s+(\d+)/', $line, $matches)) {
                $status['total_failed'] = (int)$matches[1];
            }

            // Extract banned IPs
            elseif (preg_match('/Banned IP list:\s+(.*)/', $line, $matches)) {
                $bannedList = trim($matches[1]);
                if (!empty($bannedList)) {
                    $status['banned_ips'] = array_map('trim', explode(' ', $bannedList));
                }
            }

            // Extract file list
            elseif (preg_match('/File list:\s+(.*)/', $line, $matches)) {
                $fileList = trim($matches[1]);
                if (!empty($fileList)) {
                    $status['file_list'] = array_map('trim', explode(',', $fileList));
                }
            }

            // Extract filter
            elseif (preg_match('/Filter:\s+(.*)/', $line, $matches)) {
                $status['filter'] = trim($matches[1]);
            }

            // Extract actions
            elseif (preg_match('/Actions:\s+(.*)/', $line, $matches)) {
                $actionsList = trim($matches[1]);
                if (!empty($actionsList)) {
                    $status['actions'] = array_map('trim', explode(',', $actionsList));
                }
            }
        }

        return $status;
    }

    /**
     * Ban an IP address manually
     *
     * @param string $jail
     * @param string $ip
     * @return bool Success status
     * @throws RuntimeException
     */
    public function banIp(string $jail, string $ip): bool
    {
        // Validate IP address
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new RuntimeException("Invalid IP address: {$ip}");
        }

        $command = "{$this->fail2banCommand} set {$jail} banip {$ip}";
        exec($command . ' 2>&1', $output, $returnCode);

        if ($returnCode !== 0) {
            throw new RuntimeException("Failed to ban IP {$ip} for jail '{$jail}': " . implode("\n", $output));
        }

        return true;
    }

    /**
     * Unban an IP address manually
     *
     * @param string $jail
     * @param string $ip
     * @return bool Success status
     * @throws RuntimeException
     */
    public function unbanIp(string $jail, string $ip): bool
    {
        // Validate IP address
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new RuntimeException("Invalid IP address: {$ip}");
        }

        $command = "{$this->fail2banCommand} set {$jail} unbanip {$ip}";
        exec($command . ' 2>&1', $output, $returnCode);

        if ($returnCode !== 0) {
            throw new RuntimeException("Failed to unban IP {$ip} for jail '{$jail}': " . implode("\n", $output));
        }

        return true;
    }

    /**
     * Get all banned IPs across all jails
     *
     * @return array Map of jail names to arrays of banned IPs
     * @throws RuntimeException
     */
    public function getAllBannedIps(): array
    {
        $jails = $this->getEnabledJails();
        $bannedIps = [];

        foreach ($jails as $jail) {
            $status = $this->getJailStatus($jail);
            $bannedIps[$jail] = $status['banned_ips'];
        }

        return $bannedIps;
    }

    /**
     * Check if an IP is banned in any jail
     *
     * @param string $ip IP address to check
     * @return array List of jails where the IP is banned
     * @throws RuntimeException
     */
    public function isIpBanned(string $ip): array
    {
        // Validate IP address
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new RuntimeException("Invalid IP address: {$ip}");
        }

        $bannedIn = [];
        $jails = $this->getEnabledJails();

        foreach ($jails as $jail) {
            $status = $this->getJailStatus($jail);
            if (in_array($ip, $status['banned_ips'])) {
                $bannedIn[] = $jail;
            }
        }

        return $bannedIn;
    }

    /**
     * Get Fail2Ban logs for a specific jail
     *
     * @param string $jail Jail name
     * @param int $lines Number of log lines to retrieve
     * @return array Log entries
     */
    public function getJailLogs(string $jail, int $lines = 50): array
    {
        $logFile = $this->getLogFile();
        if (!$logFile || !file_exists($logFile)) {
            return ['error' => 'Fail2Ban log file not found'];
        }

        $command = "grep \\[{$jail}\\] {$logFile} | tail -n {$lines}";
        exec($command . ' 2>&1', $output, $returnCode);

        if ($returnCode !== 0) {
            return ['error' => 'Failed to retrieve logs: ' . implode("\n", $output)];
        }

        return $this->parseLogEntries($output);
    }

    /**
     * Get ban statistics for all jails
     *
     * @return array Statistics per jail
     * @throws RuntimeException
     */
    public function getStatistics(): array
    {
        $jails = $this->getEnabledJails();
        $stats = [];

        foreach ($jails as $jail) {
            $status = $this->getJailStatus($jail);
            $stats[$jail] = [
                'currently_failed' => $status['currently_failed'],
                'total_failed' => $status['total_failed'],
                'banned_count' => count($status['banned_ips']),
                'banned_ips' => $status['banned_ips']
            ];
        }

        return $stats;
    }

    /**
     * Create a new jail (requires restart of Fail2Ban)
     *
     * @param string $name Jail name
     * @param array $config Jail configuration
     * @return bool Success status
     */
    public function createJail(string $name, array $config): bool
    {
        $jailFile = "/etc/fail2ban/jail.d/{$name}.conf";

        $content = "[{$name}]\n";
        $content .= "enabled = true\n";

        foreach ($config as $key => $value) {
            if (is_array($value)) {
                $value = implode(' ', $value);
            }
            $content .= "{$key} = {$value}\n";
        }

        if (file_put_contents($jailFile, $content) === false) {
            throw new RuntimeException("Failed to create jail configuration file: {$jailFile}");
        }

        // Restart Fail2Ban to apply changes
        exec('systemctl restart fail2ban 2>&1', $output, $returnCode);

        if ($returnCode !== 0) {
            throw new RuntimeException("Failed to restart Fail2Ban: " . implode("\n", $output));
        }

        // Clear cached jails
        $this->cachedJails = null;

        return true;
    }

    /**
     * Delete a jail
     *
     * @param string $name Jail name
     * @return bool Success status
     */
    public function deleteJail(string $name): bool
    {
        $jailFile = "/etc/fail2ban/jail.d/{$name}.conf";

        if (!file_exists($jailFile)) {
            throw new RuntimeException("Jail configuration file not found: {$jailFile}");
        }

        if (!unlink($jailFile)) {
            throw new RuntimeException("Failed to delete jail configuration file: {$jailFile}");
        }

        // Restart Fail2Ban to apply changes
        exec('systemctl restart fail2ban 2>&1', $output, $returnCode);

        if ($returnCode !== 0) {
            throw new RuntimeException("Failed to restart Fail2Ban: " . implode("\n", $output));
        }

        // Clear cached jails
        $this->cachedJails = null;

        return true;
    }

    /**
     * Get Fail2Ban version
     *
     * @return string Version number
     */
    public function getVersion(): string
    {
        $command = "{$this->fail2banCommand} --version";
        exec($command . ' 2>&1', $output, $returnCode);

        if ($returnCode !== 0 || empty($output)) {
            throw new RuntimeException("Failed to get Fail2Ban version");
        }

        $version = trim($output[0]);
        if (preg_match('/(\d+\.\d+\.\d+)/', $version, $matches)) {
            return $matches[1];
        }

        return $version;
    }

    /**
     * Get the path to the Fail2Ban log file
     *
     * @return string|null Log file path or null if not found
     */
    private function getLogFile(): ?string
    {
        $commonLogPaths = [
            '/var/log/fail2ban.log',
            '/var/log/fail2ban/fail2ban.log'
        ];

        foreach ($commonLogPaths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        return null;
    }

    /**
     * Parse log entries into structured data
     *
     * @param array $logLines
     * @return array Structured log entries
     */
    private function parseLogEntries(array $logLines): array
    {
        $entries = [];

        foreach ($logLines as $line) {
            // Extract timestamp, jail, and message
            if (preg_match('/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (\w+)\s+\[(\w+)\] (.+)/', $line, $matches)) {
                $entry = [
                    'timestamp' => $matches[1],
                    'level' => $matches[2],
                    'jail' => $matches[3],
                    'message' => $matches[4]
                ];

                // Extract IP address if present
                if (preg_match('/Ban ([\d\.]+)/', $entry['message'], $ipMatches)) {
                    $entry['ip'] = $ipMatches[1];
                    $entry['action'] = 'ban';
                } elseif (preg_match('/Unban ([\d\.]+)/', $entry['message'], $ipMatches)) {
                    $entry['ip'] = $ipMatches[1];
                    $entry['action'] = 'unban';
                }

                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * Check if Fail2Ban is running
     *
     * @return bool Whether Fail2Ban is running
     */
    public function isRunning(): bool
    {
        exec('systemctl is-active fail2ban 2>&1', $output, $returnCode);
        return $returnCode === 0 && trim(implode('', $output)) === 'active';
    }

    /**
     * Restart Fail2Ban service
     *
     * @return bool Success status
     */
    public function restart(): bool
    {
        exec('systemctl restart fail2ban 2>&1', $output, $returnCode);
        return $returnCode === 0;
    }

    /**
     * Get Fail2Ban configuration details
     *
     * @return array Configuration information
     */
    public function getConfig(): array
    {
        $config = [];

        // Get jail.local content if it exists
        if (file_exists('/etc/fail2ban/jail.local')) {
            $config['jail_local'] = file_get_contents('/etc/fail2ban/jail.local');
        }

        // Get jail.conf content
        if (file_exists('/etc/fail2ban/jail.conf')) {
            $config['jail_conf'] = file_get_contents('/etc/fail2ban/jail.conf');
        }

        // Get custom jail configurations
        $jailFiles = glob('/etc/fail2ban/jail.d/*.conf');
        $config['custom_jails'] = [];

        foreach ($jailFiles as $file) {
            $jailName = basename($file, '.conf');
            $config['custom_jails'][$jailName] = file_get_contents($file);
        }

        return $config;
    }

    /**
     * Create a custom filter for Fail2Ban
     *
     * @param string $name Filter name
     * @param array $failregexes List of regular expressions
     * @param array $ignoreregexes List of ignore regular expressions
     * @return bool Success status
     */
    public function createFilter(string $name, array $failregexes, array $ignoreregexes = []): bool
    {
        $filterFile = "/etc/fail2ban/filter.d/{$name}.conf";

        $content = "[Definition]\n\n";

        // Add failregexes
        $content .= "failregex = ";
        if (count($failregexes) === 1) {
            $content .= $failregexes[0] . "\n";
        } else {
            $content .= "\n";
            foreach ($failregexes as $regex) {
                $content .= "            " . $regex . "\n";
            }
        }

        // Add ignoreregexes if present
        if (!empty($ignoreregexes)) {
            $content .= "\nignoreregex = ";
            if (count($ignoreregexes) === 1) {
                $content .= $ignoreregexes[0] . "\n";
            } else {
                $content .= "\n";
                foreach ($ignoreregexes as $regex) {
                    $content .= "            " . $regex . "\n";
                }
            }
        } else {
            $content .= "\nignoreregex =\n";
        }

        if (file_put_contents($filterFile, $content) === false) {
            throw new RuntimeException("Failed to create filter configuration file: {$filterFile}");
        }

        return true;
    }

    /**
     * Create a custom jail for email security
     *
     * @param string $logPath Path to the log file to monitor
     * @return bool Success status
     */
    public function createEmailSecurityJail(string $logPath): bool
    {
        // First create the filter
        $emailFilterRegexes = [
            '^%(__prefix_line)sWarning: [^:]+: SASL (LOGIN|PLAIN|(?:CRAM|DIGEST)-MD5) authentication failed: authentication failure$',
            '^%(__prefix_line)sSASL PLAIN authentication failed: UGFzc3dvcmQ6$',
            '^%(__prefix_line)swarning: [-._\w]+\[\d+\]: SASL \w+ authentication failed: authentication failure$',
            '^%(__prefix_line)s[^:]+: Relay access denied; from=<[^>]*>,\s*ip=\[?<HOST>\]?$',
            '^%(__prefix_line)sClient host \[<HOST>\] blocked using zen.spamhaus.org$'
        ];

        try {
            $this->createFilter('postfix-email-security', $emailFilterRegexes);

            // Now create the jail
            $jailConfig = [
                'filter' => 'postfix-email-security',
                'logpath' => $logPath,
                'maxretry' => 3,
                'findtime' => 3600,
                'bantime' => 86400,
                'enabled' => 'true',
                'action' => 'iptables-multiport[name=postfix, port="25,465,587"]'
            ];

            return $this->createJail('postfix-email-security', $jailConfig);
        } catch (RuntimeException $e) {
            // Log the error
            error_log('Failed to create email security jail: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Integration with Firewall class to add banned IPs
     *
     * @param Firewall $firewall Firewall instance
     * @return array Results of operation
     */
    public function syncWithFirewall(Firewall $firewall): array
    {
        $results = [
            'success' => true,
            'added' => 0,
            'failed' => 0,
            'errors' => []
        ];

        try {
            $bannedIps = $this->getAllBannedIps();

            foreach ($bannedIps as $jail => $ips) {
                foreach ($ips as $ip) {
                    try {
                        $firewall->blockIP($ip);
                        $results['added']++;
                    } catch (RuntimeException $e) {
                        $results['failed']++;
                        $results['errors'][] = "Failed to block IP {$ip} from jail {$jail}: " . $e->getMessage();
                    }
                }
            }

            if ($results['failed'] > 0) {
                $results['success'] = false;
            }

            return $results;
        } catch (RuntimeException $e) {
            return [
                'success' => false,
                'added' => 0,
                'failed' => 0,
                'errors' => ["Failed to get banned IPs: " . $e->getMessage()]
            ];
        }
    }

    /**
     * Report banned IPs to the API
     *
     * @param ApiClient $apiClient API client instance
     * @param array $categories Categories to assign to the IPs (e.g., [4, 8] for brute force, authentication)
     * @param bool $reportNewOnly Only report IPs that haven't been reported before
     * @return array Report results
     */
    public function reportBannedIps(ApiClient $apiClient, array $categories = [4, 8], bool $reportNewOnly = true): array
    {
        $results = [
            'success' => true,
            'reported' => 0,
            'failed' => 0,
            'skipped' => 0,
            'errors' => []
        ];

        try {
            // Get all banned IPs from all jails
            $bannedIps = $this->getAllBannedIps();

            // Tracking reported IPs to avoid duplicates
            $reportedIps = [];
            $allBannedIps = [];

            // Track previously reported IPs if reportNewOnly is true
            $previouslyReported = [];
            if ($reportNewOnly) {
                $previouslyReported = $this->getPreviouslyReportedIps();
            }

            // Process each jail's banned IPs
            foreach ($bannedIps as $jail => $ips) {
                if (empty($ips)) {
                    continue;
                }

                foreach ($ips as $ip) {
                    // Skip if already processed in this batch
                    if (in_array($ip, $reportedIps)) {
                        continue;
                    }

                    // Skip if previously reported and we're only reporting new IPs
                    if ($reportNewOnly && in_array($ip, $previouslyReported)) {
                        $results['skipped']++;
                        continue;
                    }

                    // Add to our tracking arrays
                    $reportedIps[] = $ip;
                    $allBannedIps[] = $ip;

                    // Add jail info to metadata
                    $metadata = [
                        'source' => 'fail2ban',
                        'jail' => $jail,
                        'server' => gethostname(),
                        'timestamp' => time()
                    ];

                    try {
                        // Individually report each IP for better error handling
                        $apiClient->reportIp($ip, $categories, 'fail2ban', $metadata);
                        $results['reported']++;
                    } catch (\Exception $e) {
                        $results['failed']++;
                        $results['errors'][] = "Failed to report IP {$ip} from jail {$jail}: " . $e->getMessage();
                    }
                }
            }

            // Update our cache of reported IPs
            if ($reportNewOnly && $results['reported'] > 0) {
                $this->updateReportedIpsCache($reportedIps);
            }

            // If using batch reporting, we could do it here instead of individually
            // $apiClient->reportMultipleIps($allBannedIps, $categories, 'fail2ban', ['source' => 'fail2ban_batch']);

            if ($results['failed'] > 0) {
                $results['success'] = false;
            }

            return $results;
        } catch (\Exception $e) {
            return [
                'success' => false,
                'reported' => 0,
                'failed' => 0,
                'skipped' => 0,
                'errors' => ["Failed to report banned IPs: " . $e->getMessage()]
            ];
        }
    }

    /**
     * Set up an automatic reporting action for Fail2Ban
     *
     * @param string $apiEndpoint API endpoint URL
     * @param string $authToken Authentication token
     * @param array $categories Categories to assign to the IPs
     * @return bool Success status
     */
    public function setupAutoReporting(string $apiEndpoint, string $authToken, array $categories = [4, 8]): bool
    {
        // Create a custom action configuration for Fail2Ban
        $actionFile = '/etc/fail2ban/action.d/cyford-report.conf';

        // Convert categories to comma-separated string
        $categoriesStr = implode(',', $categories);

        // Create the action configuration content
        $actionContent = <<<CONF
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = curl -X POST "{$apiEndpoint}" \
             -H "Authorization: Bearer {$authToken}" \
             -H "Content-Type: application/json" \
             -d '{"ips": "<ip>", "categories": "{$categoriesStr}", "source": "fail2ban", "metadata": {"jail": "<name>", "server": "$(hostname)", "timestamp": "$(date +%%s)"}}'
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
            if (strpos($jailLocalContent, 'cyford-report') === false) {
                // Add global configuration to use our action
                $jailLocalContent .= "\n\n[DEFAULT]\n";
                $jailLocalContent .= "# Cyford API reporting action\n";
                $jailLocalContent .= "action = %(action_)s\n";
                $jailLocalContent .= "         cyford-report\n";

                // Write the updated jail.local file
                if (file_put_contents($jailLocalFile, $jailLocalContent) === false) {
                    throw new RuntimeException("Failed to update jail.local configuration file");
                }
            }

            // Restart Fail2Ban to apply changes
            return $this->restart();
        } catch (RuntimeException $e) {
            // Log the error
            error_log('Failed to set up auto reporting: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get list of previously reported IPs
     *
     * @return array List of previously reported IPs
     */
    private function getPreviouslyReportedIps(): array
    {
        $cacheFile = '/var/lib/fail2ban/cyford-reported-ips.json';

        if (!file_exists($cacheFile)) {
            return [];
        }

        $content = file_get_contents($cacheFile);
        if (empty($content)) {
            return [];
        }

        $data = json_decode($content, true);
        return $data['ips'] ?? [];
    }

    /**
     * Update the cache of reported IPs
     *
     * @param array $newIps New IPs to add to the cache
     * @return bool Success status
     */
    private function updateReportedIpsCache(array $newIps): bool
    {
        $cacheFile = '/var/lib/fail2ban/cyford-reported-ips.json';
        $cacheDir = dirname($cacheFile);

        // Ensure the directory exists
        if (!is_dir($cacheDir)) {
            if (!mkdir($cacheDir, 0755, true)) {
                return false;
            }
        }

        // Get existing cache
        $existingIps = $this->getPreviouslyReportedIps();

        // Merge and deduplicate
        $allIps = array_unique(array_merge($existingIps, $newIps));

        // Write updated cache
        $data = [
            'ips' => $allIps,
            'last_updated' => date('Y-m-d H:i:s')
        ];

        return file_put_contents($cacheFile, json_encode($data, JSON_PRETTY_PRINT)) !== false;
    }

    /**
     * Set up Fail2Ban to automatically report IPs to this script
     */
    private function setupFail2BanReporting(): void
    {
        try {
            $fail2Ban = new \Cyford\Security\Classes\Fail2Ban();

            // Find the path to the current script
            $scriptPath = $_SERVER['SCRIPT_FILENAME'] ?? null;
            if (!$scriptPath) {
                // Try to determine script path
                $scriptPath = realpath(__DIR__ . '/../../index.php');
            }

            if (!file_exists($scriptPath)) {
                echo "❌ Could not determine script path\n";
                return;
            }

            echo "🔧 Setting up Fail2Ban reporting to script: $scriptPath\n";

            $result = $fail2Ban->setupScriptReporting($scriptPath);

            if ($result) {
                echo "✅ Fail2Ban reporting set up successfully\n";
                echo "✅ Banned IPs will now be automatically reported to the API\n";
            } else {
                echo "❌ Failed to set up Fail2Ban reporting\n";
            }
        } catch (Exception $e) {
            echo "❌ Error setting up Fail2Ban reporting: " . $e->getMessage() . "\n";
            if ($this->logger) {
                $this->logger->error("Failed to set up Fail2Ban reporting: " . $e->getMessage());
            }
        }
    }




























}