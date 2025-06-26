<?php
namespace Cyford\Security\Classes;

use RuntimeException;

class Postfix
{
    private string $mainConfigPath;
    private string $masterConfigPath;
    private string $postfixCommand;
    private string $backupDirectory;
    private bool $allowFileModification;

    public function __construct(array $config)
    {
        $this->mainConfigPath = $config['postfix']['main_config'] ?? '/etc/postfix/main.cf';
        $this->masterConfigPath = $config['postfix']['master_config'] ?? '/etc/postfix/master.cf';
        $this->postfixCommand = $config['postfix']['postfix_command'] ?? '/usr/sbin/postfix';
        $this->backupDirectory = $config['postfix']['backup_directory'] ?? '/var/backups/postfix';
        $this->allowFileModification = $config['postfix']['allow_modification'] ?? false;

        // Ensure Postfix command exists
        if (!file_exists($this->postfixCommand)) {
            throw new RuntimeException("Postfix command not found at: {$this->postfixCommand}. Check your configuration.");
        }

        // Ensure the backup directory exists
        if (!is_dir($this->backupDirectory)) {
            mkdir($this->backupDirectory, 0755, true);
        }
    }

    /**
     * Check if Postfix is configured for integration.
     *
     * @return bool
     */
    public function checkConfig(): bool
    {
        $mainConfig = file_exists($this->mainConfigPath) ? file_get_contents($this->mainConfigPath) : '';
        $masterConfig = file_exists($this->masterConfigPath) ? file_get_contents($this->masterConfigPath) : '';

        $mainConfigCheck = strpos($mainConfig, 'content_filter = security-filter:dummy') !== false;
        $masterConfigCheck = strpos($masterConfig, 'security-filter unix - n n - - pipe') !== false;

        if ($mainConfigCheck && $masterConfigCheck) {
            echo "Postfix is properly configured for integration.\n";
            return true;
        }

        echo "Missing Postfix configurations:\n";
        if (!$mainConfigCheck) {
            echo " - 'content_filter' is missing in {$this->mainConfigPath}.\n";
        }
        if (!$masterConfigCheck) {
            echo " - 'security-filter' is missing in {$this->masterConfigPath}.\n";
        }

        return false;
    }

    /**
     * Automatically apply missing configurations if allowed.
     *
     * @return void
     */
    public function autoConfig(): void
    {
        echo "INFO: Checking and configuring Postfix...\n";

        // Check main.cf
        if (file_exists($this->mainConfigPath)) {
            $mainConfigContent = file_get_contents($this->mainConfigPath);
            echo "INFO: Scanning '{$this->mainConfigPath}'...\n";
            if (strpos($mainConfigContent, 'content_filter = security-filter:dummy') === false) {
                echo "INFO: 'content_filter' is missing in {$this->mainConfigPath}, attempting to add it...\n";
                $this->backupFile($this->mainConfigPath); // Ensure backup is triggered
                file_put_contents($this->mainConfigPath, "\ncontent_filter = security-filter:dummy\n", FILE_APPEND);
                echo "SUCCESS: 'content_filter' added to {$this->mainConfigPath}.\n";
            } else {
                echo "INFO: 'content_filter' already exists in {$this->mainConfigPath}.\n";
            }
        } else {
            echo "ERROR: {$this->mainConfigPath} does not exist.\n";
        }

        // Check master.cf
        if (file_exists($this->masterConfigPath)) {
            $masterConfigContent = file_get_contents($this->masterConfigPath);
            echo "INFO: Scanning '{$this->masterConfigPath}'...\n";
            if (strpos($masterConfigContent, 'security-filter unix - n n - - pipe') === false) {
                echo "INFO: 'security-filter' is missing in {$this->masterConfigPath}, attempting to add it...\n";
                $this->backupFile($this->masterConfigPath); // Ensure backup is triggered
                file_put_contents(
                    $this->masterConfigPath,
                    "\nsecurity-filter unix - n n - - pipe\n  flags=Rq user=postfix argv=/usr/bin/php /usr/local/share/cyford/security/index.php --input_type=postfix --ips=${client_address} --categories=3
\n",
                    FILE_APPEND
                );
                echo "SUCCESS: 'security-filter' added to {$this->masterConfigPath}.\n";
            } else {
                echo "INFO: 'security-filter' already exists in {$this->masterConfigPath}.\n";
            }
        } else {
            echo "ERROR: {$this->masterConfigPath} does not exist.\n";
        }

        // Reload Postfix
        $this->reload();
    }
    /**
     * Create a timestamped backup of a file before modifying it.
     *
     * @param string $filePath Path to the file to back up.
     * @return void
     */
    private function backupFile(string $filePath): void
    {
        $timestamp = date('Ymd_His');
        $backupDir = $this->backupDirectory;
        $backupFile = "{$backupDir}/" . basename($filePath) . ".backup_{$timestamp}";

        // Ensure backup directory exists
        if (!is_dir($backupDir)) {
            if (!mkdir($backupDir, 0755, true) && !is_dir($backupDir)) {
                throw new RuntimeException("Failed to create backup directory: {$backupDir}");
            }
        }

        // Create the backup
        if (!copy($filePath, $backupFile)) {
            throw new RuntimeException("Failed to create backup for: {$filePath}");
        }

        echo "Backup created: {$backupFile}\n";
    }
    /**
     * Reload Postfix service.
     *
     * @return void
     */
    public function reload(): void
    {
        echo "Reloading Postfix configuration...\n";

        $output = shell_exec("sudo {$this->postfixCommand} reload 2>&1");

        if (empty($output)) {
            throw new RuntimeException("Failed to reload Postfix. Ensure the Postfix service is running.");
        }

        echo "Postfix reload output: {$output}\n";
    }

    function parseHeaders($rawHeaders)
    {
        $headers = [];
        $lines = explode("\n", $rawHeaders);
        foreach ($lines as $line) {
            if (strpos($line, ':') !== false) {
                list($key, $value) = explode(':', $line, 2);
                $headers[trim($key)] = trim($value);
            }
        }
        return $headers;
    }
    /**
     * Get Postfix service status.
     *
     * @return string Postfix status output.
     */
    public function getStatus(): string
    {
        $command = "systemctl status postfix";
        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException('Failed to retrieve Postfix status.');
        }

        return $output;
    }

}