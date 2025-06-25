<?php
namespace Cyford\Security\Classes;

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
        if (!$this->allowFileModification) {
            echo "Automatic configuration is disabled. Please enable 'allow_modification' in your configuration to apply changes.\n";
            return;
        }

        echo "Applying missing configurations...\n";

        // Backup and update main.cf
        if (!strpos(file_get_contents($this->mainConfigPath), 'content_filter = security-filter:dummy')) {
            $this->backupFile($this->mainConfigPath);
            file_put_contents($this->mainConfigPath, "\ncontent_filter = security-filter:dummy\n", FILE_APPEND);
            echo " - Added 'content_filter' to {$this->mainConfigPath}.\n";
        }

        // Backup and update master.cf
        if (!strpos(file_get_contents($this->masterConfigPath), 'security-filter unix - n n - - pipe')) {
            $this->backupFile($this->masterConfigPath);
            file_put_contents(
                $this->masterConfigPath,
                "\nsecurity-filter unix - n n - - pipe\n  flags=Rq user=report-ip argv=/usr/local/bin/cyford-report --ips=\${client_address} --categories=3\n",
                FILE_APPEND
            );
            echo " - Added 'security-filter' to {$this->masterConfigPath}.\n";
        }

        // Reload Postfix to apply the changes
        $this->reload();
        echo "Postfix has been reconfigured and reloaded.\n";
    }

    /**
     * Create a timestamped backup of a file before modifying it.
     *
     * @param string $filePath Path to the file to back up.
     * @return void
     */
    private function backupFile(string $filePath): void
    {
        if (!file_exists($filePath)) {
            throw new RuntimeException("File not found for backup: {$filePath}");
        }

        $timestamp = date('Ymd_His');
        $fileName = basename($filePath);
        $backupPath = "{$this->backupDirectory}/{$fileName}.backup_{$timestamp}";

        if (!copy($filePath, $backupPath)) {
            throw new RuntimeException("Failed to create backup for: {$filePath}");
        }

        echo " - Backup created: {$backupPath}\n";
    }

    /**
     * Reload Postfix service.
     *
     * @return void
     */
    public function reload(): void
    {
        $command = "{$this->postfixCommand} reload";
        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException('Failed to reload Postfix. Check your system configuration or logs.');
        }

        echo "Postfix reloaded successfully.\n";
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