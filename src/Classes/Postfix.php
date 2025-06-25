<?php

class Postfix
{
    private string $mainConfigPath;
    private string $masterConfigPath;
    private string $postfixCommand;
    private bool $allowFileModification;

    public function __construct(array $config)
    {
        $this->mainConfigPath = $config['postfix']['main_config'] ?? '/etc/postfix/main.cf';
        $this->masterConfigPath = $config['postfix']['master_config'] ?? '/etc/postfix/master.cf';
        $this->postfixCommand = $config['postfix']['postfix_command'] ?? '/usr/sbin/postfix';
        $this->allowFileModification = $config['postfix']['allow_modification'] ?? false;

        if (!file_exists($this->postfixCommand)) {
            throw new RuntimeException("Postfix command not found at: {$this->postfixCommand}. Check your configuration.");
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

        // Add content_filter to main.cf
        if (!strpos(file_get_contents($this->mainConfigPath), 'content_filter = security-filter:dummy')) {
            file_put_contents($this->mainConfigPath, "\ncontent_filter = security-filter:dummy\n", FILE_APPEND);
            echo " - Added 'content_filter' to {$this->mainConfigPath}.\n";
        }

        // Add security-filter to master.cf
        if (!strpos(file_get_contents($this->masterConfigPath), 'security-filter unix - n n - - pipe')) {
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
     * Parse email headers and extract relevant details.
     *
     * @param string $emailHeaders Raw email headers as a string.
     * @return array Parsed header details (From, To, Subject, IP, etc.).
     */
    public function parseHeaders(string $emailHeaders): array
    {
        $parsed = [];

        $lines = explode("\n", $emailHeaders);
        foreach ($lines as $line) {
            if (stripos($line, 'From:') === 0) {
                $parsed['from'] = trim(substr($line, 5));
            } elseif (stripos($line, 'To:') === 0) {
                $parsed['to'] = trim(substr($line, 3));
            } elseif (stripos($line, 'Subject:') === 0) {
                $parsed['subject'] = trim(substr($line, 8));
            } elseif (stripos($line, 'Received:') === 0 && preg_match('/\[(\d+\.\d+\.\d+\.\d+)\]/', $line, $matches)) {
                $parsed['ip'] = $matches[1];
            }
        }

        return $parsed;
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