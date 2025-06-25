<?php
namespace Cyford\Security\Classes;

class Fail2Ban
{
    private string $fail2banCommand;

    public function __construct(string $fail2banClientPath = '/usr/bin/fail2ban-client')
    {
        $this->fail2banCommand = $fail2banClientPath;

        if (!file_exists($this->fail2banCommand)) {
            throw new RuntimeException("Fail2Ban client not found at: {$this->fail2banCommand}");
        }
    }

    /**
     * Get list of enabled jails
     *
     * @return array List of enabled jails
     * @throws RuntimeException
     */
    public function getEnabledJails(): array
    {
        $command = "{$this->fail2banCommand} status";
        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException('Failed to execute Fail2Ban status command.');
        }

        preg_match('/Jail list:\s*(.*)/', $output, $matches);

        return isset($matches[1]) ? array_map('trim', explode(',', $matches[1])) : [];
    }

    /**
     * Get the status of a specific jail
     *
     * @param string $jail
     * @return string Jail status output
     * @throws RuntimeException
     */
    public function getJailStatus(string $jail): string
    {
        $command = "{$this->fail2banCommand} status {$jail}";
        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException("Failed to retrieve status for the jail: {$jail}");
        }

        return $output;
    }

    /**
     * Ban an IP address manually
     *
     * @param string $jail
     * @param string $ip
     * @return void
     * @throws RuntimeException
     */
    public function banIp(string $jail, string $ip): void
    {
        $command = "{$this->fail2banCommand} set {$jail} banip {$ip}";
        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException("Failed to ban IP {$ip} for jail: {$jail}");
        }
    }

    /**
     * Unban an IP address manually
     *
     * @param string $jail
     * @param string $ip
     * @return void
     * @throws RuntimeException
     */
    public function unbanIp(string $jail, string $ip): void
    {
        $command = "{$this->fail2banCommand} set {$jail} unbanip {$ip}";
        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException("Failed to unban IP {$ip} for jail: {$jail}");
        }
    }
}