<?php
namespace Cyford\Security\Classes;

class Firewall
{
    private string $firewallType;

    public function __construct()
    {
        if (file_exists('/usr/sbin/firewalld')) {
            $this->firewallType = 'firewalld';
        } elseif (file_exists('/usr/sbin/iptables')) {
            $this->firewallType = 'iptables';
        } else {
            throw new RuntimeException('Neither iptables nor firewalld is installed.');
        }
    }

    /**
     * Add a rule to allow traffic
     *
     * @param string $rule
     * @throws RuntimeException
     */
    public function addRule(string $rule): void
    {
        $command = $this->firewallType === 'firewalld'
            ? "firewall-cmd --permanent --add-rule={$rule}"
            : "iptables {$rule}";

        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException("Failed to add rule: {$rule}");
        }

        if ($this->firewallType === 'firewalld') {
            shell_exec('firewall-cmd --reload');
        }
    }

    /**
     * Remove a rule to deny traffic
     *
     * @param string $rule
     * @throws RuntimeException
     */
    public function removeRule(string $rule): void
    {
        $command = $this->firewallType === 'firewalld'
            ? "firewall-cmd --permanent --remove-rule={$rule}"
            : "iptables -D {$rule}";

        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException("Failed to remove rule: {$rule}");
        }

        if ($this->firewallType === 'firewalld') {
            shell_exec('firewall-cmd --reload');
        }
    }

    /**
     * Get the status of the firewall
     *
     * @return string Firewall status output
     * @throws RuntimeException
     */
    public function getStatus(): string
    {
        $command = $this->firewallType === 'firewalld'
            ? 'firewall-cmd --state'
            : 'systemctl status iptables';

        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException('Failed to retrieve firewall status.');
        }

        return $output;
    }
}