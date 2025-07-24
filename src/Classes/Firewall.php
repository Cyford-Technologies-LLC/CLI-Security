<?php
namespace Cyford\Security\Classes;

use RuntimeException;

class Firewall
{
    private string $firewallType;
    private ?string $defaultZone = null;

    public function __construct()
    {
        if (file_exists('/usr/sbin/firewalld')) {
            $this->firewallType = 'firewalld';
            // Get default zone for firewalld
            $output = shell_exec('firewall-cmd --get-default-zone 2>&1');
            if ($output) {
                $this->defaultZone = trim($output);
            }
        } elseif (file_exists('/usr/sbin/iptables')) {
            $this->firewallType = 'iptables';
        } else {
            throw new RuntimeException('Neither iptables nor firewalld is installed.');
        }
    }

    /**
     * Get the current firewall type
     *
     * @return string The firewall type ('iptables' or 'firewalld')
     */
    public function getFirewallType(): string
    {
        return $this->firewallType;
    }

    /**
     * Add a rule to allow traffic
     *
     * @param string $rule
     * @return bool Success status
     * @throws RuntimeException
     */
    public function addRule(string $rule): bool
    {
        $command = '';

        if ($this->firewallType === 'firewalld') {
            // For firewalld, check if the rule is already in proper format
            if (strpos($rule, '--permanent') === false && strpos($rule, '--add') === false) {
                // If not in firewalld format, try to determine zone
                $zone = $this->defaultZone ?: 'public';
                $command = "firewall-cmd --permanent --zone={$zone} --add-rich-rule='{$rule}'";
            } else {
                // Rule already in firewalld format
                $command = "firewall-cmd {$rule}";
            }
        } else {
            // For iptables, ensure the rule has the proper format
            if (strpos($rule, '-A ') === 0 || strpos($rule, '-I ') === 0) {
                $command = "iptables {$rule}";
            } else {
                // Try to convert to iptables format if not already
                $command = "iptables -A INPUT {$rule}";
            }
        }

        exec($command . ' 2>&1', $output, $returnCode);

        if ($returnCode !== 0) {
            throw new RuntimeException("Failed to add rule: {$rule}. Error: " . implode("\n", $output));
        }

        if ($this->firewallType === 'firewalld') {
            // Reload firewalld to apply changes
            exec('firewall-cmd --reload');
        } else {
            // For iptables, save rules to make them persistent
            $this->saveIptablesRules();
        }

        return true;
    }

    /**
     * Remove a rule to deny traffic
     *
     * @param string $rule
     * @return bool Success status
     * @throws RuntimeException
     */
    public function removeRule(string $rule): bool
    {
        $command = '';

        if ($this->firewallType === 'firewalld') {
            // For firewalld, check if the rule is already in proper format
            if (strpos($rule, '--permanent') === false && strpos($rule, '--remove') === false) {
                // If not in firewalld format, try to determine zone
                $zone = $this->defaultZone ?: 'public';
                $command = "firewall-cmd --permanent --zone={$zone} --remove-rich-rule='{$rule}'";
            } else {
                // Rule already in firewalld format
                $command = "firewall-cmd {$rule}";
            }
        } else {
            // For iptables, ensure the rule has the proper format
            if (strpos($rule, '-D ') === 0) {
                $command = "iptables {$rule}";
            } else {
                // Try to convert to iptables format if not already
                $command = "iptables -D INPUT {$rule}";
            }
        }

        exec($command . ' 2>&1', $output, $returnCode);

        if ($returnCode !== 0) {
            throw new RuntimeException("Failed to remove rule: {$rule}. Error: " . implode("\n", $output));
        }

        if ($this->firewallType === 'firewalld') {
            // Reload firewalld to apply changes
            exec('firewall-cmd --reload');
        } else {
            // For iptables, save rules to make them persistent
            $this->saveIptablesRules();
        }

        return true;
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
            ? 'firewall-cmd --state && firewall-cmd --list-all'
            : 'systemctl status iptables && iptables -L -n -v';

        exec($command . ' 2>&1', $output, $returnCode);

        if (empty($output)) {
            throw new RuntimeException('Failed to retrieve firewall status.');
        }

        return implode("\n", $output);
    }

    /**
     * Block an IP address
     *
     * @param string $ip IP address to block
     * @return bool Success status
     */
    public function blockIP(string $ip): bool
    {
        // Validate IP address
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new RuntimeException("Invalid IP address: $ip");
        }

        try {
            if ($this->firewallType === 'firewalld') {
                $zone = $this->defaultZone ?: 'public';
                $rule = "rule family=\"ipv4\" source address=\"$ip\" reject";
                return $this->addRule("--zone=$zone --add-rich-rule='$rule'");
            } else {
                return $this->addRule("-I INPUT -s $ip -j DROP");
            }
        } catch (RuntimeException $e) {
            return false;
        }
    }

    /**
     * Unblock an IP address
     *
     * @param string $ip IP address to unblock
     * @return bool Success status
     */
    public function unblockIP(string $ip): bool
    {
        // Validate IP address
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new RuntimeException("Invalid IP address: $ip");
        }

        try {
            if ($this->firewallType === 'firewalld') {
                $zone = $this->defaultZone ?: 'public';
                $rule = "rule family=\"ipv4\" source address=\"$ip\" reject";
                return $this->removeRule("--zone=$zone --remove-rich-rule='$rule'");
            } else {
                return $this->removeRule("-D INPUT -s $ip -j DROP");
            }
        } catch (RuntimeException $e) {
            return false;
        }
    }

    /**
     * Allow a specific port
     *
     * @param int $port Port number
     * @param string $protocol Protocol (tcp/udp)
     * @return bool Success status
     */
    public function allowPort(int $port, string $protocol = 'tcp'): bool
    {
        try {
            if ($this->firewallType === 'firewalld') {
                $zone = $this->defaultZone ?: 'public';
                return $this->addRule("--zone=$zone --add-port=$port/$protocol");
            } else {
                return $this->addRule("-A INPUT -p $protocol --dport $port -j ACCEPT");
            }
        } catch (RuntimeException $e) {
            return false;
        }
    }

    /**
     * Block a specific port
     *
     * @param int $port Port number
     * @param string $protocol Protocol (tcp/udp)
     * @return bool Success status
     */
    public function blockPort(int $port, string $protocol = 'tcp'): bool
    {
        try {
            if ($this->firewallType === 'firewalld') {
                $zone = $this->defaultZone ?: 'public';
                return $this->removeRule("--zone=$zone --remove-port=$port/$protocol");
            } else {
                return $this->addRule("-A INPUT -p $protocol --dport $port -j DROP");
            }
        } catch (RuntimeException $e) {
            return false;
        }
    }

    /**
     * Make iptables rules persistent across reboots
     *
     * @return bool Success status
     */
    private function saveIptablesRules(): bool
    {
        if ($this->firewallType !== 'iptables') {
            return true; // Nothing to do for firewalld
        }

        // Check for iptables-save command
        exec('which iptables-save 2>&1', $output, $returnCode);
        if ($returnCode !== 0) {
            return false;
        }

        // Determine the rules save location based on distribution
        $saveFile = '/etc/sysconfig/iptables'; // Default for RHEL/CentOS

        if (file_exists('/etc/debian_version')) {
            $saveFile = '/etc/iptables/rules.v4'; // Debian/Ubuntu

            // Create directory if it doesn't exist
            if (!file_exists('/etc/iptables')) {
                mkdir('/etc/iptables', 0755);
            }
        }

        // Save the rules
        exec("iptables-save > $saveFile 2>&1", $output, $returnCode);

        return $returnCode === 0;
    }
}