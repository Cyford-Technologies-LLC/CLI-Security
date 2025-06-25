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