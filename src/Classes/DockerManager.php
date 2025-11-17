<?php
namespace Cyford\Security\Classes;

use Exception;

class DockerManager
{
    private $logger;

    public function __construct($logger = null)
    {
        $this->logger = $logger;
    }

    /**
     * List all running containers
     */
    public function listContainers(): array
    {
        exec('docker ps --format "{{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null', $output, $returnCode);
        
        if ($returnCode !== 0) {
            throw new Exception('Failed to list Docker containers');
        }

        $containers = [];
        foreach ($output as $line) {
            $parts = explode("\t", $line);
            if (count($parts) >= 2) {
                $containers[] = [
                    'name' => $parts[0],
                    'status' => $parts[1],
                    'ports' => $parts[2] ?? ''
                ];
            }
        }

        return $containers;
    }

    /**
     * Execute command in container
     */
    public function execInContainer(string $containerName, string $command): array
    {
        $fullCommand = "docker exec {$containerName} {$command} 2>&1";
        exec($fullCommand, $output, $returnCode);

        return [
            'success' => $returnCode === 0,
            'output' => $output,
            'return_code' => $returnCode
        ];
    }

    /**
     * Connect to Postfix container and configure integration
     */
    public function configurePostfixIntegration(string $postfixContainer = 'postfix'): bool
    {
        try {
            // Check if Postfix container exists
            $containers = $this->listContainers();
            $postfixExists = false;
            
            foreach ($containers as $container) {
                if (strpos($container['name'], $postfixContainer) !== false) {
                    $postfixExists = true;
                    $postfixContainer = $container['name'];
                    break;
                }
            }

            if (!$postfixExists) {
                echo "❌ Postfix container '{$postfixContainer}' not found\n";
                return false;
            }

            echo "✅ Found Postfix container: {$postfixContainer}\n";

            // Configure content filter in Postfix container
            $commands = [
                "postconf -e 'content_filter = cyford-filter:dummy'",
                "echo 'cyford-filter unix - n n - - pipe flags=Rq user=postfix argv=/usr/bin/curl -X POST http://cyford-security:8080/filter --data-binary @-' >> /etc/postfix/master.cf",
                "postfix reload"
            ];

            foreach ($commands as $command) {
                $result = $this->execInContainer($postfixContainer, $command);
                if (!$result['success']) {
                    echo "❌ Failed to execute: {$command}\n";
                    return false;
                }
            }

            echo "✅ Postfix integration configured\n";
            return true;

        } catch (Exception $e) {
            echo "❌ Error configuring Postfix integration: " . $e->getMessage() . "\n";
            return false;
        }
    }

    /**
     * Get container logs
     */
    public function getContainerLogs(string $containerName, int $lines = 50): array
    {
        exec("docker logs --tail {$lines} {$containerName} 2>&1", $output, $returnCode);

        return [
            'success' => $returnCode === 0,
            'logs' => $output
        ];
    }

    /**
     * Restart container
     */
    public function restartContainer(string $containerName): bool
    {
        exec("docker restart {$containerName} 2>/dev/null", $output, $returnCode);
        return $returnCode === 0;
    }
}