<?php

try {
    // Load the bootstrap file to get shared components
    $bootstrap = require __DIR__ . '/bootstrap.php';
    $apiClient = $bootstrap['apiClient'];
    $cliArgs = $bootstrap['cliArgs'];

    // Retrieve IPs and categories from CLI arguments
    $ipsToReport = explode(',', $cliArgs->get('ips', ''));
    $categories = array_map('intval', explode(',', $cliArgs->get('categories', '')));

    // Validate required arguments
    if (empty($ipsToReport) || empty($categories)) {
        die("Usage: php index.php --ips=8.8.8.8,127.0.0.1 --categories=3,5,8\n");
    }

    // Login to get the API token
    $apiClient->login();

    // Report each IP
    foreach ($ipsToReport as $ip) {
        $apiClient->reportIp($ip, $categories);
    }

    echo "Script finished successfully.\n";
} catch (Exception $e) {
    die("Error in script execution: " . $e->getMessage() . "\n");
}