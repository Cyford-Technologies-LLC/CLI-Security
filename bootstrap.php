<?php

define('BASE_PATH', __DIR__);

// Load Composer's autoload (if using Composer)
require_once BASE_PATH . '/vendor/autoload.php';

// Load the configuration
$config = require BASE_PATH . '/config.php';

// Parse command-line arguments
$cliArgs = new CommandLineArguments($argv);

// Initialize the API client
$apiClient = new ApiClient($config);

// Initialize Fail2Ban
try {
    $fail2ban = new Fail2Ban();
} catch (RuntimeException $e) {
    echo "Warning: Fail2Ban initialization failed - " . $e->getMessage() . PHP_EOL;
    $fail2ban = null; // Fail safely
}

// Initialize Postfix
try {
    $postfix = new Postfix();
} catch (RuntimeException $e) {
    echo "Warning: Postfix initialization failed - " . $e->getMessage() . PHP_EOL;
    $postfix = null; // Fail safely
}

// Initialize Firewall
try {
    $firewall = new Firewall();
} catch (RuntimeException $e) {
    echo "Warning: Firewall initialization failed - " . $e->getMessage() . PHP_EOL;
    $firewall = null; // Fail safely
}

// Initialize System
try {
    $system = new System();
} catch (RuntimeException $e) {
    echo "Warning: System initialization failed - " . $e->getMessage() . PHP_EOL;
    $system = null; // Fail safely
}

// Return the shared application resources
return [
    'config' => $config,
    'cliArgs' => $cliArgs,
    'apiClient' => $apiClient,
    'fail2ban' => $fail2ban,
    'postfix' => $postfix,
    'firewall' => $firewall,
    'system' => $system,
];