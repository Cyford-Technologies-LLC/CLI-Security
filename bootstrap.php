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

return [
    'config' => $config,
    'cliArgs' => $cliArgs,
    'apiClient' => $apiClient,
];