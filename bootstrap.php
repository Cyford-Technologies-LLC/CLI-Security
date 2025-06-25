<?php

declare(strict_types=1);

define('BASE_PATH', __DIR__);

// Load dependencies and configuration
require_once BASE_PATH . '/vendor/autoload.php';
$config = require BASE_PATH . '/config.php';
use Cyford\Security\Classes\Logger;

// Initialize Logger
$logger = new Logger($config);

// Log the start of initialization
$logger->info('Starting application initialization.');

// Centralized initializer for services
function initializeService(string $serviceName, callable $initializer, Logger $logger)
{
    try {
        $logger->info("Initializing {$serviceName}...");
        return $initializer();
    } catch (RuntimeException $e) {
        $logger->warning("Initialization of {$serviceName} failed: " . $e->getMessage());
        return null; // Fail gracefully without stopping the app
    }
}

// Turn on detailed error reporting if enabled in config
if (!empty($config['errors']['report_errors']) && $config['errors']['report_errors'] === 1) {
    ini_set('display_errors', '1');
    ini_set('display_startup_errors', '1');
    error_reporting(E_ALL);

    $logger->info('Detailed error reporting is enabled.');
} else {
    $logger->info('Detailed error reporting is disabled.');
}

// Initialize Command-Line Arguments
$cliArgs = initializeService(
    'CommandLineArguments',
    static fn() => new CommandLineArguments($argv),
    $logger
);

// Initialize Systems (for system-related details like OS, memory, etc.)
$systems = initializeService(
    'Systems',
    static fn() => new Systems(),
    $logger
);

// Log system information for reference (optional)
if ($systems) {
    $osInfo = $systems->getOSInfo();
    $logger->info('System Information: ' . json_encode($osInfo));

    $diskUsage = $systems->getDiskUsage();
    $logger->info('Disk Usage: ' . json_encode($diskUsage));
}

// Initialize Postfix (required for spam filtering integration)
$postfix = initializeService('Postfix', static fn() => new Postfix($config), $logger);

// If Postfix is successfully initialized, set up the spam filter
$spamFilter = null;
if ($postfix) {
    $logger->info('Postfix is installed. Checking configuration...');

    if ($postfix->checkConfig()) {
        $logger->info('Postfix configuration verified. Initializing SpamFilter...');
        $spamFilter = initializeService('SpamFilter', static fn() => new SpamFilter($config), $logger);

        if ($spamFilter) {
            $logger->info('SpamFilter initialized successfully and integrated.');
        } else {
            $logger->warning('SpamFilter failed to initialize.');
        }
    } else {
        $logger->warning('Postfix configuration is incomplete. SpamFilter will not be initialized.');
    }
}

// Initialize Fail2Ban
$fail2Ban = initializeService(
    'Fail2Ban',
    static fn() => new Fail2Ban(),
    $logger
);

if ($fail2Ban) {
    try {
        $enabledJails = $fail2Ban->getEnabledJails();
        $logger->info('Enabled Fail2Ban Jails: ' . implode(', ', $enabledJails));
    } catch (RuntimeException $e) {
        $logger->warning("Could not retrieve Fail2Ban jails: " . $e->getMessage());
    }
}

// Initialize Firewall
$firewall = initializeService(
    'Firewall',
    static fn() => new Firewall(),
    $logger
);

if ($firewall) {
    try {
        $status = $firewall->getStatus();
        $logger->info("Firewall Status: {$status}");
    } catch (RuntimeException $e) {
        $logger->warning("Could not retrieve firewall status: " . $e->getMessage());
    }
}

// Log the successful completion of initialization
$logger->info('Application initialization completed successfully.');

// Return the context for application runtime
return [
    'config'     => $config,
    'logger'     => $logger,
    'cliArgs'    => $cliArgs,
    'systems'    => $systems,
    'postfix'    => $postfix,
    'spamFilter' => $spamFilter,
    'fail2Ban'   => $fail2Ban,
    'firewall'   => $firewall,
];