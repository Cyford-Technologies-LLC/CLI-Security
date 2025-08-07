<?php

declare(strict_types=1);
date_default_timezone_set('America/New_York');

define('BASE_PATH', __DIR__);

// Load dependencies and configuration
require_once BASE_PATH . '/vendor/autoload.php';
$config = require BASE_PATH . '/config.php';
use Cyford\Security\Classes\Logger;
use Cyford\Security\Classes\CommandLineArguments;
use Cyford\Security\Classes\Postfix;
use Cyford\Security\Classes\Fail2Ban;
use Cyford\Security\Classes\Firewall;
use Cyford\Security\Classes\SpamFilter;
use Cyford\Security\Classes\Systems;

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
    ini_set('display_errors', '0');
    ini_set('display_startup_errors', '0');
    ini_set('log_errors', '1');
    error_reporting(E_ALL);

    $logger->info('Detailed error reporting is enabled.');
} else {
    $logger->info('Detailed error reporting is disabled.');
}

// Initialize Command-Line Arguments
$cliArgs = initializeService(
    'CommandLineArguments',
    static function () use ($argv, $logger) {
        try {
            if (empty($argv)) {
                $logger->error('No arguments provided to the script.');
                throw new RuntimeException('No arguments provided.');
            }
            return new CommandLineArguments($argv);
        } catch (RuntimeException $e) {
            $logger->error('Failed to initialize CommandLineArguments: ' . $e->getMessage());
            throw $e;
        }
    },
    $logger
);

// If CommandLineArguments initialization failed, do not proceed
if (!$cliArgs) {
    throw new RuntimeException('Failed to initialize CommandLineArguments.');
}

$inputType = $cliArgs->getInputType(); // Get input type from CLI arguments
$logger->info("Input type: {$inputType}");

// Initialize Systems (optional system-level information, like OS or disk stats)
$systems = initializeService(
    'Systems',
    static fn() => new Systems(),
    $logger
);

// Initialize Postfix if input type is 'postfix'
$postfix = null;
$spamFilter = null;
if ($inputType === 'postfix') {
    $postfix = initializeService('Postfix', static fn() => new Postfix($config), $logger);

    if ($postfix) {
        // Only check config if not processing email (to avoid autoConfig during email processing)
        $isEmailProcessing = isset($argv) && in_array('--input_type=postfix', $argv);
        
        if (!$isEmailProcessing) {
            // Set up Postfix-specific configurations during setup/manual runs
            $logger->info('Postfix is installed. Checking configuration...');

            if ($postfix->checkConfig()) {
                $logger->info('Postfix configuration verified.');
            } else {
                $logger->warning('Postfix configuration is incomplete, attempting to fix...');
                $postfix->autoConfig();

                if ($postfix->checkConfig()) {
                    $logger->info('Postfix has been successfully configured.');
                } else {
                    throw new RuntimeException('Postfix configuration failed. Please check logs for details.');
                }
            }
        }
        
        $spamFilter = initializeService('SpamFilter', static fn() => new SpamFilter($config), $logger);
    }
}

// Initialize Fail2Ban only if input type is 'fail2ban'
$fail2Ban = null;
if ($inputType === 'fail2ban') {
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
}

// Initialize Firewall (optional for all input types)
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

// Log initialization completion
$logger->info('Application initialization completed successfully.');

// Return initialized components to the main script
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