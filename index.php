<?php

try {
    // Load dependencies and configuration
    $bootstrap = require __DIR__ . '/bootstrap.php';
    $cliArgs = $bootstrap['cliArgs'];
    $logger = $bootstrap['logger'];
    $postfix = $bootstrap['postfix'];
    $spamFilter = $bootstrap['spamFilter'];

    // Determine the input type
    $inputType = $cliArgs->getInputType();
    $logger->info("Starting processing. Input type: {$inputType}");

    switch ($inputType) {
        case 'postfix':
            // Handle email input from Postfix
            $postfix->processEmail($spamFilter, $logger);
            break;

        case 'fail2ban':
            // Handle IPs provided by Fail2Ban
            processFail2BanInput($cliArgs, $logger);
            break;

        case 'manual':
            // Handle manual input type
            $logger->info("Processing manual input...");
            break;
            
        case 'internal':
            // Handle internal commands directly without full bootstrap
            require_once __DIR__ . '/src/Classes/Database.php';
            require_once __DIR__ . '/src/Classes/Internal.php';
            require_once __DIR__ . '/src/Classes/SpamFilter.php';
            require_once __DIR__ . '/src/Classes/Systems.php';
            
            $config = require __DIR__ . '/config.php';
            $internal = new \Cyford\Security\Classes\Internal($config, $logger);
            
            // Parse command line arguments manually for internal commands
            $args = [];
            foreach ($argv as $arg) {
                if (strpos($arg, '--command=') === 0) {
                    $args['command'] = substr($arg, 10);
                } elseif (strpos($arg, '--limit=') === 0) {
                    $args['limit'] = (int)substr($arg, 8);
                } elseif (strpos($arg, '--pattern_id=') === 0) {
                    $args['pattern_id'] = (int)substr($arg, 13);
                } elseif (strpos($arg, '--subject=') === 0) {
                    $args['subject'] = substr($arg, 10);
                } elseif (strpos($arg, '--body=') === 0) {
                    $args['body'] = substr($arg, 7);
                } elseif (strpos($arg, '--username=') === 0) {
                    $args['username'] = substr($arg, 11);
                } elseif (strpos($arg, '--password=') === 0) {
                    $args['password'] = substr($arg, 11);
                }elseif (strpos($arg, '--ip=') === 0) {
                    $args['ip'] = substr($arg, 5);
                } elseif (strpos($arg, '--jail=') === 0) {
                    $args['jail'] = substr($arg, 7);
                } elseif (strpos($arg, '--reason=') === 0) {
                    $args['reason'] = substr($arg, 9);
                }
                }
            
            $internal->processCommand($args);
            break;

        default:
            throw new RuntimeException("Unknown input type: {$inputType}");
    }

    echo "Script executed successfully.\n";
    exit(0);

} catch (Exception $e) {
    // Handle global script errors
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
}

/**
 * Process IP input from Fail2Ban.
 *
 * @param object $cliArgs Command-line arguments utility
 * @param object $logger Logger instance
 * @return void
 * @throws RuntimeException
 */
function processFail2BanInput($cliArgs, $logger): void
{
    $logger->info("Processing input from Fail2Ban...");

    $ips = $cliArgs->get('ips', '');
    if (!$ips) {
        throw new RuntimeException("No IPs provided for Fail2Ban.");
    }

    $ipsArray = explode(',', $ips);
    foreach ($ipsArray as $ip) {
        $logger->info("Processing IP: {$ip}");
        // Add logic here to handle Fail2Ban actions (e.g., ban or unban IPs)
    }

    $logger->info("Fail2Ban input processing complete.");
}