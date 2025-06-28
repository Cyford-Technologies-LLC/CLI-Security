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
            // Handle internal commands
            $config = require __DIR__ . '/config.php';
            $internal = new \Cyford\Security\Classes\Internal($config, $logger);
            $args = [];
            if ($cliArgs->has('command')) $args['command'] = $cliArgs->get('command');
            if ($cliArgs->has('limit')) $args['limit'] = (int)$cliArgs->get('limit');
            if ($cliArgs->has('pattern_id')) $args['pattern_id'] = (int)$cliArgs->get('pattern_id');
            if ($cliArgs->has('subject')) $args['subject'] = $cliArgs->get('subject');
            if ($cliArgs->has('body')) $args['body'] = $cliArgs->get('body');
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