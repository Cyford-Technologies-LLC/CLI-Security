<?php

try {
    // Load the bootstrap file to get shared components
    $bootstrap = require __DIR__ . '/bootstrap.php';
    $cliArgs = $bootstrap['cliArgs']; // Access CommandLineArguments instance
    $logger = $bootstrap['logger'];
    $postfix = $bootstrap['postfix'];
    $spamFilter = $bootstrap['spamFilter'];

    // Get the input type (already validated in CommandLineArguments)
    $inputType = $cliArgs->getInputType();

    $logger->info("Processing input type: {$inputType}");

    switch ($inputType) {
        case 'postfix':
            // Handle Postfix input
            $emailData = file_get_contents('php://stdin');
            if (!$emailData) {
                throw new RuntimeException("No email data received from Postfix.");
            }

            // Parse headers and body from email input
            $emailLines = explode("\n\n", $emailData, 2); // Separate headers and body
            $headersData = $emailLines[0];
            $bodyData = $emailLines[1] ?? '';
            $parsedHeaders = $postfix->parseHeaders($headersData);

            $logger->info("Parsed headers: " . json_encode($parsedHeaders));

            // Run SpamFilter analysis
            if ($spamFilter->isSpam($parsedHeaders, $bodyData)) {
                $logger->warning('Email detected as spam.');
            } else {
                $logger->info('Email is clean.');
            }
            break;

        case 'fail2ban':
            // Handle Fail2Ban input via arguments
            $ips = $cliArgs->get('ips', '');
            if (!$ips) {
                throw new RuntimeException("No IPs provided for Fail2Ban.");
            }

            $ipsArray = explode(',', $ips);
            $logger->info("Received IPs from Fail2Ban: " . implode(', ', $ipsArray));

            // Process each IP with desired logic
            foreach ($ipsArray as $ip) {
                $logger->info("Processing IP: {$ip}");
                // Add IP handling logic here
            }
            break;

        case 'manual':
            // Handle manual or other types of input
            $logger->info('Handling manual input.');
            break;

        default:
            throw new RuntimeException("Unhandled input type: {$inputType}");
    }

    echo "Script executed successfully.\n";

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
}