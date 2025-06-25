<?php

try {
    // Load the bootstrap file for shared dependencies
    $bootstrap = require __DIR__ . '/bootstrap.php';
    $cliArgs = $bootstrap['cliArgs'];
    $logger = $bootstrap['logger'];
    $postfix = $bootstrap['postfix'];
    $spamFilter = $bootstrap['spamFilter'];

    // Get the input type (already verified in CommandLineArguments)
    $inputType = $cliArgs->getInputType();
    $logger->info("Processing input type: {$inputType}");

    switch ($inputType) {
        case 'postfix':
            // Handle Postfix passed data
            $emailData = file_get_contents('php://stdin');
            if (!$emailData) {
                throw new RuntimeException("No email data received from Postfix.");
            }

            // Separate headers and body
            $emailLines = explode("\n\n", $emailData, 2);
            $headersData = $emailLines[0] ?? '';
            $bodyData = $emailLines[1] ?? '';

            // Parse the headers
            $parsedHeaders = $postfix->parseHeaders($headersData);
            $logger->info("Parsed headers: " . json_encode($parsedHeaders));

            // Check if the email is spam
            $isSpam = $spamFilter->isSpam($parsedHeaders, $bodyData);
            if ($isSpam) {
                $logger->warning('Email detected as spam. Processing halted.');
                // You can reject or quarantine the email here if needed.
                exit(0); // Gracefully end without further processing
            } else {
                $logger->info('Email is clean. Continuing processing...');
            }

            // Requeue the email back into Postfix
            $sendmailPath = '/usr/sbin/sendmail'; // Update this if your system has a different path



            $recipient = '';

            // Read email data from stdin
            $emailData = file_get_contents('php://stdin');
            if (!$emailData) {
                throw new RuntimeException("No email data received from Postfix.");
            }

            // Log the raw contents of stdin to a file for debugging
            file_put_contents('/var/log/maillog', $emailData);


            // Separate headers and body
            $emailLines = explode("\n\n", $emailData, 2);
            $headersData = $emailLines[0] ?? '';
            $bodyData = $emailLines[1] ?? '';

            // Parse the headers to extract recipient
            $parsedHeaders = $postfix->parseHeaders($headersData);
            $recipient = $parsedHeaders['To'] ?? ''; // Extract recipient from To header

            if (empty($recipient)) {
                throw new RuntimeException("Recipient not provided in email headers.");
            }

            $logger->info("Recipient extracted from email headers: {$recipient}");




            $requeueCommand = "{$sendmailPath} -i -- {$recipient}";
            $process = proc_open($requeueCommand, [
                ['pipe', 'r'], // stdin
                ['pipe', 'w'], // stdout
                ['pipe', 'w'], // stderr
            ], $pipes);

            if (is_resource($process)) {
                fwrite($pipes[0], $emailData); // Pass the original email to the input pipe
                fclose($pipes[0]);

                // Read output if needed
                $output = stream_get_contents($pipes[1]);
                fclose($pipes[1]);

                // Read errors if any
                $errors = stream_get_contents($pipes[2]);
                fclose($pipes[2]);

                $returnCode = proc_close($process);
                if ($returnCode !== 0) {
                    $logger->error("Failed to requeue email: {$errors}");
                    throw new RuntimeException("Requeueing failed. Return code: {$returnCode}");
                }

                $logger->info("Email successfully passed back to Postfix for further processing.");
            } else {
                throw new RuntimeException("Could not open process to requeue email.");
            }
            break;

        case 'fail2ban':
            // Handle Fail2Ban input
            $ips = $cliArgs->get('ips', '');
            if (!$ips) {
                throw new RuntimeException("No IPs provided for Fail2Ban.");
            }

            $ipsArray = explode(',', $ips);
            $logger->info("Received IPs from Fail2Ban: " . implode(', ', $ipsArray));

            // Process each IP here
            foreach ($ipsArray as $ip) {
                $logger->info("Processing IP: {$ip}");
                // IP processing logic
            }
            break;

        case 'manual':
            // Handle manual input
            $logger->info('Handling manual input type.');
            break;

        default:
            throw new RuntimeException("Unhandled input type: {$inputType}");
    }

    echo "Script executed successfully.\n";

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
}