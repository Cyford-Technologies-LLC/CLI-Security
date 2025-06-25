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
            processEmailFromPostfix($postfix, $spamFilter, $logger);
            break;

        case 'fail2ban':
            // Handle IPs provided by Fail2Ban
            processFail2BanInput($cliArgs, $logger);
            break;

        case 'manual':
            // Handle manual input type
            $logger->info("Processing manual input...");
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
 * Process emails passed by Postfix.
 *
 * @param object $postfix Postfix utility instance
 * @param object $spamFilter Spam filter instance
 * @param object $logger Logger instance
 * @return void
 * @throws RuntimeException
 */
function processEmailFromPostfix($postfix, $spamFilter, $logger): void
{
    $logger->info("Processing email received from Postfix...");

    // Read email data from stdin
    $emailData = file_get_contents('php://stdin');
    if (!$emailData) {
        throw new RuntimeException("No email data received from Postfix.");
    }
    $logger->info("Raw email data successfully read.");

    // Parse headers and body
    list($headers, $body) = parseEmail($emailData);
    $logger->info("Parsed headers: " . json_encode($headers));

    // Detect spam using SpamFilter
    $isSpam = $spamFilter->isSpam($headers, $body);
    if ($isSpam) {
        $logger->warning("Email flagged as spam. Processing terminated.");
        exit(0); // Gracefully end processing
    }

    $logger->info("Email is clean of spam. Proceeding with requeue.");

    // Extract recipient from headers
    $recipient = $headers['To'] ?? null;
    if (empty($recipient)) {
        $logger->error("Recipient not found in email headers. Headers: " . json_encode($headers));
        throw new RuntimeException("Recipient not found in email headers.");
    }

    // Handle potential cases of multiple recipients
    $recipient = extractPrimaryRecipient($recipient);
    $logger->info("Recipient resolved: {$recipient}");

    // Requeue email back to Postfix
    requeueEmail($emailData, $recipient, $logger);
}

function extractPrimaryRecipient(string $toHeader): string
{
    $recipients = explode(',', $toHeader);
    $primaryRecipient = trim($recipients[0]);

    if (!filter_var($primaryRecipient, FILTER_VALIDATE_EMAIL)) {
        throw new RuntimeException("Invalid email address in 'To' header: {$primaryRecipient}");
    }

    return $primaryRecipient;
}

/**
 * Parse email into headers and body.
 *
 * @param string $emailData Raw email data
 * @return array An array with headers and body
 */
function parseEmail(string $emailData): array
{
    // Split raw email data into headers and body
    [$headersRaw, $body] = preg_split("/\R\R/", $emailData, 2);

    $headers = [];
    $lines = explode("\n", $headersRaw);
    $currentHeader = '';

    foreach ($lines as $line) {
        if (preg_match("/^([\w-]+):\s*(.*)$/", $line, $matches)) {
            // Start a new header
            $currentHeader = $matches[1];
            $headers[$currentHeader] = $matches[2];
        } elseif (!empty($currentHeader)) {
            // Handle folded header lines (RFC 5322)
            $headers[$currentHeader] .= ' ' . trim($line);
        }
    }

    return [$headers, $body];
}
/**
 * Requeue the email back to Postfix.
 *
 * @param string $emailData Full email data (headers + body)
 * @param string $recipient Recipient email address
 * @param object $logger Logger instance
 * @return void
 * @throws RuntimeException
 */

function requeueEmail(string $emailData, string $recipient, $logger): void
{
    $sendmailPath = '/usr/sbin/sendmail';

    // Validate recipient email
    if (!filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
        $message = "Invalid recipient email: {$recipient}";
        $logger->error($message);
        throw new InvalidArgumentException($message);
    }

    // Ensure emailData contains a 'To' header with the recipient
    if (!preg_match('/^To: .+/m', $emailData)) {
        $logger->info("Adding 'To' header to email data for recipient: {$recipient}");
        $emailData = "To: {$recipient}\r\n" . $emailData;
    }

    $requeueCommand = "{$sendmailPath} -i -- {$recipient}";
    $logger->info("Requeuing email to Postfix using command: {$requeueCommand}");

    // Execute the requeue process
    $process = proc_open($requeueCommand, [
        ['pipe', 'r'], // stdin
        ['pipe', 'w'], // stdout
        ['pipe', 'w'], // stderr
    ], $pipes);

    if (is_resource($process)) {
        // Write email data to stdin
        fwrite($pipes[0], $emailData);
        fclose($pipes[0]);

        // Capture process output
        $output = stream_get_contents($pipes[1]);
        $errors = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        // Get exit code
        $returnCode = proc_close($process);
        if ($returnCode !== 0) {
            $error = "Failed to requeue email. Exit code: {$returnCode}. Stderr: {$errors}.";
            $logger->error($error);
            throw new RuntimeException($error);
        }

        $logger->info("Email successfully requeued. Output: {$output}");
    } else {
        $logger->error("Failed to open process for requeueing email.");
        throw new RuntimeException("Could not open process to requeue email.");
    }
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