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

    // Check if the email has already been processed by the security filter
    if (!empty($headers['X-Processed-By-Security-Filter'])) {
        $logger->info("Email already processed by the security filter. Skipping further processing.");
        exit(0); // Stop further processing
    }

    // Detect spam using SpamFilter
    $isSpam = $spamFilter->isSpam($headers, $body);
    if ($isSpam) {
        $logger->warning("Email flagged as spam. Processing terminated.");
        exit(0); // Gracefully terminate
    }

    $logger->info("Email is clean of spam. Proceeding with requeue.");

    // Extract recipient from 'To' header
    $recipient = extractEmailAddress($headers['To'] ?? '');
    if (empty($recipient)) {
        $logger->error("Recipient not found or invalid in email headers. Headers: " . json_encode($headers));
        throw new RuntimeException("Recipient not found or invalid in email headers.");
    }
    $logger->info("Recipient resolved: {$recipient}");

    // Requeue email back to Postfix
    requeueEmail($emailData, $recipient, $logger);
}

function extractEmailAddress(string $toHeader): string
{
    // Match the email address using a regular expression
    if (preg_match('/<([^>]+)>/', $toHeader, $matches)) {
        // Extract email from formats containing a display name
        return $matches[1];
    }

    // If no angle brackets (<, >), assume the header contains only the email
    if (filter_var($toHeader, FILTER_VALIDATE_EMAIL)) {
        return $toHeader;
    }

    // Invalid format, return an empty string
    return '';
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
    global $config; // Assuming global config is accessible
    $requeueMethod = $config['postfix']['requeue_method'] ?? 'postdrop';

    // Ensure the recipient is valid
    if (!filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
        $message = "Invalid recipient email after extraction: {$recipient}";
        $logger->error($message);
        throw new InvalidArgumentException($message);
    }

    // Add custom header to prevent reprocessing
    if (!preg_match('/^X-Processed-By-Security-Filter:/m', $emailData)) {
        $logger->info("Adding 'X-Processed-By-Security-Filter' header to prevent reprocessing.");
        $emailData = "X-Processed-By-Security-Filter: true\r\n" . $emailData;
    }

    $logger->info("Requeueing email using method: {$requeueMethod} for recipient: {$recipient}");

    switch ($requeueMethod) {
        case 'sendmail':
            requeueWithSendmail($emailData, $recipient, $logger);
            break;

        case 'postdrop':
            requeueWithPostdrop($emailData, $logger);
            break;

        default:
            $error = "Unknown requeue method: {$requeueMethod}";
            $logger->error($error);
            throw new RuntimeException($error);
    }
}
function requeueWithSendmail(string $emailData, string $recipient, $logger): void
{
    $sendmailPath = '/usr/sbin/sendmail';

    $requeueCommand = "{$sendmailPath} -i -- {$recipient}";
    $logger->info("Executing sendmail command: {$requeueCommand}");

    // Open a process for sendmail
    $process = proc_open($requeueCommand, [
        ['pipe', 'r'], // stdin
        ['pipe', 'w'], // stdout
        ['pipe', 'w'], // stderr
    ], $pipes);

    if (is_resource($process)) {
        fwrite($pipes[0], $emailData);
        fclose($pipes[0]);

        $output = stream_get_contents($pipes[1]);
        $errors = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $returnCode = proc_close($process);

        if ($returnCode !== 0) {
            $error = "sendmail failed. Exit code: {$returnCode}. Errors: {$errors}";
            $logger->error($error);
            throw new RuntimeException($error);
        }

        $logger->info("Email successfully queued with sendmail. Output: {$output}");
    } else {
        $error = "Failed to open process for sendmail execution.";
        $logger->error($error);
        throw new RuntimeException($error);
    }
}
function requeueWithPostdrop(string $emailData, $logger): void
{
    $postdropPath = '/usr/sbin/postdrop';

    $logger->info("Delivering email via postdrop...");
    $logger->info("Email data being sent to postdrop: " . substr($emailData, 0, 500)); // Log first 500 characters

    // Open a process for postdrop
    $process = proc_open($postdropPath, [
        ['pipe', 'r'], // stdin
        ['pipe', 'w'], // stdout
        ['pipe', 'w'], // stderr
    ], $pipes);

    if (is_resource($process)) {
        fwrite($pipes[0], $emailData);
        fclose($pipes[0]);

        $output = stream_get_contents($pipes[1]);
        $errors = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $returnCode = proc_close($process);

        if ($returnCode !== 0) {
            $error = "postdrop failed. Exit code: {$returnCode}. Errors: {$errors}";
            $logger->error($error);
            throw new RuntimeException($error);
        }

        $logger->info("Email successfully queued with postdrop. Output: {$output}");
    } else {
        $error = "Failed to open process for postdrop execution.";
        $logger->error($error);
        throw new RuntimeException($error);
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