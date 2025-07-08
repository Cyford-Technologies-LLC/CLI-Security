<?php
namespace Cyford\Security\Classes;

use Exception;
use InvalidArgumentException;
use RuntimeException;

class Postfix
{
    private string $mainConfigPath;
    private string $masterConfigPath;
    private string $postfixCommand;
    private string $backupDirectory;
    private bool $allowFileModification;
    private Systems $systems;
    private array $config;
    private ?Database $database = null;
    private ?ApiClient $apiClient = null;

    public function __construct(array $config, ?Systems $systems = null)
    {
        $this->config = $config;
        $this->mainConfigPath = $config['postfix']['main_config'] ?? '/etc/postfix/main.cf';
        $this->masterConfigPath = $config['postfix']['master_config'] ?? '/etc/postfix/master.cf';
        $this->postfixCommand = $config['postfix']['postfix_command'] ?? '/usr/sbin/postfix';
        $this->backupDirectory = $config['postfix']['backup_directory'] ?? '/var/backups/postfix';
        $this->allowFileModification = $config['postfix']['allow_modification'] ?? false;
        $this->systems = $systems ?? new Systems();
        
        // Initialize database if hash detection is enabled
        if ($config['postfix']['spam_handling']['hash_detection'] ?? false) {
            try {
                $this->database = new Database($config);
            } catch (Exception $e) {
                // Database will remain null if initialization fails
            }
        }
        
        // ApiClient will be initialized lazily when needed (requires logger)

        // Ensure Postfix command exists
        if (!file_exists($this->postfixCommand)) {
            throw new RuntimeException("Postfix command not found at: $this->postfixCommand. Check your configuration.");
        }

        // Ensure the backup directory exists
        if (!is_dir($this->backupDirectory) && !mkdir($concurrentDirectory = $this->backupDirectory, 0755, true) && !is_dir($concurrentDirectory)) {
            // Fallback to /tmp if can't create in /var/backups
            $this->backupDirectory = '/tmp/postfix_backups';
            if (!is_dir($this->backupDirectory)) {
                if (!mkdir($concurrentDirectory = $this->backupDirectory, 0755, true) && !is_dir($concurrentDirectory)) {
                    throw new \RuntimeException(sprintf('Directory "%s" was not created', $concurrentDirectory));
                }
            }
        }
    }

    /**
     * Get or initialize ApiClient with logger
     */
    private function getApiClient($logger): ApiClient
    {
        if ($this->apiClient === null) {
            $this->apiClient = new ApiClient($this->config, $logger);
        }
        return $this->apiClient;
    }
    public function processEmail($spamFilter, $logger): void
    {
        $errorHandling = $this->config['postfix']['error_handling'] ?? [];
        $onSystemError = $errorHandling['on_system_error'] ?? 'pass';
        $maxRetries = $errorHandling['max_retries'] ?? 3;
        $retryDelay = $errorHandling['retry_delay'] ?? 1;
        $failSafeMode = $errorHandling['fail_safe_mode'] ?? true;

        $logger->info("Processing email received from Postfix...");

        // Wrap email processing in error handling
        for ($attempt = 1; $attempt <= $maxRetries; $attempt++) {
            try {
                $this->processEmailInternal($spamFilter, $logger);
                return; // Success - exit retry loop
            } catch (Exception $e) {
                $this->logSystemError($e, $attempt, $logger);

                if ($attempt < $maxRetries) {
                    $logger->warning("Attempt {$attempt} failed, retrying in {$retryDelay} seconds...");
                    sleep($retryDelay);
                    continue;
                }

                // All retries exhausted - handle according to config
                $this->handleSystemError($e, $onSystemError, $failSafeMode, $logger);
                return;
            }
        }
    }

    /**
     * Internal email processing (original processEmail logic)
     */
    private function processEmailInternal($spamFilter, $logger): void
    {
        // Skip configuration check during email processing
        // This prevents autoConfig from running during email processing

        // Read email data from stdin
        $emailData = file_get_contents('php://stdin');
        if (!$emailData) {
            throw new RuntimeException("No email data received from Postfix.");
        }
        $logger->info("Raw email data successfully read.");

        // Parse headers and body
        [$headers, $body] = $this->parseEmail($emailData);
        $logger->info("Parsed headers: " . json_encode($headers, JSON_THROW_ON_ERROR));

        // Skip system/security emails to prevent loops
        if ($this->shouldSkipEmail($headers, $logger)) {
            exit(0);
        }

        // Check if already processed
        if ($this->isAlreadyProcessed($headers, $emailData, $logger)) {
            return;
        }

        // Get recipient with multiple fallback methods
        $recipient = $this->getRecipient($headers, $logger);
        if (empty($recipient)) {
            $logger->error("Recipient not found or invalid in email headers.");
            throw new RuntimeException("Recipient not found or invalid in email headers.");
        }
        $logger->info("Recipient resolved: $recipient");

        $subject = $headers['Subject'] ?? '';
        $isSpam = false;
        $spamReason = '';

        // Check hash-based detection first (if enabled)
        $skipSpamFilter = false;

        $logger->info("Starting hash detection check...");
        if ($this->database !== null) {
            $logger->info("Hash detection is enabled, using initialized database...");
            try {
                // Check if this hash is known spam
                $logger->info("Checking for known spam hash...");
                if ($this->database->isKnownSpamHash($subject, $body)) {
                    $isSpam = true;
                    $spamReason = 'Known spam pattern (hash match)';
                    $skipSpamFilter = true;
                    $logger->info("Email flagged as spam by hash detection.");
                }
                // Check if this hash is known clean
                elseif ($this->database->isKnownCleanHash($subject, $body)) {
                    $isSpam = false;
                    $spamReason = 'Known clean pattern (hash match)';
                    $skipSpamFilter = true;
                    $logger->info("Email marked as clean by hash detection - skipping spam filter.");
                } else {
                    $logger->info("No hash match found, will proceed to spam filter");
                }
            } catch (Exception $e) {
                $logger->warning("Database unavailable, skipping hash detection: " . $e->getMessage());
            }
        } else {
            $logger->info("Hash detection is disabled");
        }

        // If not caught by hash, check with spam filter
        if (!$skipSpamFilter) {
            // Check LOCAL spam filter FIRST
            $logger->info("Running local spam filter check first...");
            $isSpam = $spamFilter->isSpam($headers, $body);
            if ($isSpam) {
                $spamReason = $spamFilter->getLastSpamReason() ?? 'Local spam filter detection';
                $logger->info("Local spam filter flagged email: $spamReason");
            } else {
                $logger->info("Local spam filter: email is clean");

                // Only check API if local filter didn't detect spam
                if (($this->config['api']['check_spam_against_server'] ?? false)) {
                    $logger->info("No local spam detected, checking with API...");
                    try {
                        $apiClient = $this->getApiClient($logger);
                        $logger->info("DEBUG: Using ApiClient");
                        $logger->info("DEBUG: About to call login()");
                        try {
                            $apiClient->login();
                            $logger->info("DEBUG: Login completed successfully");
                        } catch (Exception $e) {
                            $logger->error("ERROR: Login failed: " . $e->getMessage());
                            throw $e;
                        }

                        $logger->info("DEBUG: Checking config values...");
                        // Continue with API spam check logic here
                    } catch (Exception $e) {
                        $logger->error("API spam check failed: " . $e->getMessage());
                    }
                }
            }
        }

        // Record hash pattern for future detection
        if ($this->database !== null && !$skipSpamFilter) {
            try {
                $this->database->recordEmailHash($subject, $body, $isSpam);
                $logger->info("Email hash recorded as " . ($isSpam ? 'spam' : 'clean') . " for future detection");
            } catch (Exception $e) {
                $logger->warning("Failed to record email hash: " . $e->getMessage());
            }
        }

        if ($isSpam) {
            $logger->warning("Email flagged as spam. Reason: $spamReason");

            // Report spam to server if enabled
            if ($this->config['api']['report_spam_to_server'] ?? true) {
                try {
                    $apiClient = $this->getApiClient($logger);
                    $apiClient->login();
                    $reportData = [
                        'email' => $headers['From'] ?? '',
                        'content' => $subject . "\n\n" . $body
                    ];
                    $logger->info("Reporting spam to server - from: " . ($headers['From'] ?? 'unknown'));

                    $reportResult = $apiClient->analyzeSpam($headers['From'] ?? '', $body, $headers);
                    $logger->info("Spam report response: " . json_encode($reportResult, JSON_THROW_ON_ERROR));
                    $logger->info("Spam reported to server successfully");
                } catch (Exception $e) {
                    $logger->warning("Failed to report spam to server: " . $e->getMessage());
                }
            }

            // Log detailed spam information
            $this->logSpamEmail($emailData, $headers, $recipient, $spamReason, $logger);

            // Add spam headers if configured
            if ($config['postfix']['spam_handling']['add_spam_headers'] ?? true) {
                $emailData = $this->addSpamHeaders($emailData, $spamReason, $logger);
            }

            // Add footer to spam email if configured
            $emailData = $this->addFooterIfConfigured($emailData, true);


            $this->handleSpamEmail($emailData, $headers, $recipient, $spamReason, $logger);
            return;
        }

        $logger->info("Email is clean of spam. Proceeding with requeue.");

        // Add footer if configured
        $emailData = $this->addFooterIfConfigured($emailData);

        $this->requeueEmail($emailData, $recipient, $logger);
    }


    /**
     * Process email from Postfix content filter with error handling
     */


    /**
     * Remove old security-related entries from master.cf
     */
    private function removeOldEntries(string $content): string
    {
        // Remove old generic smtp entry with content_filter
        $content = preg_replace('/^smtp\s+inet.*content_filter=security-filter:dummy.*$/m', '', $content);
        
        // Remove old security-filter entry
        $content = preg_replace('/^security-filter\s+unix.*$/m', '', $content);
        $content = preg_replace('/^\s+flags=Rq.*security.*$/m', '', $content);
        
        // Remove any existing IP-based entries to avoid duplicates
        $content = preg_replace('/^\d+\.\d+\.\d+\.\d+:smtp\s+inet.*$/m', '', $content);
        $content = preg_replace('/^127\.0\.0\.1:smtp\s+inet.*$/m', '', $content);
        $content = preg_replace('/^\s+-o\s+content_filter=security-filter:dummy.*$/m', '', $content);
        $content = preg_replace('/^\s+-o\s+content_filter=\s*$/m', '', $content);
        $content = preg_replace('/^\s+-o\s+smtpd_client_restrictions=permit_mynetworks,reject.*$/m', '', $content);
        
        // Clean up extra blank lines
        $content = preg_replace('/\n\s*\n\s*\n/', "\n\n", $content);
        
        return $content;
    }
    
    /**
     * Generate only the IP-based entries to add to master.cf
     */
    private function generateIPBasedEntries(string $publicIP): string
    {
        return <<<EOF
# Cyford Security Filter Configuration
# External SMTP (with content filter for security)
{$publicIP}:smtp inet  n       -       n       -       -       smtpd
  -o content_filter=security-filter:dummy

# Internal SMTP (no content filter)
127.0.0.1:smtp inet  n       -       n       -       -       smtpd
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o content_filter=

# Security filter service
security-filter unix - n n - - pipe
  flags=Rq user=report-ip argv=/usr/bin/php /usr/local/share/cyford/security/index.php --input_type=postfix --recipient=\${{recipient}} --ips=\${{client_address}} --categories=3
EOF;
    }

    /**
     * Check if email should be skipped
     */
    private function shouldSkipEmail(array $headers, $logger): bool
    {
        $from = $headers['From'] ?? '';
        $subject = $headers['Subject'] ?? '';

        if (str_contains($from, 'report-ip@') ||
            str_contains($subject, '*** SECURITY information') ||
            str_contains($headers['Auto-Submitted'] ?? '', 'auto-generated')) {
            $logger->info("Skipping system/security email to prevent processing loop");
            return true;
        }
        return false;
    }

    /**
     * Check if email is already processed
     */
    private function isAlreadyProcessed(array $headers, string $emailData, $logger): bool
    {
        $hasSecurityHeader = isset($headers['X-Processed-By-Security-Filter']);
        $hasSecurityHeaderInRaw = str_contains($emailData, 'X-Processed-By-Security-Filter:');
        
        $logger->info("Security header check - In parsed headers: " . ($hasSecurityHeader ? 'YES' : 'NO') . 
                      ", In raw data: " . ($hasSecurityHeaderInRaw ? 'YES' : 'NO'));
        
        if ($hasSecurityHeader || $hasSecurityHeaderInRaw) {
            $logger->info("Email already processed by the security filter. Allowing normal delivery.");
            return true;
        }
        return false;
    }

    /**
     * Parse email into headers and body
     */
    private function parseEmail(string $emailData): array
    {
        [$headersRaw, $body] = preg_split("/\R\R/", $emailData, 2);

        $headers = [];
        $lines = explode("\n", $headersRaw);
        $currentHeader = '';

        foreach ($lines as $line) {
            if (preg_match("/^([\w-]+):\s*(.*)$/", $line, $matches)) {
                $currentHeader = $matches[1];
                $headers[$currentHeader] = $matches[2];
            } elseif (!empty($currentHeader)) {
                $headers[$currentHeader] .= ' ' . trim($line);
            }
        }

        return [$headers, $body];
    }

    /**
     * Get recipient using multiple fallback methods
     */
    private function getRecipient(array $headers, $logger): string
    {
        // Method 1: Standard To header
        if (!empty($headers['To'])) {
            $recipient = $this->extractEmailAddress($headers['To']);
            if (!empty($recipient)) {
                $logger->info("Recipient found in To header: {$recipient}");
                return $recipient;
            }
        }
        
        // Method 2: Delivered-To header (Postfix adds this)
        if (!empty($headers['Delivered-To'])) {
            $recipient = $this->extractEmailAddress($headers['Delivered-To']);
            if (!empty($recipient)) {
                $logger->info("Recipient found in Delivered-To header: {$recipient}");
                return $recipient;
            }
        }
        
        // Method 3: X-Original-To header
        if (!empty($headers['X-Original-To'])) {
            $recipient = $this->extractEmailAddress($headers['X-Original-To']);
            if (!empty($recipient)) {
                $logger->info("Recipient found in X-Original-To header: {$recipient}");
                return $recipient;
            }
        }
        
        // Method 4: Check common Postfix environment variables
        $envVars = ['RECIPIENT', 'USER', 'ORIGINAL_RECIPIENT', 'EXTENSION'];
        foreach ($envVars as $envVar) {
            if (!empty($_ENV[$envVar])) {
                $recipient = $this->extractEmailAddress($_ENV[$envVar]);
                if (!empty($recipient)) {
                    $logger->info("Recipient found in {$envVar} environment: {$recipient}");
                    return $recipient;
                }
            }
        }
        
        // Method 5: Parse from Postfix queue ID (last resort)
        // Postfix often passes recipient info in the process environment
        if (!empty($_SERVER['argv'])) {
            foreach ($_SERVER['argv'] as $arg) {
                if (str_contains($arg, '@')) {
                    $recipient = $this->extractEmailAddress($arg);
                    if (!empty($recipient)) {
                        $logger->info("Recipient found in server argv: {$recipient}");
                        return $recipient;
                    }
                }
            }
        }
        
        // Method 6: Check for --recipient argument from Postfix
        global $argv;
        if (!empty($argv)) {
            foreach ($argv as $i => $iValue) {
                if ($iValue === '--recipient' && isset($argv[$i + 1])) {
                    $recipient = $this->extractEmailAddress($argv[$i + 1]);
                    if (!empty($recipient)) {
                        $logger->info("Recipient found in --recipient argument: {$recipient}");
                        return $recipient;
                    }
                }
                // Also check for --recipient=email format
                if (str_starts_with($iValue, '--recipient=')) {
                    $recipient = $this->extractEmailAddress(substr($iValue, 12));
                    if (!empty($recipient)) {
                        $logger->info("Recipient found in --recipient= argument: {$recipient}");
                        return $recipient;
                    }
                }
            }

            // Fallback: any argument with @
            foreach ($argv as $arg) {
                if (str_contains($arg, '@')) {
                    $recipient = $this->extractEmailAddress($arg);
                    if (!empty($recipient)) {
                        $logger->info("Recipient found in command line: {$recipient}");
                        return $recipient;
                    }
                }
            }
        }
        
        // Method 7: Try to extract from any header containing an email
        foreach ($headers as $headerName => $headerValue) {
            if (str_contains($headerValue, '@') && !in_array($headerName, ['From', 'Reply-To', 'Return-Path', 'Sender'])) {
                $recipient = $this->extractEmailAddress($headerValue);
                if (!empty($recipient) && str_contains($recipient, 'cyfordtechnologies.com')) {
                    $logger->info("Recipient found in {$headerName} header: {$recipient}");
                    return $recipient;
                }
            }
        }
        
        $logger->warning("No recipient found in any header or environment variable");
        return '';
    }

    /**
     * Extract email address from header with fallback methods
     */
    private function extractEmailAddress(string $toHeader): string
    {
        // Method 1: Extract from angle brackets <email@domain.com>
        if (preg_match('/<([^>]+)>/', $toHeader, $matches)) {
            return $matches[1];
        }

        // Method 2: Direct email validation
        if (filter_var($toHeader, FILTER_VALIDATE_EMAIL)) {
            return $toHeader;
        }
        
        // Method 3: Extract first email-like pattern
        if (preg_match('/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/', $toHeader, $matches)) {
            return $matches[1];
        }

        return '';
    }

    /**
     * Requeue email back to Postfix
     */
    private function requeueEmail(string $emailData, string $recipient, $logger): void
    {
        global $config;
        $requeueMethod = $config['postfix']['requeue_method'] ?? 'postdrop';

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

        $logger->info("Requeueing email using method: $requeueMethod for recipient: $recipient");

        switch ($requeueMethod) {
            case 'sendmail':
                $this->requeueWithSendmail($emailData, $recipient, $logger);
                break;
            case 'postdrop':
                $this->requeueWithPostdrop($emailData, $logger);
                break;
            case 'postpickup':
                $this->requeueWithPostpickup($emailData, $logger);
                break;
            case 'smtp':
                $this->requeueWithSMTP($emailData, $recipient, $logger);
                break;
            case 'dovecot-lda':
                $this->requeueWithDovecotLDA($emailData, $recipient, $logger);
                break;
            default:
                $error = "Unknown requeue method: {$requeueMethod}";
                $logger->error($error);
                throw new RuntimeException($error);
        }
    }

    /**
     * Requeue with sendmail
     */
    private function requeueWithSendmail(string $emailData, string $recipient, $logger): void
    {
        $sendmailPath = '/usr/sbin/sendmail';
        $requeueCommand = "{$sendmailPath} -i -- {$recipient}";
        $logger->info("Executing sendmail command: $requeueCommand");

        $process = proc_open($requeueCommand, [
            ['pipe', 'r'],
            ['pipe', 'w'],
            ['pipe', 'w'],
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
                throw new RuntimeException("sendmail failed. Exit code: $returnCode. Errors: $errors");
            }

            $logger->info("Email successfully requeued with sendmail");
        } else {
            throw new RuntimeException("Failed to open process for sendmail execution");
        }
    }

    /**
     * Requeue with SMTP
     */
    private function requeueWithSMTP(string $emailData, string $recipient, $logger): void
    {
        $smtpHost = '127.0.0.1';
        $smtpPort = 25;
        
        $logger->info("Connecting to SMTP server at $smtpHost:$smtpPort");
        
        $socket = fsockopen($smtpHost, $smtpPort, $errno, $errstr, 30);
        if (!$socket) {
            throw new RuntimeException("Failed to connect to SMTP server: {$errstr} ({$errno})");
        }
        
        try {
            // Read greeting
            $response = fgets($socket);
            if (!str_starts_with($response, '220')) {
                throw new RuntimeException("SMTP server error: $response");
            }
            
            // HELO
            fwrite($socket, "HELO localhost\r\n");
            $response = fgets($socket);
            if (!str_starts_with($response, '250')) {
                throw new RuntimeException("HELO failed: $response");
            }
            
            // MAIL FROM
            fwrite($socket, "MAIL FROM:<>\r\n");
            $response = fgets($socket);
            if (!str_starts_with($response, '250')) {
                throw new RuntimeException("MAIL FROM failed: $response");
            }
            
            // RCPT TO
            fwrite($socket, "RCPT TO:<{$recipient}>\r\n");
            $response = fgets($socket);
            if (!str_starts_with($response, '250')) {
                throw new RuntimeException("RCPT TO failed: $response");
            }
            
            // DATA
            fwrite($socket, "DATA\r\n");
            $response = fgets($socket);
            if (!str_starts_with($response, '354')) {
                throw new RuntimeException("DATA failed: $response");
            }
            
            // Send email data
            fwrite($socket, $emailData);
            if (!str_ends_with($emailData, "\r\n")) {
                fwrite($socket, "\r\n");
            }
            fwrite($socket, ".\r\n");
            
            $response = fgets($socket);
            if (!str_starts_with($response, '250')) {
                throw new RuntimeException("Email delivery failed: $response");
            }
            
            // QUIT
            fwrite($socket, "QUIT\r\n");
            fgets($socket);
            
            $logger->info("Email requeued via SMTP");
            
        } finally {
            fclose($socket);
        }
    }

    /**
     * Requeue with postdrop
     */
    private function requeueWithPostdrop(string $emailData, $logger): void
    {
        $logger->info("Delivering email via postdrop...");
        
        $tempFile = tempnam('/tmp', 'postdrop_');
        
        try {
            if (file_put_contents($tempFile, $emailData) === false) {
                throw new RuntimeException("Failed to write temporary file");
            }
            
            $command = "postdrop < {$tempFile}";
            $result = shell_exec($command . ' 2>&1');
            
            if ($result !== null && trim($result) !== '') {
                throw new RuntimeException("Postdrop failed: $result");
            }
            
            $logger->info("Email successfully queued via postdrop");
            
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    /**
     * Requeue with postpickup
     */
    private function requeueWithPostpickup(string $emailData, $logger): void
    {
        $logger->info("Delivering email via pickup directory...");
        
        $pickupDir = '/var/spool/postfix/pickup';
        $queueId = uniqid('sec_', true);
        $tempFile = "/tmp/{$queueId}";
        $finalFile = "{$pickupDir}/{$queueId}";
        
        try {
            if (file_put_contents($tempFile, $emailData) === false) {
                throw new RuntimeException("Failed to write temporary file");
            }
            
            $moveCmd = "sudo mv {$tempFile} {$finalFile}";
            exec($moveCmd, $output, $returnCode);
            
            if ($returnCode !== 0) {
                throw new RuntimeException("Move failed with return code: $returnCode");
            }
            
            exec("sudo chown postfix:postdrop {$finalFile}");
            exec("sudo chmod 644 {$finalFile}");
            
            $logger->info("Email successfully queued via pickup directory: $queueId");
            
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    /**
     * Handle spam email according to configuration
     */
    private function handleSpamEmail(string $emailData, array $headers, string $recipient, string $spamReason, $logger): void
    {
        global $config;

        // Check spam handling method FIRST
        $spamHandlingMethod = $config['postfix']['spam_handling_method'] ?? 'maildir';

        if ($spamHandlingMethod === 'maildir') {
            $logger->info("Using maildir / cron spam handling method");
            $this->deliverSpamToMaildir($emailData, $recipient, $logger);
            return;
        }

        $spamAction = $config['postfix']['spam_handling']['action'] ?? 'reject';
        
        switch ($spamAction) {
            case 'reject':
                $this->bounceSpamEmail($headers, $logger);
                break;
                
            case 'quarantine':
                $this->quarantineSpamEmail($emailData, $recipient, $logger);
                break;
                
            case 'allow':
                $logger->info("Spam email allowed through as per configuration.");
                $emailData = $this->addFooterIfConfigured($emailData, true);
                $this->requeueEmail($emailData, $recipient, $logger);
                break;
                
            case 'headers':
                $logger->info("Adding X-Spam headers and delivering email.");
                $emailData = $this->addSpamHeaders($emailData, $spamReason, $logger);
                $this->requeueEmail($emailData, $recipient, $logger);
                break;
                
            default:
                $logger->warning("Unknown spam action: $spamAction. Adding spam headers.");
                $emailData = $this->addSpamHeaders($emailData, $spamReason, $logger);
                $this->requeueEmail($emailData, $recipient, $logger);
        }
    }

    /**
     * Bounce spam email back to sender using Postfix smart host
     */
    private function bounceSpamEmail(array $headers, $logger): void
    {
        global $config;
        $bounceMessage = $config['postfix']['spam_handling']['bounce_message'] ?? 'Message rejected due to spam content.';
        $from = $headers['From'] ?? 'unknown';
        
        $logger->info("Bouncing spam email from: $from");
        
        // Extract sender email from From header
        $senderEmail = $this->extractEmailAddress($from);
        if (empty($senderEmail)) {
            $logger->warning("Cannot bounce - invalid sender email: $from");
            return;
        }
        
        // Create bounce message
        $bounceEmail = $this->createBounceMessage($headers, $bounceMessage);
        
        // Use Postfix's requeue method (which uses smart host) instead of direct sendmail
        try {
            $this->requeueEmail($bounceEmail, $senderEmail, $logger);
            $logger->info("Bounce message sent via smart host to: $senderEmail");
        } catch (Exception $e) {
            $logger->error("Failed to send bounce via smart host: " . $e->getMessage());
        }
    }

    /**
     * Quarantine spam email to specified folder
     */
    private function quarantineSpamEmail(string $emailData, string $recipient, $logger): void
    {
        global $config;
        $spamFolder = $config['postfix']['spam_handling']['quarantine_folder'] ?? 'Spam';
        
        $logger->info("Quarantining spam email to $spamFolder folder for $recipient");
        
        // Resolve alias to real user
        $realUser = $this->resolveEmailAlias($recipient, $logger);
        if (!$realUser) {
            $logger->error("Could not resolve recipient $recipient to a real user. Rejecting email.");
            $this->bounceSpamEmail([], $logger);
            return;
        }
        
        $logger->info("Resolved $recipient to real user: $realUser");
        
        // Get quarantine method from config
        global $config;
        $quarantineMethod = $config['postfix']['spam_handling']['quarantine_method'] ?? 'user_maildir';
        
        if ($quarantineMethod === 'user_maildir') {
            // Use user's maildir (requires proper permissions)
            $maildirTemplate = $config['postfix']['spam_handling']['maildir_path'] ?? '/home/{user}/Maildir';
            $userMaildir = str_replace('{user}', $realUser, $maildirTemplate);
            
            $logger->info("Quarantine method: user_maildir");
            $logger->info("Real user: $realUser, User maildir: $userMaildir");
            
            // Check if user maildir exists
            if (!is_dir($userMaildir)) {
                $logger->error("User maildir does not exist: $userMaildir");
                throw new \RuntimeException("User maildir does not exist: $userMaildir");
            }
            
            // Detect existing spam folders (common names)
            $spamFolderCandidates = [
                '.Spambox',     // Your existing folder
                '.Spam',        // Common name
                '.Junk',        // Thunderbird
                '.Junk Email',  // Outlook
                '.INBOX.Spam',  // Some IMAP setups
                '.INBOX.Junk'   // Some IMAP setups
            ];
            
            $maildirPath = null;
            foreach ($spamFolderCandidates as $candidate) {
                $candidatePath = $userMaildir . '/' . $candidate;
                if (is_dir($candidatePath)) {
                    $maildirPath = $candidatePath;
                    $logger->info("Found existing spam folder: $maildirPath");
                    break;
                }
            }
            
            // If no existing spam folder found, create default one
            if (!$maildirPath) {
                $defaultSpamFolder = $config['postfix']['spam_handling']['quarantine_folder'] ?? 'Spam';
                $maildirPath = "$userMaildir/.{$defaultSpamFolder}";
                
                $logger->info("No existing spam folder found, creating: $maildirPath");
                
                // Create directories directly (no sudo in chroot)
                $success = true;
                $success = $success && (mkdir($maildirPath, 0775, true) || is_dir($maildirPath));
                $success = $success && (mkdir($maildirPath . '/cur', 0775, true) || is_dir($maildirPath . '/cur'));
                $success = $success && (mkdir($maildirPath . '/new', 0775, true) || is_dir($maildirPath . '/new'));
                $success = $success && (mkdir($maildirPath . '/tmp', 0775, true) || is_dir($maildirPath . '/tmp'));

                if ($success) {
                    $logger->info("Created spam folder: $maildirPath");
                } else {
                    $logger->error("Failed to create spam folder: $maildirPath");
                    throw new \RuntimeException("Quarantine failed - cannot create spam folder");
                }
            }
            
            $spamFile = $maildirPath . '/new/';
        }
        else {
            // Use system quarantine (chroot compatible)
            $systemQuarantinePath = $config['postfix']['spam_handling']['system_quarantine_path'] ?? '/var/spool/postfix/quarantine';
            $userSpamPath = $systemQuarantinePath . '/' . $realUser;
            
            // Create spam storage if it doesn't exist
            if (!is_dir($userSpamPath)) {
                if (!mkdir($userSpamPath, 0755, true) && !is_dir($userSpamPath)) {
                    $logger->error("Failed to create system quarantine folder: $userSpamPath");
                    throw new \RuntimeException("Quarantine failed - cannot create spam folder");
                }
                $logger->info("Created system quarantine folder: $userSpamPath");
            }
            $spamFile = $userSpamPath . '/';
        }
        
        // Save email to determined spam location
        $filename = time() . '.' . uniqid('', true) . '.spam';
        $fullSpamFile = $spamFile . $filename;
        
        if (file_put_contents($fullSpamFile, $emailData)) {
            $logger->info("Spam email quarantined to: $fullSpamFile (method: $quarantineMethod)");
        } else {
            $logger->error("Failed to quarantine spam email. Rejecting instead.");
            throw new \RuntimeException("Quarantine failed");
        }
    }

    /**
     * Resolve email alias to real user using cached system
     */
    private function resolveEmailAlias(string $email, $logger): ?string
    {
        $username = explode('@', $email)[0];
        
        // First check if it's a real system user
        if ($this->systems->isRealUser($username)) {
            return $username;
        }
        
        // Use cached alias mapping
        $realUser = $this->systems->getAliasMapping($email);
        if ($realUser) {
            $logger->info("Found cached alias mapping: $email -> $realUser");
            return $realUser;
        }
        
        $logger->warning("Could not resolve alias $email to a real user");
        return null;
    }

    /**
     * Add X-Spam headers to email (SpamAssassin compatible)
     */
    private function addSpamHeaders(string $emailData, string $spamReason, $logger): string
    {
        $logger->info("Adding X-Spam headers to email");
        
        // Generate spam score (simple scoring based on reason)
        $spamScore = $this->calculateSpamScore($spamReason);
        $spamLevel = str_repeat('*', min(10, (int)$spamScore)); // Max 10 stars
        
        // Create X-Spam headers (SpamAssassin compatible)
        $spamHeaders = "X-Spam-Flag: YES\r\n";
        $spamHeaders .= "X-Spam-Checker-Version: Cyford Web Armor 1.0\r\n";
        $spamHeaders .= "X-Spam-Level: $spamLevel\r\n";
        $spamHeaders .= "X-Spam-Score: $spamScore\r\n";
        $spamHeaders .= "X-Spam-Status: Yes, score=$spamScore required=5.0 tests=CYFORD_SPAM\r\n";
        $spamHeaders .= "X-Spam-Subject: ***SPAM*** \r\n";
        $spamHeaders .= "X-Spam-Report: $spamReason\r\n";
        
        // Add headers after existing headers
        if (preg_match('/(.*?\r?\n\r?\n)(.*)/s', $emailData, $matches)) {
            $existingHeaders = $matches[1];
            $body = $matches[2];
            
            // Modify subject to add ***SPAM*** prefix if not already there
            if (!preg_match('/Subject:.*\*\*\*SPAM\*\*\*/i', $existingHeaders)) {
                $existingHeaders = preg_replace(
                    '/^(Subject:\s*)(.*?)$/m',
                    '$1***SPAM*** $2',
                    $existingHeaders
                );
            }
            
            return $existingHeaders . $spamHeaders . "\r\n" . $body;
        }
        
        // Fallback: add headers at the beginning
        return $spamHeaders . "\r\n" . $emailData;
    }
    
    /**
     * Calculate spam score based on detection reason
     */
    private function calculateSpamScore(string $spamReason): float
    {
        $score = 5.0; // Base spam score
        
        // Increase score based on specific patterns
        if (stripos($spamReason, 'suspicious subject') !== false) {
            $score += 2.0;
        }
        if (stripos($spamReason, 'body patterns') !== false) {
            $score += 3.0;
        }
        if (stripos($spamReason, 'blacklist') !== false) {
            $score += 5.0;
        }
        if (stripos($spamReason, 'hash match') !== false) {
            $score += 10.0;
        }
        
        return round($score, 1);
    }

    /**
     * Add footer to email if configured
     */
    private function addFooterIfConfigured(string $emailData, bool $isSpam = false): string
    {
        global $config;
        $addFooter = $config['postfix']['spam_handling']['add_footer'] ?? false;
        
        if (!$addFooter) {
            return $emailData;
        }
        
        $footerText = $config['postfix']['spam_handling']['footer_text'] ?? '\n\n--- This email has been scanned by Cyford Security Filter ---';
        
        if ($isSpam) {
            $footerText = '\n\n--- This email was flagged as spam and quarantined by Cyford Web Armor ---';
        }
        
        // Find the end of headers and add footer to body
        if (preg_match('/(.*?\r?\n\r?\n)(.*)/s', $emailData, $matches)) {
            $headers = $matches[1];
            $body = $matches[2];
            return $headers . $body . $footerText;
        }
        
        return $emailData . $footerText;
    }

    /**
     * Log spam email with full details
     */
    private function logSpamEmail(string $emailData, array $headers, string $recipient, string $spamReason, $logger): void
    {
        global $config;
        $spamLogFile = $config['postfix']['spam_handling']['spam_log_file'] ?? '/var/log/cyford-security/spam.log';
        
        // Ensure spam log directory exists
        $logDir = dirname($spamLogFile);
        if (!is_dir($logDir)) {
            if (!mkdir($logDir, 0755, true) && !is_dir($logDir)) {
                throw new \RuntimeException(sprintf('Directory "%s" was not created', $logDir));
            }
        }
        
        $timestamp = date('Y-m-d H:i:s');
        $from = $headers['From'] ?? 'unknown';
        $subject = $headers['Subject'] ?? 'No Subject';
        $messageId = $headers['Message-ID'] ?? 'unknown';
        
        $logEntry = <<<EOF
================================================================================
SPAM DETECTED: {$timestamp}
================================================================================
Recipient: {$recipient}
From: {$from}
Subject: {$subject}
Message-ID: {$messageId}
Spam Reason: {$spamReason}

--- RAW EMAIL DATA ---
{$emailData}
--- END RAW EMAIL DATA ---


EOF;
        
        // Append to spam log file
        if (file_put_contents($spamLogFile, $logEntry, FILE_APPEND | LOCK_EX) === false) {
            $logger->error("Failed to write to spam log file: $spamLogFile");
        } else {
            $logger->info("Spam email logged to: $spamLogFile");
        }
    }

    /**
     * Create bounce message
     */
    private function createBounceMessage(array $headers, string $bounceMessage): string
    {
        $from = $headers['From'] ?? 'unknown';
        $subject = $headers['Subject'] ?? 'No Subject';
        $messageId = $headers['Message-ID'] ?? uniqid('', true);
        
        return <<<EOF
From: MAILER-DAEMON@{$_SERVER['SERVER_NAME']}
To: {$from}
Subject: Mail Delivery Failure - Spam Detected
In-Reply-To: {$messageId}

{$bounceMessage}

Original Subject: {$subject}
EOF;
    }

    /**
     * Create a timestamped backup of a file before modifying it.
     */
    private function backupFile(string $filePath): void
    {
        $timestamp = date('Ymd_His');
        $backupDir = $this->backupDirectory;
        $backupFile = "{$backupDir}/" . basename($filePath) . ".backup_{$timestamp}";

        // Ensure backup directory exists and is writable
        if (!is_dir($backupDir)) {
            if (!mkdir($backupDir, 0755, true) && !is_dir($backupDir)) {
                // Try /tmp as fallback
                $backupDir = '/tmp';
                $backupFile = "{$backupDir}/" . basename($filePath) . ".backup_{$timestamp}";
            }
        }

        // Check if directory is writable
        if (!is_writable($backupDir)) {
            echo "WARNING: Cannot write to $backupDir, using /tmp for backup\n";
            $backupDir = '/tmp';
            $backupFile = "{$backupDir}/" . basename($filePath) . ".backup_{$timestamp}";
        }

        // Create the backup
        if (!copy($filePath, $backupFile)) {
            echo "WARNING: Failed to create backup for: $filePath. Continuing without backup.\n";
            return;
        }

        echo "Backup created: $backupFile\n";
    }

    /**
     * Send spam data to API if configured
     */
//    private function sendSpamToAPI(string $subject, string $body, array $headers, $logger): void
//    {
//        global $config;
//
//        // Check if API integration is enabled
//        if (empty($config['api']['spam_check_endpoint'])) {
//            return;
//        }
//
//        try {
//            require_once __DIR__ . '/SpamAPI.php';
//            $spamAPI = new SpamAPI($config, 'postfix');
//
//            // Extract client IP from headers
//            $clientIP = '';
//            if (!empty($headers['Received'])) {
//                preg_match('/\[(\d+\.\d+\.\d+\.\d+)]/', $headers['Received'], $matches);
//                $clientIP = $matches[1] ?? '';
//            }
//
//            // Send spam data only if new (include headers for full context)
//            $wasSent = $spamAPI->sendSpamDataIfNew($subject, $body, $clientIP, $headers);
//
//            if ($wasSent) {
//                $logger->info("Spam data sent to Cyford Web Armor API");
//            } else {
//                $logger->info("Spam data already sent, skipping API call");
//            }
//
//        } catch (Exception $e) {
//            $logger->warning("Failed to send spam data to API: " . $e->getMessage());
//        }
//    }

    /**
     * Handle system errors according to configuration
     */
    private function handleSystemError(Exception $e, string $onSystemError, bool $failSafeMode, $logger): void
    {
        $logger->error("System error after all retries: " . $e->getMessage());
        
        // Read email data for error handling
        $emailData = file_get_contents('php://stdin');
        if (!$emailData) {
            $logger->error("Cannot read email data for error handling");
            exit(1);
        }
        
        [$headers, $body] = $this->parseEmail($emailData);
        $recipient = $this->getRecipient($headers, $logger);
        
        switch ($onSystemError) {
            case 'pass':
                $logger->info("System error - passing email through as configured");
                if ($failSafeMode) {
                    $emailData = $this->addSystemErrorFooter($emailData);
                }
                $this->requeueEmail($emailData, $recipient, $logger);
                break;
                
            case 'fail':
                $logger->info("System error - failing email as configured");
                $this->bounceSystemError($headers, $e->getMessage(), $logger);
                break;
                
            case 'quarantine':
                $logger->info("System error - quarantining email as configured");
                $this->quarantineSystemError($emailData, $recipient, $e->getMessage(), $logger);
                break;
                
            default:
                $logger->warning("Unknown error handling action: $onSystemError, defaulting to pass");
                $this->requeueEmail($emailData, $recipient, $logger);
        }
    }
    
    /**
     * Log system errors
     */
    private function logSystemError(Exception $e, int $attempt, $logger): void
    {
        global $config;
        $errorLogFile = $config['postfix']['error_handling']['error_log_file'] ?? '/var/log/cyford-security/system-errors.log';
        
        $timestamp = date('Y-m-d H:i:s');
        $errorEntry = "[$timestamp] ATTEMPT $attempt: " . $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine() . "\n";
        
        file_put_contents($errorLogFile, $errorEntry, FILE_APPEND | LOCK_EX);
        $logger->error("System error (attempt $attempt): " . $e->getMessage());
    }
    
    /**
     * Add system error footer to email
     */
    private function addSystemErrorFooter(string $emailData): string
    {
        $footer = "\n\n--- WARNING: This email was processed with system errors - Cyford Web Armor ---";
        
        if (preg_match('/(.*?\r?\n\r?\n)(.*)/s', $emailData, $matches)) {
            $headers = $matches[1];
            $body = $matches[2];
            return $headers . $body . $footer;
        }
        
        return $emailData . $footer;
    }
    
    /**
     * Bounce email due to system error
     */
    private function bounceSystemError(array $headers, string $errorMessage, $logger): void
    {
        $from = $headers['From'] ?? 'unknown';
        $subject = $headers['Subject'] ?? 'No Subject';
        
        $bounceMessage = "Your email could not be processed due to a system error.\n\n";
        $bounceMessage .= "Error: $errorMessage\n\n";
        $bounceMessage .= "Please try again later or contact the administrator.";
        
        $bounceEmail = $this->createBounceMessage($headers, $bounceMessage);
        
        $tempFile = tempnam('/tmp', 'system_error_bounce_');
        file_put_contents($tempFile, $bounceEmail);
        
        $command = "/usr/sbin/sendmail -t < {$tempFile}";
        shell_exec($command);
        
        unlink($tempFile);
        $logger->info("System error bounce sent to: $from");
    }
    
    /**
     * Quarantine email due to system error
     */
    private function quarantineSystemError(string $emailData, string $recipient, string $errorMessage, $logger): void
    {
        $realUser = $this->resolveEmailAlias($recipient, $logger);
        if (!$realUser) {
            $logger->error("Cannot quarantine - could not resolve recipient $recipient");
            return;
        }
        
        $quarantineFolder = "/home/{$realUser}/Maildir/.SystemErrors";
        
        if (!is_dir($quarantineFolder)) {
            if (!mkdir($quarantineFolder, 0755, true) && !is_dir($quarantineFolder)) {
                throw new \RuntimeException(sprintf('Directory "%s" was not created', $quarantineFolder));
            }
            if (!mkdir($concurrentDirectory = $quarantineFolder . '/cur', 0755, true) && !is_dir($concurrentDirectory)) {
                throw new \RuntimeException(sprintf('Directory "%s" was not created', $concurrentDirectory));
            }
            if (!mkdir($concurrentDirectory = $quarantineFolder . '/new', 0755, true) && !is_dir($concurrentDirectory)) {
                throw new \RuntimeException(sprintf('Directory "%s" was not created', $concurrentDirectory));
            }
            if (!mkdir($concurrentDirectory = $quarantineFolder . '/tmp', 0755, true) && !is_dir($concurrentDirectory)) {
                throw new \RuntimeException(sprintf('Directory "%s" was not created', $concurrentDirectory));
            }
        }
        
        $filename = time() . '.' . uniqid('', true) . '.syserr';
        $errorFile = $quarantineFolder . '/new/' . $filename;
        
        // Add error information to email
        $errorHeader = "X-System-Error: $errorMessage\r\n";
        $emailData = $errorHeader . $emailData;
        
        if (file_put_contents($errorFile, $emailData)) {
            $logger->info("Email quarantined due to system error: $errorFile");
        } else {
            $logger->error("Failed to quarantine email with system error");
        }
    }

    /**
     * Requeue with Dovecot LDA
     */
    private function requeueWithDovecotLDA(string $emailData, string $recipient, $logger): void
    {
        $logger->info("Delivering email via Dovecot LDA...");
        
        // Find dovecot-lda path
        $ldaPaths = ['/usr/lib/dovecot/dovecot-lda', '/usr/libexec/dovecot/dovecot-lda'];
        $ldaPath = null;
        foreach ($ldaPaths as $path) {
            if (file_exists($path)) {
                $ldaPath = $path;
                break;
            }
        }
        
        if (!$ldaPath) {
            throw new RuntimeException("dovecot-lda not found");
        }
        
        // Extract username from recipient
        $username = explode('@', $recipient)[0];
        
        $command = "{$ldaPath} -d {$username} -f ''";
        $logger->info("Executing dovecot-lda command: $command");
        
        $process = proc_open($command, [
            ['pipe', 'r'],
            ['pipe', 'w'],
            ['pipe', 'w'],
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
                throw new RuntimeException("dovecot-lda failed. Exit code: $returnCode. Errors: $errors");
            }
            
            $logger->info("Email successfully delivered via dovecot-lda");
        } else {
            throw new RuntimeException("Failed to open process for dovecot-lda execution");
        }
    }

    /**
     * Deliver spam to maildir via task queue (chroot-safe)
     */
    private function deliverSpamToMaildir(string $emailData, string $recipient, $logger): void
    {
        global $config;
        
        $logger->info("=== SPAM MAILDIR DELIVERY VIA TASK QUEUE ===");
        $logger->info("Recipient: $recipient");
        
        $username = strstr($recipient, '@', true);
        $logger->info("Extracted username: $username");
        
        $maildirPath = str_replace('{user}', $username, $config['postfix']['spam_handling']['maildir_path']);
        $spamDir = $maildirPath . '/.' . $config['postfix']['spam_handling']['quarantine_folder'];
        $filename = time() . '.' . getmypid() . '.spam';
        $targetPath = $spamDir . '/new/' . $filename;
        
        $logger->info("Target path: $targetPath");
        $logger->info("Email size: " . strlen($emailData) . " bytes");
        
        try {
            // Add task to queue for root processor to handle
            $systems = new Systems();
            $taskId = $systems->addTask('move_spam', [
                'email_content' => $emailData,
                'recipient' => $recipient,
                'username' => $username,
                'target_path' => $targetPath,
                'spam_dir' => $spamDir
            ]);
            
            $logger->info("✅ SUCCESS: Spam task added to queue: $taskId");
            $logger->info("Task will be processed by root cron job within 1 minute");
            $logger->info("=== SPAM MAILDIR DELIVERY QUEUED ===");
            exit(0);
            
        } catch (Exception $e) {
            $logger->error("❌ FAILED: Could not add spam task to queue: " . $e->getMessage());
            $logger->error("Falling back to standard requeue method");
        }
    }

}