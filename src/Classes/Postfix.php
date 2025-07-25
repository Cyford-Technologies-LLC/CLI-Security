<?php
namespace Cyford\Security\Classes;

use Exception;
use InvalidArgumentException;
use RuntimeException;
use Cyford\Security\Classes\ThreatCategory\Spam;
use Cyford\Security\Classes\ThreatCategory\Phishing;
use Cyford\Security\Classes\ThreatCategory\Malware;
use Cyford\Security\Classes\ThreatCategory\Virus;
use Cyford\Security\Classes\Logger;

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

    // Add these new properties at the top with your other properties
    private array $threatDetectors = [];
    private array $lastThreatResults = [];
    protected Logger $logger;


    public function __construct(array $config, ?Systems $systems = null)
    {
        $this->config = $config;
        $this->mainConfigPath = $config['postfix']['main_config'] ?? '/etc/postfix/main.cf';
        $this->masterConfigPath = $config['postfix']['master_config'] ?? '/etc/postfix/master.cf';
        $this->postfixCommand = $config['postfix']['postfix_command'] ?? '/usr/sbin/postfix';
        $this->backupDirectory = $config['postfix']['backup_directory'] ?? '/var/backups/postfix';
        $this->allowFileModification = $config['postfix']['allow_modification'] ?? false;
        $this->systems = $systems ?? new Systems();
        $this->logger = new Logger($config);
        
        // Initialize a database if hash detection is enabled
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
            $this->apiClient = new ApiClient($this->config, $this->logger);
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



        // Extract sender IP after parsing
        $senderIp = $this->extractSenderIp($headers, $emailData);
        $this->logger->info("Sender IP: " . ($senderIp ?: 'Not found'));




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

        // WHITELIST CHECK - Skip all spam checks if whitelisted
        $logger->info("Checking  black listed");
        if ($this->isBlacklisted($headers, $emailData, $senderIp, $logger)) {
            $logger->info("Email is blacklisted, rejecting");
            $spamReason = "Email is blacklisted";
            $this->handleSpamEmail($emailData, $headers, $recipient, $spamReason, $logger);
            return;
        }
        $logger->info("Checking  whitelisted");

        if ($this->isWhitelisted($headers, $emailData, $senderIp, $logger)) {
            $logger->info("Email is whitelisted, skipping spam checks and delivering directly");
            // For allowlisted emails, you might still want to add a special footer or header
            if ($this->config['postfix']['spam_handling']['add_footer'] ?? false) {
                $emailData = $this->addFooterIfConfigured($emailData, false); // true indicates allowlisted
            }
            $this->requeueEmail($emailData, $recipient, $logger);
            return; // Exit processing - email is already delivered
        }



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
        }
        else {
            $logger->info("Hash detection is disabled");
        }

        // If not caught by hash, check with spam filter
// If not caught by hash, check with spam filter
        if (!$skipSpamFilter) {

            // NEW CODE STARTS HERE - check for all threats after the standard spam check
            if ($this->config['postfix']['spam_handling']['threat_detection']['enabled'] ?? false) {
                $logger->info("Running dynamic threat detection check...");
                $isThreat = $this->checkAllThreats($headers, $body);

                if ($isThreat) {
                    $isSpam = true; // Mark as spam if any threat is detected
                    $spamReason = "Dynamic threat detection: " . $this->getLastThreatReasons();
                    $logger->info("Dynamic threat detection flagged email: $spamReason");
                }
                else {
                    $isSpam = false;
                    $logger->info("Dynamic threat detection: email is clean");
                }
            }

            // Check LOCAL spam filter FIRST
//            $logger->info("Running local spam filter check first...");
//            $isSpam = $spamFilter->isSpam($headers, $body);
            if ($isSpam) {
//                $spamReason = $spamFilter->getLastSpamReason() ?? 'Local spam filter detection';
                $spamReason = 'API spam detection: ';
                if (isset($apiResult['spam_analysis']['factors']) && is_array($apiResult['spam_analysis']['factors'])) {
                    $spamReason .= implode(', ', $apiResult['spam_analysis']['factors']);
                } else {
                    $spamReason .= 'Unknown factors';
                }
                $logger->info("Local spam filter flagged email: $spamReason");

                $this->handleSpamEmail($emailData, $headers, $recipient, $spamReason, $logger);
                return;


            }

            $logger->info("Local spam filter: email is clean");

            // Only check API if local filter didn't detect spam

// Only check API if local filter didn't detect spam
            if (($this->config['api']['check_spam_against_server'] ?? true)) {
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

                    // This is the missing part that actually calls the API for spam checking
                    $response = $apiClient->analyzeSpam(
                        $headers['From'] ,
                        $body,
                        $headers,
                        [
                            'ip' => $senderIp ?? $_SERVER['REMOTE_ADDR'] ,
                            'to_email' => $recipient,
                            'hostname' => gethostname(),
                            'threshold' => $this->config['api']['spam_threshold'] ?? 70
                        ]
                    );

                    $logger->info("DEBUG: API response received: " . json_encode($response, JSON_THROW_ON_ERROR));
                    $logger->info("StatusCode: "  . $response['status_code']);


                    // Process the API response
                    if ($response['status_code'] === 200) {
                        $logger->info("status code: 200 " );

                        $apiResult = $response['response'];

                        if (is_array($apiResult['data'])){
                            $dataResults = $apiResult['data'];
                        }
                        else{
                            $dataResults = json_decode($apiResult['data'], TRUE, 512, JSON_THROW_ON_ERROR);
                        }
                        $logger->info("DEBUG: API response decoded: " . json_encode($dataResults, JSON_THROW_ON_ERROR));

                        $dataResults_is_array = is_array($dataResults);
                        $logger->info("data is array: "  . $dataResults_is_array);

                        if (isset($dataResults) && is_array($dataResults)) {
                            $logger->info("DEBUG: 'data' key exists.");
                            if (isset($dataResults['spam_analysis']) && is_array($dataResults['spam_analysis'])) {
                                $isSpam = $apiResult['data']['spam_analysis']['is_spam'] ?? false;

                                if ($isSpam) {
                                    $isSpam = true;
//                                    $spamReason = 'API spam detection: ' . ($apiResult['reason'] ?? 'Unknown');
                                    $logger->info("API flagged email as spam: True"); // Simplified for now

                                    $spamReason = 'API spam detection: ';
                                    if (isset($apiResult['data']['spam_analysis']['factors']) && is_array($apiResult['data']['spam_analysis']['factors'])) {
                                        $spamReason .= implode(', ', $apiResult['data']['spam_analysis']['factors']);
                                    } else {
                                        $spamReason .= 'Unknown factors';
                                    }

                                    $logger->info("API flagged email as spam: $spamReason");

                                    $this->handleSpamEmail($emailData, $headers, $recipient, $spamReason, $logger);
                                    return;
                                }

                                $logger->info("API confirmed email is clean");

                                // Process clean email (add footer if configured)
                                if ($this->config['postfix']['spam_handling']['add_footer'] ?? false) {
                                    $emailData = $this->addFooterIfConfigured($emailData);
                                }

                                // Deliver the clean email
                                $this->requeueEmail($emailData, $recipient, $logger);
                                return;
                            }
                        }
                    } else {
                        $logger->warning("API returned non-200 status: " . $response['status_code']);
                    }
                } catch (Exception $e) {
                    $logger->error("API spam check failed: " . $e->getMessage());
                    // Continue processing even if API check fails
                }
            }

// If we get here, process as clean (API check failed or disabled)
            $logger->info("Processing as clean email (default path)");
            if ($this->config['postfix']['spam_handling']['add_footer'] ?? false) {
                $emailData = $this->addFooterIfConfigured($emailData);
            }
            $this->requeueEmail($emailData, $recipient , $logger);
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
$publicIP:smtp inet  n       -       n       -       -       smtpd
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
                $logger->info("Recipient found in To header: $recipient");
                return $recipient;
            }
        }
        
        // Method 2: Delivered-To header (Postfix adds this)
        if (!empty($headers['Delivered-To'])) {
            $recipient = $this->extractEmailAddress($headers['Delivered-To']);
            if (!empty($recipient)) {
                $logger->info("Recipient found in Delivered-To header: $recipient");
                return $recipient;
            }
        }
        
        // Method 3: X-Original-To header
        if (!empty($headers['X-Original-To'])) {
            $recipient = $this->extractEmailAddress($headers['X-Original-To']);
            if (!empty($recipient)) {
                $logger->info("Recipient found in X-Original-To header: $recipient");
                return $recipient;
            }
        }
        
        // Method 4: Check common Postfix environment variables
        $envVars = ['RECIPIENT', 'USER', 'ORIGINAL_RECIPIENT', 'EXTENSION'];
        foreach ($envVars as $envVar) {
            if (!empty($_ENV[$envVar])) {
                $recipient = $this->extractEmailAddress($_ENV[$envVar]);
                if (!empty($recipient)) {
                    $logger->info("Recipient found in $envVar environment: $recipient");
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
                        $logger->info("Recipient found in server argv: $recipient");
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
                        $logger->info("Recipient found in --recipient argument: $recipient");
                        return $recipient;
                    }
                }
                // Also check for --recipient=email format
                if (str_starts_with($iValue, '--recipient=')) {
                    $recipient = $this->extractEmailAddress(substr($iValue, 12));
                    if (!empty($recipient)) {
                        $logger->info("Recipient found in --recipient= argument: $recipient");
                        return $recipient;
                    }
                }
            }

            // Fallback: any argument with @
            foreach ($argv as $arg) {
                if (str_contains($arg, '@')) {
                    $recipient = $this->extractEmailAddress($arg);
                    if (!empty($recipient)) {
                        $logger->info("Recipient found in command line: $recipient");
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
                    $logger->info("Recipient found in $headerName header: $recipient");
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
            $message = "Invalid recipient email after extraction: $recipient";
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
                $error = "Unknown requeue method: $requeueMethod";
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
        $requeueCommand = "$sendmailPath -i -- $recipient";
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
            throw new RuntimeException("Failed to connect to SMTP server: $errstr ($errno)");
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
            fwrite($socket, "RCPT TO:<$recipient>\r\n");
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
            
            $command = "postdrop < $tempFile";
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
        $tempFile = "/tmp/$queueId";
        $finalFile = "$pickupDir/$queueId";
        
        try {
            if (file_put_contents($tempFile, $emailData) === false) {
                throw new RuntimeException("Failed to write temporary file");
            }
            
            $moveCmd = "sudo mv $tempFile $finalFile";
            exec($moveCmd, $output, $returnCode);
            
            if ($returnCode !== 0) {
                throw new RuntimeException("Move failed with return code: $returnCode");
            }
            
            exec("sudo chown postfix:postdrop $finalFile");
            exec("sudo chmod 644 $finalFile");
            
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


        // Add spam headers if configured
        if ($config['postfix']['spam_handling']['add_spam_headers'] ?? true) {
            $emailData = $this->addSpamHeaders($emailData, $spamReason, $logger);
        }

        // Add footer to spam email if configured
        $emailData = $this->addFooterIfConfigured($emailData, true);


        // Check spam handling method FIRST
        $spamHandlingMethod = $config['postfix']['spam_handling_method'] ?? 'maildir';

        // Check if recipient is an alias
        $aliasTargets = $this->getAliasTargets($recipient, $logger);

        if (!empty($aliasTargets)) {
            $logger->info("Recipient $recipient is an alias for " . count($aliasTargets) . " targets");

            // Process spam for each target of the alias
            foreach ($aliasTargets as $target) {
                $logger->info("Processing spam for alias target: $target");

                // Check spam handling method for this alias target
                $spamHandlingMethod = $config['postfix']['spam_handling_method'] ?? 'maildir';

                if ($spamHandlingMethod === 'maildir') {
                    $logger->info("Using maildir spam handling for alias target: $target");
                    $this->deliverSpamToMaildir($emailData, $target, $logger);
                } else {
                    // Handle other spam actions for this alias target
                    $this->processSpamWithDefaultActions($emailData, $headers, $target, $spamReason, $logger);
                }
            }
            // Email has been handled for all alias targets
            exit(0);
        }


            if ($spamHandlingMethod === 'maildir') {
            $logger->info("Using maildir / cron spam handling method");
            $this->deliverSpamToMaildir($emailData, $recipient, $logger);
            return;
        }

        $spamAction = $config['postfix']['spam_handling']['action'] ?? 'reject';
        $logger->info("Spam Action: $spamAction");
        
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
                $maildirPath = "$userMaildir/.$defaultSpamFolder";
                
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
        $backupFile = "$backupDir/" . basename($filePath) . ".backup_$timestamp";

        // Ensure backup directory exists and is writable
        if (!is_dir($backupDir)) {
            if (!mkdir($backupDir, 0755, true) && !is_dir($backupDir)) {
                // Try /tmp as fallback
                $backupDir = '/tmp';
                $backupFile = "$backupDir/" . basename($filePath) . ".backup_$timestamp";
            }
        }

        // Check if directory is writable
        if (!is_writable($backupDir)) {
            echo "WARNING: Cannot write to $backupDir, using /tmp for backup\n";
            $backupDir = '/tmp';
            $backupFile = "$backupDir/" . basename($filePath) . ".backup_$timestamp";
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
        
        $command = "/usr/sbin/sendmail -t < $tempFile";
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
        
        $quarantineFolder = "/home/$realUser/Maildir/.SystemErrors";
        
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
        
        $command = "$ldaPath -d $username -f ''";
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


    public function checkAllThreats(array $headers, string $body): bool
    {
        $isThreat = false;
        $this->lastThreatResults = [];

        // Initialize threat detectors if needed
        if (empty($this->threatDetectors)) {
            $this->logger->info("Initializing threat detectors...");
            $this->initializeThreatDetectors();
            $this->logger->info("Initialized " . count($this->threatDetectors) . " threat detectors");
        }

        // Log that we're starting threat detection
        $this->logger->info("Starting dynamic threat detection process");

        // Run all threat detectors
        foreach ($this->threatDetectors as $category => $detector) {
            $this->logger->info("Running $category threat detector...");
            $result = $detector->analyze($headers, $body);
            $this->lastThreatResults[$category] = $result;

            $this->logger->info("$category detection result: " . ($result['is_threat'] ? "THREAT DETECTED" : "Clean"), [
                'matches' => $result['matches'] ?? [],
                'score' => $result['score'] ?? 0
            ]);

            if ($result['is_threat']) {
                $isThreat = true;
            }
        }


        return $isThreat;
    }

    /**
     * Initialize threat detectors
     */
    private function initializeThreatDetectors(): void
    {
        $this->threatDetectors = [
            'spam' => new Spam($this->config),
            'phishing' => new Phishing($this->config)
        ];

        // Optional threat detectors - only add if configured
        if ($this->config['postfix']['threat_detection']['malware_detection'] ?? false) {
            $this->threatDetectors['malware'] = new Malware($this->config);
        }

        if ($this->config['postfix']['threat_detection']['virus_detection'] ?? false) {
            $this->threatDetectors['virus'] = new Virus($this->config);
        }
    }

    /**
     * Get reasons for the last threat detection
     *
     * @return string Formatted string of threat reasons
     */
    public function getLastThreatReasons(): string
    {
        $reasons = [];

        foreach ($this->lastThreatResults as $category => $result) {
            if ($result['is_threat']) {
                $categoryReasons = [];
                foreach ($result['matches'] as $match) {
                    $categoryReasons[] = $match['algorithm'] . " (score: {$match['score']})";
                }

                if (!empty($categoryReasons)) {
                    $reasons[] = ucfirst($category) . ": " . implode(', ', $categoryReasons);
                }
            }
        }

        return implode('; ', $reasons);
    }

    /**
     * Get complete threat results for the last check
     *
     * @return array Complete threat results by category
     */
    public function getLastThreatResults(): array
    {
        return $this->lastThreatResults;
    }




    /**
     * Extract the sender IP from email headers
     *
     * @param array $headers Parsed email headers
     * @param string $rawHeaderText Optional raw header text for backup extraction
     * @return string|null The sender IP or null if not found
     */
    private function extractSenderIp(array $headers, string $rawHeaderText = ''): ?string
    {
        // Pattern to extract IP addresses
        $ipPattern = '/\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/';

        // Try Received headers first - they usually contain the original IP
        if (isset($headers['Received'])) {
            $receivedValue = $headers['Received'];

            // If there are multiple received headers, they might be concatenated
            $receivedHeaders = explode('Received:', $receivedValue);

            foreach ($receivedHeaders as $received) {
                if (preg_match($ipPattern, $received, $matches)) {
                    $ip = $matches[1];

                    // Skip private/local IPs
                    if (!$this->isPrivateIp($ip)) {
                        return $ip;
                    }
                }
            }
        }

        // Try X-Originating-IP header
        if (isset($headers['X-Originating-IP']) &&
            preg_match($ipPattern, $headers['X-Originating-IP'], $matches)) {
            return $matches[1];
        }

        // Try X-Sender-IP header
        if (isset($headers['X-Sender-IP'])) {
            return $headers['X-Sender-IP'];
        }

        // Last attempt - try to find IPs in Authentication-Results
        if (isset($headers['Authentication-Results']) &&
            preg_match('/client-ip=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/',
                $headers['Authentication-Results'], $matches)) {
            return $matches[1];
        }

        // If all else fails and we have raw headers, scan them directly
        if (!empty($rawHeaderText)) {
            if (preg_match_all($ipPattern, $rawHeaderText, $matches)) {
                foreach ($matches[1] as $ip) {
                    if (!$this->isPrivateIp($ip)) {
                        return $ip;
                    }
                }
            }
        }

        // No valid IP found
        return null;
    }

    /**
     * Check if an IP is a private/local address
     *
     * @param string $ip The IP address to check
     * @return bool True if the IP is private/local
     */
    private function isPrivateIp(string $ip): bool
    {
        // Check for localhost
        if ($ip === '127.0.0.1' || $ip === '::1') {
            return true;
        }

        // Convert IP to long integer
        $long = ip2long($ip);
        if ($long === false) {
            return false;
        }

        // Check private IP ranges
        return (
            ($long >= ip2long('10.0.0.0') && $long <= ip2long('10.255.255.255')) ||
            ($long >= ip2long('172.16.0.0') && $long <= ip2long('172.31.255.255')) ||
            ($long >= ip2long('192.168.0.0') && $long <= ip2long('192.168.255.255'))
        );
    }
    /**
     * Check if email is whitelisted based on sender email, domain, or IP
     *
     * @param array $headers Email headers
     * @param string $emailData Raw email data
     * @param string|null $senderIp Sender IP address
     * @param Logger $logger Logger instance
     * @return bool True if whitelisted, false otherwise
     */
    public function isWhitelisted(array $headers, string $emailData, ?string $senderIp, Logger $logger): bool
    {
        $logger->info("Checking whitelist status for email...");

        // Get sender email from headers
        $senderEmail = $headers['From'] ?? '';
        if (preg_match('/<([^>]+)>/', $senderEmail, $matches)) {
            $senderEmail = $matches[1];
        }
        $senderEmail = trim($senderEmail);

        if (empty($senderEmail)) {
            $logger->warning("Could not extract sender email for whitelist check");
            return false;
        }

        // Extract domain from sender email
        $senderDomain = '';
        if (strpos($senderEmail, '@') !== false) {
            [, $senderDomain] = explode('@', $senderEmail, 2);
        }

        // Check whitelist files
        $whitelistFiles = [
            'emails' => $this->config['whitelist']['emails_file'] ?? '/usr/local/share/cyford/security/lists/whitelist_emails.txt',
            'domains' => $this->config['whitelist']['domains_file'] ?? '/usr/local/share/cyford/security/lists/whitelist_domains.txt',
            'ips' => $this->config['whitelist']['ips_file'] ?? '/usr/local/share/cyford/security/lists/whitelist_ips.txt',
        ];

        // Check the email allowlist
        if (!empty($senderEmail) && file_exists($whitelistFiles['emails'])) {
            $emailWhitelist = array_map('trim', file($whitelistFiles['emails'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
            foreach ($emailWhitelist as $whiteEmail) {
                // Skip comments
                if (strpos($whiteEmail, '#') === 0) {
                    continue;
                }

                if (strtolower($senderEmail) === strtolower($whiteEmail)) {
                    $logger->info("Email whitelisted: $senderEmail matches whitelist entry");
                    return true;
                }
            }
        }

        // Check the domain allowlist
        if (!empty($senderDomain) && file_exists($whitelistFiles['domains'])) {
            $domainWhitelist = array_map('trim', file($whitelistFiles['domains'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
            foreach ($domainWhitelist as $whiteDomain) {
                // Skip comments
                if (strpos($whiteDomain, '#') === 0) {
                    continue;
                }

                // Exact domain match
                if (strtolower($senderDomain) === strtolower($whiteDomain)) {
                    $logger->info("Domain whitelisted: $senderDomain matches whitelist entry");
                    return true;
                }

                // Subdomain wildcard match (*.example.com)
                if (substr($whiteDomain, 0, 2) === '*.' &&
                    substr_compare(strtolower($senderDomain), strtolower(substr($whiteDomain, 1)), -strlen(substr($whiteDomain, 1))) === 0) {
                    $logger->info("Domain whitelisted: $senderDomain matches wildcard entry $whiteDomain");
                    return true;
                }
            }
        }

        // Check IP whitelist
        if (!empty($senderIp) && file_exists($whitelistFiles['ips'])) {
            $ipWhitelist = array_map('trim', file($whitelistFiles['ips'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
            foreach ($ipWhitelist as $whiteIp) {
                // Skip comments
                if (strpos($whiteIp, '#') === 0) {
                    continue;
                }

                // Exact IP match
                if ($senderIp === $whiteIp) {
                    $logger->info("IP whitelisted: $senderIp matches whitelist entry");
                    return true;
                }

                // CIDR notation match (192.168.1.0/24)
                if (strpos($whiteIp, '/') !== false) {
                    if ($this->isIpInCidrRange($senderIp, $whiteIp)) {
                        $logger->info("IP whitelisted: $senderIp is in CIDR range $whiteIp");
                        return true;
                    }
                }
            }
        }

        $logger->info("Email not whitelisted");
        return false;
    }

    /**
     * Check if an IP address is within a CIDR range
     *
     * @param string $ip IP address to check
     * @param string $cidr CIDR range (e.g., 192.168.1.0/24)
     * @return bool True if IP is in range, false otherwise
     */
    private function isIpInCidrRange(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr);
        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - (int)$bits);
        $subnet &= $mask;

        return ($ip & $mask) === $subnet;
    }

    /**
     * Process a whitelisted email by passing it through to the original recipient
     *
     * @param string $emailData Raw email data
     * @param array $headers Email headers
     * @param string $recipient Email recipient
     * @param Logger $logger Logger instance
     */


    /**
     * Add whitelist check to the main email processing flow
     *
     * Update your processEmailInternal method to include this right after parsing headers and before spam checks
     */

    /**
     * Check if email is blacklisted based on sender email, domain, or IP
     *
     * @param array $headers Email headers
     * @param string $emailData Raw email data
     * @param string|null $senderIp Sender IP address
     * @param Logger $logger Logger instance
     * @return bool True if blacklisted, false otherwise
     */
    public function isBlacklisted(array $headers, string $emailData, ?string $senderIp, Logger $logger): bool
    {
        $logger->info("Checking blacklist status for email...");

        // Get sender email from headers
        $senderEmail = $headers['From'] ?? '';
        if (preg_match('/<([^>]+)>/', $senderEmail, $matches)) {
            $senderEmail = $matches[1];
        }
        $senderEmail = trim($senderEmail);

        if (empty($senderEmail)) {
            $logger->warning("Could not extract sender email for blacklist check");
            return false;
        }

        // Extract domain from sender email
        $senderDomain = '';
        if (strpos($senderEmail, '@') !== false) {
            [, $senderDomain] = explode('@', $senderEmail, 2);
        }

        // Check blacklist files
        $blacklistFiles = [
            'emails' => $this->config['blacklist']['emails_file'] ?? '/usr/local/share/cyford/security/lists/blacklist_emails.txt',
            'domains' => $this->config['blacklist']['domains_file'] ?? '/usr/local/share/cyford/security/lists/blacklist_domains.txt',
            'ips' => $this->config['blacklist']['ips_file'] ?? '/usr/local/share/cyford/security/lists/blacklist_ips.txt',
        ];

        // Check email blacklist
        if (!empty($senderEmail) && file_exists($blacklistFiles['emails'])) {
            $emailBlacklist = array_map('trim', file($blacklistFiles['emails'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
            foreach ($emailBlacklist as $blackEmail) {
                // Skip comments
                if (strpos($blackEmail, '#') === 0) {
                    continue;
                }

                if (strtolower($senderEmail) === strtolower($blackEmail)) {
                    $logger->info("Email blacklisted: $senderEmail matches blacklist entry");
                    return true;
                }
            }
        }

        // Check domain blacklist
        if (!empty($senderDomain) && file_exists($blacklistFiles['domains'])) {
            $domainBlacklist = array_map('trim', file($blacklistFiles['domains'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
            foreach ($domainBlacklist as $blackDomain) {
                // Skip comments
                if (strpos($blackDomain, '#') === 0) {
                    continue;
                }

                // Exact domain match
                if (strtolower($senderDomain) === strtolower($blackDomain)) {
                    $logger->info("Domain blacklisted: $senderDomain matches blacklist entry");
                    return true;
                }

                // Subdomain wildcard match (*.example.com)
                if (substr($blackDomain, 0, 2) === '*.' &&
                    substr_compare(strtolower($senderDomain), strtolower(substr($blackDomain, 1)), -strlen(substr($blackDomain, 1))) === 0) {
                    $logger->info("Domain blacklisted: $senderDomain matches wildcard entry $blackDomain");
                    return true;
                }
            }
        }

        // Check IP blacklist
        if (!empty($senderIp) && file_exists($blacklistFiles['ips'])) {
            $ipBlacklist = array_map('trim', file($blacklistFiles['ips'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
            foreach ($ipBlacklist as $blackIp) {
                // Skip comments
                if (strpos($blackIp, '#') === 0) {
                    continue;
                }

                // Exact IP match
                if ($senderIp === $blackIp) {
                    $logger->info("IP blacklisted: $senderIp matches blacklist entry");
                    return true;
                }

                // CIDR notation match (192.168.1.0/24)
                if (strpos($blackIp, '/') !== false) {
                    if ($this->isIpInCidrRange($senderIp, $blackIp)) {
                        $logger->info("IP blacklisted: $senderIp is in CIDR range $blackIp");
                        return true;
                    }
                }
            }
        }

        $logger->info("Email not blacklisted");
        return false;
    }

    /**
     * Check if an email address is an alias and return all target recipients
     *
     * @param string $recipient Email address to check
     * @param mixed $logger Logger instance
     * @return array List of target recipients for this alias, empty if not an alias
     */
    private function getAliasTargets(string $recipient, $logger): array
    {
        $localPart = strstr($recipient, '@', true);
        $domain = substr(strstr($recipient, '@'), 1);

        $logger->info("Checking if $recipient is an alias");
        $logger->info("Local part: $localPart, Domain: $domain");

        // List of potential alias files to check
        $aliasFiles = [
            '/etc/postfix/virtual',
            '/etc/aliases'
        ];

        $allTargets = [];

        // Check /etc/aliases file (system aliases)
        if (file_exists('/etc/aliases')) {
            $logger->info("Checking alias file: /etc/aliases");

            // Use getent to query system aliases - safer than shell_exec
            exec("getent aliases $localPart 2>&1", $output, $returnCode);

            if ($returnCode === 0 && !empty($output)) {
                $getentOutput = implode("\n", $output);

                // Format is typically "alias: target1, target2"
                if (preg_match('/^[^:]+:\s*(.+)$/', $getentOutput, $matches)) {
                    $logger->info("Found system alias: $getentOutput");

                    // Parse the targets, which may be space-separated
                    $targetsStr = trim($matches[1]);
                    $targets = preg_split('/[\s,]+/', $targetsStr);
                    $targets = array_filter(array_map('trim', $targets));

                    if (!empty($targets)) {
                        $logger->info("Parsed alias targets: " . implode(', ', $targets));
                        $allTargets = array_merge($allTargets, $targets);
                    }
                }
            }
        }

        // Manual parsing of virtual file if needed
        if (file_exists('/etc/postfix/virtual')) {
            $logger->info("Checking alias file: /etc/postfix/virtual");
            $content = file_get_contents('/etc/postfix/virtual');

            // Skip comments and blank lines
            $lines = array_filter(array_map('trim', explode("\n", $content)), function($line) {
                return $line && $line[0] !== '#';
            });

            foreach ($lines as $line) {
                $parts = preg_split('/\s+/', $line, 2);
                if (count($parts) == 2) {
                    list($source, $target) = $parts;

                    // Check for exact match
                    if ($source === $recipient) {
                        $logger->info("Found exact match in virtual file: $source -> $target");
                        $targets = preg_split('/[\s,]+/', $target);
                        $targets = array_filter(array_map('trim', $targets));
                        $allTargets = array_merge($allTargets, $targets);
                    }

                    // Check for domain alias (@domain)
                    if ($source === "@$domain") {
                        $logger->info("Found domain alias in virtual file: $source -> $target");
                        $targets = preg_split('/[\s,]+/', $target);
                        $targets = array_filter(array_map('trim', $targets));
                        $allTargets = array_merge($allTargets, $targets);
                    }
                }
            }
        }

        // Ensure each target has a domain if needed
        foreach ($allTargets as &$target) {
            if (strpos($target, '@') === false) {
                $target .= '@' . $domain;
            }
        }

        // Remove duplicates and empty values
        $allTargets = array_unique(array_filter($allTargets));

        if (!empty($allTargets)) {
            $logger->info("Found alias targets for $recipient: " . implode(', ', $allTargets));
        } else {
            $logger->info("$recipient is not an alias");
        }

        return $allTargets;
    }}