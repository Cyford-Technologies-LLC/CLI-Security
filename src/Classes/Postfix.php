<?php
namespace Cyford\Security\Classes;

use RuntimeException;

class Postfix
{
    private string $mainConfigPath;
    private string $masterConfigPath;
    private string $postfixCommand;
    private string $backupDirectory;
    private bool $allowFileModification;
    private Systems $systems;

    public function __construct(array $config, ?Systems $systems = null)
    {
        $this->mainConfigPath = $config['postfix']['main_config'] ?? '/etc/postfix/main.cf';
        $this->masterConfigPath = $config['postfix']['master_config'] ?? '/etc/postfix/master.cf';
        $this->postfixCommand = $config['postfix']['postfix_command'] ?? '/usr/sbin/postfix';
        $this->backupDirectory = $config['postfix']['backup_directory'] ?? '/var/backups/postfix';
        $this->allowFileModification = $config['postfix']['allow_modification'] ?? false;
        $this->systems = $systems ?? new Systems();

        // Ensure Postfix command exists
        if (!file_exists($this->postfixCommand)) {
            throw new RuntimeException("Postfix command not found at: {$this->postfixCommand}. Check your configuration.");
        }

        // Ensure the backup directory exists
        if (!is_dir($this->backupDirectory)) {
            if (!mkdir($this->backupDirectory, 0755, true)) {
                // Fallback to /tmp if can't create in /var/backups
                $this->backupDirectory = '/tmp/postfix_backups';
                if (!is_dir($this->backupDirectory)) {
                    mkdir($this->backupDirectory, 0755, true);
                }
            }
        }
    }

    /**
     * Check if Postfix is configured for integration.
     */
    public function checkConfig(): bool
    {
        $masterConfig = file_exists($this->masterConfigPath) ? file_get_contents($this->masterConfigPath) : '';

        // Check for IP-based SMTP configuration
        $externalSmtpCheck = preg_match('/\d+\.\d+\.\d+\.\d+:smtp\s+inet.*content_filter=security-filter:dummy/', $masterConfig);
        $localhostSmtpCheck = strpos($masterConfig, '127.0.0.1:smtp inet') !== false;
        $securityFilterCheck = strpos($masterConfig, 'security-filter unix - n n - - pipe') !== false;

        if ($externalSmtpCheck && $localhostSmtpCheck && $securityFilterCheck) {
            echo "Cyford WEB ARMOR (for PostFix) INITIATED!.\n";
            return true;
        }

        echo "Missing Postfix configurations:\n";
        if (!$externalSmtpCheck) {
            echo " - External IP SMTP with content_filter is missing in {$this->masterConfigPath}.\n";
        }
        if (!$localhostSmtpCheck) {
            echo " - Localhost SMTP service is missing in {$this->masterConfigPath}.\n";
        }
        if (!$securityFilterCheck) {
            echo " - 'security-filter' service is missing in {$this->masterConfigPath}.\n";
        }

        return false;
    }

    /**
     * Automatically apply missing configurations if allowed.
     */
    public function autoConfig(): void
    {
        echo "INFO: Checking and configuring Postfix for IP-based filtering...\n";

        // Get server's public IP
        $publicIP = $this->systems->getPublicIP();
        if (!$publicIP) {
            echo "ERROR: Could not determine server's public IP address.\n";
            return;
        }
        echo "INFO: Detected public IP: {$publicIP}\n";

        // Remove old global content_filter from main.cf if it exists
        if (file_exists($this->mainConfigPath)) {
            $mainConfigContent = file_get_contents($this->mainConfigPath);
            if (strpos($mainConfigContent, 'content_filter = security-filter:dummy') !== false) {
                echo "INFO: Removing old global content_filter from {$this->mainConfigPath}...\n";
                $this->backupFile($this->mainConfigPath);
                $mainConfigContent = str_replace("content_filter = security-filter:dummy\n", "", $mainConfigContent);
                $mainConfigContent = str_replace("#content_filter = security-filter:dummy\n", "", $mainConfigContent);
                file_put_contents($this->mainConfigPath, $mainConfigContent);
                echo "SUCCESS: Old content_filter removed.\n";
            }
        }

        // Configure master.cf with IP-based filtering
        if (file_exists($this->masterConfigPath)) {
            $masterConfigContent = file_get_contents($this->masterConfigPath);
            echo "INFO: Configuring IP-based SMTP services in {$this->masterConfigPath}...\n";
            
            $this->backupFile($this->masterConfigPath);
            
            // Remove old entries and add new IP-based entries
            $masterConfigContent = $this->removeOldEntries($masterConfigContent);
            $newEntries = $this->generateIPBasedEntries($publicIP);
            $masterConfigContent .= "\n" . $newEntries;
            file_put_contents($this->masterConfigPath, $masterConfigContent);
            
            echo "SUCCESS: IP-based SMTP configuration applied.\n";
            echo "INFO: External SMTP ({$publicIP}:25) - WITH security filter\n";
            echo "INFO: Internal SMTP (127.0.0.1:25) - WITHOUT security filter\n";
        } else {
            echo "ERROR: {$this->masterConfigPath} does not exist.\n";
        }

        // Reload Postfix
        $this->reload();
    }

    /**
     * Process email from Postfix content filter
     */
    public function processEmail($spamFilter, $logger): void
    {
        $logger->info("Processing email received from Postfix...");
        
        // Skip configuration check during email processing
        // This prevents autoConfig from running during email processing

        // Read email data from stdin
        $emailData = file_get_contents('php://stdin');
        if (!$emailData) {
            throw new RuntimeException("No email data received from Postfix.");
        }
        $logger->info("Raw email data successfully read.");

        // Parse headers and body
        list($headers, $body) = $this->parseEmail($emailData);
        $logger->info("Parsed headers: " . json_encode($headers));

        // Skip system/security emails to prevent loops
        if ($this->shouldSkipEmail($headers, $logger)) {
            exit(0);
        }

        // Check if already processed
        if ($this->isAlreadyProcessed($headers, $emailData, $logger)) {
            return;
        }

        // Get recipient first
        $recipient = $this->extractEmailAddress($headers['To'] ?? '');
        if (empty($recipient)) {
            $logger->error("Recipient not found or invalid in email headers.");
            throw new RuntimeException("Recipient not found or invalid in email headers.");
        }
        $logger->info("Recipient resolved: {$recipient}");
        
        $subject = $headers['Subject'] ?? '';
        $isSpam = false;
        $spamReason = '';
        
        // Check hash-based detection first (if enabled)
        global $config;
        $database = null;
        $skipSpamFilter = false;
        
        if ($config['postfix']['spam_handling']['hash_detection'] ?? false) {
            $database = new \Cyford\Security\Classes\Database($config);
            
            // Check if this hash is known spam
            if ($database->isKnownSpamHash($subject, $body)) {
                $isSpam = true;
                $spamReason = 'Known spam pattern (hash match)';
                $skipSpamFilter = true;
                $logger->info("Email flagged as spam by hash detection.");
            }
            // Check if this hash is known clean
            elseif ($database->isKnownCleanHash($subject, $body)) {
                $isSpam = false;
                $spamReason = 'Known clean pattern (hash match)';
                $skipSpamFilter = true;
                $logger->info("Email marked as clean by hash detection - skipping spam filter.");
            }
        }
        
        // If not caught by hash, check with spam filter
        if (!$skipSpamFilter) {
            $isSpam = $spamFilter->isSpam($headers, $body);
            if ($isSpam) {
                $spamReason = $spamFilter->getLastSpamReason() ?? 'Spam filter detection';
            }
            
            // Record new hash pattern (spam or clean) for future reference
            if ($database) {
                $database->recordEmailHash($subject, $body, $isSpam);
                $logger->info("Email hash recorded as " . ($isSpam ? 'spam' : 'clean') . " for future detection");
            }
        }

        if ($isSpam) {
            $logger->warning("Email flagged as spam. Reason: {$spamReason}");
            
            // Log detailed spam information
            $this->logSpamEmail($emailData, $headers, $recipient, $spamReason, $logger);
            
            $this->handleSpamEmail($emailData, $headers, $recipient, $logger);
            return;
        }

        $logger->info("Email is clean of spam. Proceeding with requeue.");
        
        // Add footer if configured
        $emailData = $this->addFooterIfConfigured($emailData);
        
        $this->requeueEmail($emailData, $recipient, $logger);
    }

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
  flags=Rq user=report-ip argv=/usr/bin/php /usr/local/share/cyford/security/index.php --input_type=postfix --ips=\${{client_address}} --categories=3
EOF;
    }

    /**
     * Check if email should be skipped
     */
    private function shouldSkipEmail(array $headers, $logger): bool
    {
        $from = $headers['From'] ?? '';
        $subject = $headers['Subject'] ?? '';

        if (strpos($from, 'report-ip@') !== false ||
            strpos($subject, '*** SECURITY information') !== false ||
            strpos($headers['Auto-Submitted'] ?? '', 'auto-generated') !== false) {
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
        $hasSecurityHeaderInRaw = strpos($emailData, 'X-Processed-By-Security-Filter:') !== false;
        
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
     * Extract email address from header
     */
    private function extractEmailAddress(string $toHeader): string
    {
        if (preg_match('/<([^>]+)>/', $toHeader, $matches)) {
            return $matches[1];
        }

        if (filter_var($toHeader, FILTER_VALIDATE_EMAIL)) {
            return $toHeader;
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
            throw new \InvalidArgumentException($message);
        }

        // Add custom header to prevent reprocessing
        if (!preg_match('/^X-Processed-By-Security-Filter:/m', $emailData)) {
            $logger->info("Adding 'X-Processed-By-Security-Filter' header to prevent reprocessing.");
            $emailData = "X-Processed-By-Security-Filter: true\r\n" . $emailData;
        }

        $logger->info("Requeueing email using method: {$requeueMethod} for recipient: {$recipient}");

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
        $logger->info("Executing sendmail command: {$requeueCommand}");

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
                throw new RuntimeException("sendmail failed. Exit code: {$returnCode}. Errors: {$errors}");
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
        
        $logger->info("Connecting to SMTP server at {$smtpHost}:{$smtpPort}");
        
        $socket = fsockopen($smtpHost, $smtpPort, $errno, $errstr, 30);
        if (!$socket) {
            throw new RuntimeException("Failed to connect to SMTP server: {$errstr} ({$errno})");
        }
        
        try {
            // Read greeting
            $response = fgets($socket);
            if (substr($response, 0, 3) !== '220') {
                throw new RuntimeException("SMTP server error: {$response}");
            }
            
            // HELO
            fwrite($socket, "HELO localhost\r\n");
            $response = fgets($socket);
            if (substr($response, 0, 3) !== '250') {
                throw new RuntimeException("HELO failed: {$response}");
            }
            
            // MAIL FROM
            fwrite($socket, "MAIL FROM:<>\r\n");
            $response = fgets($socket);
            if (substr($response, 0, 3) !== '250') {
                throw new RuntimeException("MAIL FROM failed: {$response}");
            }
            
            // RCPT TO
            fwrite($socket, "RCPT TO:<{$recipient}>\r\n");
            $response = fgets($socket);
            if (substr($response, 0, 3) !== '250') {
                throw new RuntimeException("RCPT TO failed: {$response}");
            }
            
            // DATA
            fwrite($socket, "DATA\r\n");
            $response = fgets($socket);
            if (substr($response, 0, 3) !== '354') {
                throw new RuntimeException("DATA failed: {$response}");
            }
            
            // Send email data
            fwrite($socket, $emailData);
            if (substr($emailData, -2) !== "\r\n") {
                fwrite($socket, "\r\n");
            }
            fwrite($socket, ".\r\n");
            
            $response = fgets($socket);
            if (substr($response, 0, 3) !== '250') {
                throw new RuntimeException("Email delivery failed: {$response}");
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
                throw new RuntimeException("Postdrop failed: {$result}");
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
                throw new RuntimeException("Move failed with return code: {$returnCode}");
            }
            
            exec("sudo chown postfix:postdrop {$finalFile}");
            exec("sudo chmod 644 {$finalFile}");
            
            $logger->info("Email successfully queued via pickup directory: {$queueId}");
            
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    /**
     * Handle spam email according to configuration
     */
    private function handleSpamEmail(string $emailData, array $headers, string $recipient, $logger): void
    {
        global $config;
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
                
            default:
                $logger->warning("Unknown spam action: {$spamAction}. Rejecting email.");
                $this->bounceSpamEmail($headers, $logger);
        }
    }

    /**
     * Bounce spam email back to sender
     */
    private function bounceSpamEmail(array $headers, $logger): void
    {
        global $config;
        $bounceMessage = $config['postfix']['spam_handling']['bounce_message'] ?? 'Message rejected due to spam content.';
        $from = $headers['From'] ?? 'unknown';
        
        $logger->info("Bouncing spam email from: {$from}");
        
        // Create bounce message
        $bounceEmail = $this->createBounceMessage($headers, $bounceMessage);
        
        // Send bounce via sendmail
        $tempFile = tempnam('/tmp', 'bounce_');
        file_put_contents($tempFile, $bounceEmail);
        
        $command = "/usr/sbin/sendmail -t < {$tempFile}";
        shell_exec($command);
        
        unlink($tempFile);
        $logger->info("Bounce message sent to sender.");
    }

    /**
     * Quarantine spam email to specified folder
     */
    private function quarantineSpamEmail(string $emailData, string $recipient, $logger): void
    {
        global $config;
        $spamFolder = $config['postfix']['spam_handling']['quarantine_folder'] ?? 'Spam';
        
        $logger->info("Quarantining spam email to {$spamFolder} folder for {$recipient}");
        
        // Resolve alias to real user
        $realUser = $this->resolveEmailAlias($recipient, $logger);
        if (!$realUser) {
            $logger->error("Could not resolve recipient {$recipient} to a real user. Rejecting email.");
            $this->bounceSpamEmail([], $logger);
            return;
        }
        
        $logger->info("Resolved {$recipient} to real user: {$realUser}");
        
        // Get user's home directory and maildir path
        $maildirPath = "/home/{$realUser}/Maildir/.{$spamFolder}";
        
        // Create spam folder if it doesn't exist
        if (!is_dir($maildirPath)) {
            mkdir($maildirPath, 0755, true);
            mkdir($maildirPath . '/cur', 0755, true);
            mkdir($maildirPath . '/new', 0755, true);
            mkdir($maildirPath . '/tmp', 0755, true);
            $logger->info("Created spam folder: {$maildirPath}");
        }
        
        // Save email to spam folder
        $filename = time() . '.' . uniqid() . '.spam';
        $spamFile = $maildirPath . '/new/' . $filename;
        
        if (file_put_contents($spamFile, $emailData)) {
            $logger->info("Spam email quarantined to: {$spamFile}");
        } else {
            $logger->error("Failed to quarantine spam email. Rejecting instead.");
            $this->bounceSpamEmail([], $logger);
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
            $logger->info("Found cached alias mapping: {$email} -> {$realUser}");
            return $realUser;
        }
        
        $logger->warning("Could not resolve alias {$email} to a real user");
        return null;
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
            $footerText = '\n\n--- WARNING: This email was flagged as spam but allowed through ---';
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
            mkdir($logDir, 0755, true);
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
            $logger->error("Failed to write to spam log file: {$spamLogFile}");
        } else {
            $logger->info("Spam email logged to: {$spamLogFile}");
        }
    }

    /**
     * Create bounce message
     */
    private function createBounceMessage(array $headers, string $bounceMessage): string
    {
        $from = $headers['From'] ?? 'unknown';
        $subject = $headers['Subject'] ?? 'No Subject';
        $messageId = $headers['Message-ID'] ?? uniqid();
        
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
            if (!mkdir($backupDir, 0755, true)) {
                // Try /tmp as fallback
                $backupDir = '/tmp';
                $backupFile = "{$backupDir}/" . basename($filePath) . ".backup_{$timestamp}";
            }
        }

        // Check if directory is writable
        if (!is_writable($backupDir)) {
            echo "WARNING: Cannot write to {$backupDir}, using /tmp for backup\n";
            $backupDir = '/tmp';
            $backupFile = "{$backupDir}/" . basename($filePath) . ".backup_{$timestamp}";
        }

        // Create the backup
        if (!copy($filePath, $backupFile)) {
            echo "WARNING: Failed to create backup for: {$filePath}. Continuing without backup.\n";
            return;
        }

        echo "Backup created: {$backupFile}\n";
    }

    /**
     * Reload Postfix service.
     */
    public function reload(): void
    {
        echo "Reloading Postfix configuration...\n";

        $output = shell_exec("sudo {$this->postfixCommand} reload 2>&1");

        if (empty($output)) {
            throw new RuntimeException("Failed to reload Postfix. Ensure the Postfix service is running.");
        }

        echo "Postfix reload output: {$output}\n";
    }

    /**
     * Parse headers from raw header string
     */
    function parseHeaders($rawHeaders)
    {
        $headers = [];
        $lines = explode("\n", $rawHeaders);
        foreach ($lines as $line) {
            if (strpos($line, ':') !== false) {
                list($key, $value) = explode(':', $line, 2);
                $headers[trim($key)] = trim($value);
            }
        }
        return $headers;
    }

    /**
     * Get Postfix service status.
     */
    public function getStatus(): string
    {
        $command = "systemctl status postfix";
        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException('Failed to retrieve Postfix status.');
        }

        return $output;
    }
}