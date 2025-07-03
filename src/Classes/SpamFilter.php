<?php
namespace Cyford\Security\Classes;

class SpamFilter
{
    private string $spamLogFile;
    private string $lastSpamReason = '';
    private array $config;

    public function __construct(array $config)
    {
        // Use proper spam log file location
        $this->spamLogFile = $config['postfix']['spam_handling']['spam_log_file'] ?? '/var/log/cyford-security/spam.log';
        $this->config = $config;
    }

    /**
     * Analyze an email and determine if it's spam.
     *
     * @param array $headers Key-value headers from the email (e.g., From, Subject).
     * @param string $body The email body content.
     * @return bool True if the email is spam.
     */
    public function isSpam(array $headers, string $body): bool
    {
        $spamReasons = [];

        // 1. Check if Subject is suspicious
        if (isset($headers['Subject']) && $this->detectSuspiciousSubject($headers['Subject'])) {
            $spamReasons[] = 'Suspicious subject detected.';
        }

        // 2. Check the body content for spammy patterns
        if ($this->detectSpamContent($body)) {
            $spamReasons[] = 'Spam patterns detected in the body.';
        }

        // 3. (Optional) Detect links with suspicious domains
        if ($this->containsSuspiciousLinks($body)) {
            $spamReasons[] = 'Suspicious links detected in email body.';
        }

        // 4. Phishing detection
        if ($this->isPhishingEnabled()) {
            $phishingReasons = $this->detectPhishing($headers, $body);
            $spamReasons = array_merge($spamReasons, $phishingReasons);
        }

        // 5. Log any detected spam and return status
        if (!empty($spamReasons)) {
            $this->lastSpamReason = implode(', ', $spamReasons);
            $this->logSpam("Spam detected - Reasons: " . $this->lastSpamReason);
            return true;
        }

        $this->lastSpamReason = '';
        return false;
    }

    /**
     * Detect suspicious subjects (e.g., generic words like "Hello").
     *
     * @param string $subject Email subject text.
     * @return bool True if the subject is suspicious.
     */
    private function detectSuspiciousSubject(string $subject): bool
    {
        // Example: flag generic or overly simple subjects
        $suspiciousSubjects = ['hello', 'hi', 'urgent', 'important'];
        return in_array(strtolower(trim($subject)), $suspiciousSubjects, true);
    }

    /**
     * Run content-based filtering using regex.
     *
     * @param string $body Email body content.
     * @return bool True if the body contains spam patterns.
     */
    private function detectSpamContent(string $body): bool
    {
        // Check for nonsensical or spammy patterns
        $patterns = [
            '/(\bno inquiryso resolve\b)/i',                  // Specific example from provided emails
            '/\b(amounted old strictly|timed blind)\b/i',    // Patterns of repeated phrases
            // Removed overly broad URL and domain patterns that catch legitimate emails
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $body)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the body contains links with suspicious domains.
     *
     * @param string $body
     * @return bool
     */
    private function containsSuspiciousLinks(string $body): bool
    {
        $suspiciousDomains = ['ebikrat.run', 'spammydomain.com', 'unknownserver.net'];

        if (preg_match_all('/https?:\/\/(www\.)?([^\s\/]+)/i', $body, $matches)) {
            foreach ($matches[2] as $domain) {
                foreach ($suspiciousDomains as $suspiciousDomain) {
                    if (stripos($domain, $suspiciousDomain) !== false) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Get the reason why the last email was flagged as spam
     */
    public function getLastSpamReason(): string
    {
        return $this->lastSpamReason;
    }

    /**
     * Log spam detection activity.
     *
     * @param string $message Message to log.
     * @return void
     */
    private function logSpam(string $message): void
    {
        $timestamp = date('Y-m-d H:i:s');
        file_put_contents($this->spamLogFile, "[{$timestamp}] {$message}" . PHP_EOL, FILE_APPEND);
    }

    /**
     * Check if phishing detection is enabled
     */
    private function isPhishingEnabled(): bool
    {
        return $this->config['postfix']['spam_handling']['phishing_detection']['enabled'] ?? false;
    }

    /**
     * Detect phishing attempts
     */
    private function detectPhishing(array $headers, string $body): array
    {
        $reasons = [];
        $phishingConfig = $this->config['postfix']['spam_handling']['phishing_detection'] ?? [];

        // Check sender mismatch
        if ($phishingConfig['check_sender_mismatch'] ?? false) {
            if ($this->checkSenderMismatch($headers)) {
                $reasons[] = 'Sender display name does not match email domain';
            }
        }

        // Check suspicious URLs
        if ($phishingConfig['check_suspicious_urls'] ?? false) {
            if ($this->checkSuspiciousUrls($body, $phishingConfig)) {
                $reasons[] = 'Contains suspicious or malicious URLs';
            }
        }

        // Check phishing keywords
        if ($phishingConfig['check_phishing_keywords'] ?? false) {
            if ($this->checkPhishingKeywords($body, $phishingConfig)) {
                $reasons[] = 'Contains common phishing keywords';
            }
        }

        return $reasons;
    }

    /**
     * Check if sender display name doesn't match email domain
     */
    private function checkSenderMismatch(array $headers): bool
    {
        $from = $headers['From'] ?? '';
        
        // Extract display name and email
        if (preg_match('/"([^"]+)"\s*<([^>]+)>/', $from, $matches)) {
            $displayName = strtolower($matches[1]);
            $email = $matches[2];
            $domain = explode('@', $email)[1] ?? '';
            
            // Check if display name mentions a different company
            $trustedDomains = $this->config['postfix']['spam_handling']['phishing_detection']['trusted_domains'] ?? [];
            foreach ($trustedDomains as $trustedDomain) {
                if (strpos($displayName, strtolower(str_replace('.com', '', $trustedDomain))) !== false && 
                    strpos($domain, $trustedDomain) === false) {
                    return true; // Display name mentions trusted company but email is from different domain
                }
            }
        }
        
        return false;
    }

    /**
     * Check for suspicious URLs
     */
    private function checkSuspiciousUrls(string $body, array $config): bool
    {
        $suspiciousDomains = $config['suspicious_domains'] ?? [];
        
        if (preg_match_all('/https?:\/\/([^\s\/]+)/i', $body, $matches)) {
            foreach ($matches[1] as $domain) {
                foreach ($suspiciousDomains as $suspiciousDomain) {
                    if (strpos($domain, $suspiciousDomain) !== false) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }

    /**
     * Check for phishing keywords
     */
    private function checkPhishingKeywords(string $body, array $config): bool
    {
        $keywords = $config['suspicious_keywords'] ?? [];
        $bodyLower = strtolower($body);
        
        foreach ($keywords as $keyword) {
            if (strpos($bodyLower, strtolower($keyword)) !== false) {
                return true;
            }
        }
        
        return false;
    }
}
