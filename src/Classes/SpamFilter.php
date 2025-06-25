<?php
namespace Cyford\Security\Classes;

class SpamFilter
{
    private string $spamLogFile;

    public function __construct(array $config)
    {
        // Spam log file location
        $this->spamLogFile = $config['errors']['error_log_location'] ?? __DIR__ . '/logs/spam.log';
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

        // 4. Log any detected spam and return status
        if (!empty($spamReasons)) {
            $this->logSpam("Spam detected - Reasons: " . implode(', ', $spamReasons));
            return true;
        }

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
            '/[a-z]{2,}\.[a-z]{2,}\.(com|net|org)/i',        // Suspicious domains in plain text
            '/https?:\/\/[^\s]+/i',                          // Links embedded in the email body
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
}
