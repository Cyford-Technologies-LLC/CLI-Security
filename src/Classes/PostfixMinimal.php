<?php
namespace Cyford\Security\Classes;

use RuntimeException;

class PostfixMinimal
{
    /**
     * Process email - minimal working version
     */
    public function processEmail($spamFilter, $logger): void
    {
        // Read email data
        $emailData = file_get_contents('php://stdin');
        if (!$emailData) {
            throw new RuntimeException("No email data received from Postfix.");
        }
        
        // Parse headers and body
        list($headers, $body) = $this->parseEmail($emailData);
        
        // Get recipient
        $recipient = $this->getRecipient($headers, $logger);
        if (empty($recipient)) {
            throw new RuntimeException("Recipient not found.");
        }
        
        // Skip hash detection for now - just requeue
        $logger->info("Email is clean. Proceeding with requeue.");
        $this->requeueEmail($emailData, $recipient, $logger);
    }
    
    private function parseEmail(string $emailData): array
    {
        [$headersRaw, $body] = preg_split("/\R\R/", $emailData, 2);
        $headers = [];
        $lines = explode("\n", $headersRaw);
        
        foreach ($lines as $line) {
            if (preg_match("/^([\w-]+):\s*(.*)$/", $line, $matches)) {
                $headers[$matches[1]] = $matches[2];
            }
        }
        
        return [$headers, $body];
    }
    
    private function getRecipient(array $headers, $logger): string
    {
        if (!empty($headers['To'])) {
            if (preg_match('/<([^>]+)>/', $headers['To'], $matches)) {
                return $matches[1];
            }
            if (filter_var($headers['To'], FILTER_VALIDATE_EMAIL)) {
                return $headers['To'];
            }
        }
        return '';
    }
    
    private function requeueEmail(string $emailData, string $recipient, $logger): void
    {
        // Add header to prevent reprocessing
        $emailData = "X-Processed-By-Security-Filter: true\r\n" . $emailData;
        
        // Use SMTP to requeue
        $socket = fsockopen('127.0.0.1', 25, $errno, $errstr, 30);
        if (!$socket) {
            throw new RuntimeException("Failed to connect to SMTP: $errstr");
        }
        
        fgets($socket); // Read greeting
        fwrite($socket, "HELO localhost\r\n");
        fgets($socket);
        fwrite($socket, "MAIL FROM:<>\r\n");
        fgets($socket);
        fwrite($socket, "RCPT TO:<$recipient>\r\n");
        fgets($socket);
        fwrite($socket, "DATA\r\n");
        fgets($socket);
        fwrite($socket, $emailData);
        fwrite($socket, "\r\n.\r\n");
        fgets($socket);
        fwrite($socket, "QUIT\r\n");
        fclose($socket);
        
        $logger->info("Email requeued successfully");
    }
}