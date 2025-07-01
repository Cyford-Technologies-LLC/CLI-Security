<?php
// Add this function to your Postfix class

private function handleSpamEmail($emailContent, $recipient) {
    $config = $this->config['postfix']['spam_handling'];
    
    if ($config['quarantine_method'] === 'maildir_spam') {
        // Extract username from recipient email
        $username = strstr($recipient, '@', true);
        
        $maildirPath = str_replace('{user}', $username, $config['maildir_path']);
        $spamDir = $maildirPath . '/' . $config['spam_folder'];

        // Create spam folder structure if it doesn't exist
        if (!is_dir($spamDir)) {
            mkdir($spamDir . '/cur', 0755, true);
            mkdir($spamDir . '/new', 0755, true);
            mkdir($spamDir . '/tmp', 0755, true);
        }

        // Generate unique filename
        $filename = time() . '.' . getmypid() . '.spam';
        
        // Write email directly to spam folder
        if (file_put_contents($spamDir . '/new/' . $filename, $emailContent)) {
            $this->logMessage("Spam email quarantined to: {$spamDir}/new/{$filename}");
            exit(0); // Success - email handled
        } else {
            $this->logMessage("Failed to write spam email to maildir");
        }
    }
    
    // Fall back to requeue method if maildir fails
    return false;
}

// Usage in your spam detection:
if ($isSpam) {
    if ($this->handleSpamEmail($emailContent, $recipient)) {
        // Email was successfully quarantined
        exit(0);
    }
    // Continue with existing requeue logic
}