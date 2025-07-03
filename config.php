<?php

// Load environment variables
if (file_exists(__DIR__ . '/.env')) {
    $lines = file(__DIR__ . '/.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0 || strpos($line, '=') === false) continue;
        list($key, $value) = explode('=', $line, 2);
        $_ENV[trim($key)] = trim($value);
    }
}

// Helper function to get env variables
if (!function_exists('env')) {
    function env($key, $default = null) {
        return $_ENV[$key] ?? $default;
    }
}

// Configuration for API endpoints, authentication, etc.
return [
    'api' => [
        'login_endpoint' => 'https://api.cyfordtechnologies.com/api/auth/v1/login', // Login URL
        'report_endpoint' => 'https://api.cyfordtechnologies.com/api/security/v1/report-ip', // Report URL
        'analyze_spam_endpoint' => 'https://api.cyfordtechnologies.com/api/security/v1/analyze-spam', // Spam analysis URL
        'check_spam_against_server' => true, // Enable server-side spam checking
        'report_spam_to_server' => false, // Enable spam reporting to server
        'spam_threshold' => 70, // Spam detection threshold (30-90)
        'credentials' => [
            'email' => env('API_EMAIL', ''),  // Account email for API login
            'password' => env('API_PASSWORD', ''),  // Account password for API login
        ],
    ],
    'postfix' => [
        'enable_postfix_integration' => true, // Enable postfix integration
        'requeue_method' => 'smtp', // Options: smtp, sendmail, postdrop, postpickup, dovecot-lda (SMTP recommended for chroot compatibility)
        'spam_handling_method' => 'maildir', // Options: maildir, requeue (maildir uses task queue for chroot)
        'main_config' => '/etc/postfix/main.cf', // Path to Postfix main configuration file
        'master_config' => '/etc/postfix/master.cf', // Path to Postfix master configuration file
        'postfix_command' => '/usr/sbin/postfix', // Path to Postfix executable
        'allow_modification' => true, // Set to true to allow automatic configuration changes
        'backup_directory' => '/var/backups/postfix', // Path to store configuration file backups
        'spam_handling' => [
            'action' => 'quarantine', // Options: 'reject', 'quarantine', 'allow', 'headers'
            'bounce_message' => 'Your message has been rejected due to spam content by Cyford Web Armor. Please contact the administrator if you believe this is an error.',
            'quarantine_folder' => 'Spambox', // Folder name to create for spam emails
            'quarantine_method' => 'user_maildir', // Options: 'user_maildir', 'system_quarantine'
            'maildir_path' => '/home/{user}/Maildir-cyford', // Path to user maildir ({user} will be replaced)
            'system_quarantine_path' => '/var/spool/postfix/quarantine', // System quarantine path (chroot accessible)
            'add_footer' => true, // Add spam filter footer to clean emails
            'footer_text' => '--- This email has been scanned by Cyford Web Armor ---',
            'add_spam_headers' => true, // Add X-Spam headers to quarantined spam emails
            'spam_log_file' => '/var/log/cyford-security/spam.log', // Detailed spam log with raw emails
            'hash_detection' => true, // Enable hash-based duplicate spam detection
            'hash_threshold' => 3, // Block after X identical emails
            'threshold' => 70, // Postfix spam detection threshold (30-90)
        ],
        'error_handling' => [
            'on_system_error' => 'pass', // Options: 'pass', 'fail', 'quarantine'
            'error_log_file' => '/var/log/cyford-security/system-errors.log',
            'max_retries' => 3, // Number of retries before giving up
            'retry_delay' => 1, // Seconds to wait between retries
            'fail_safe_mode' => true, // If true, always pass emails when in doubt
        ],
    ],
    'imap' => [
        'enabled' => true,
        'server' => 'dovecot',
        'host' => 'localhost',
        'port' => 143,
        'ssl_port' => 993,
        'auth_method' => 'plain',
        'maildir_path' => '/home/{user}/Maildir-cyford',
        'allow_modification' => true,
        'auto_configure' => true
    ],
    'database' => [
        'type' => 'sqlite', // Portable database, no installation required
        'path' => '/var/spool/postfix/cyford-security.db', // SQLite database file (persistent and chroot accessible)
        'cache_ttl' => 300, // Cache time-to-live in seconds (5 minutes)
    ],
    'task_queue' => [
        'queue_file' => '/var/spool/postfix/cyford-tasks.json', // Task queue file (chroot accessible)
        'backup_queue_file' => '/var/spool/cyford-security/tasks.json', // Legacy location
    ],
    'log' => [
        'file_path' => '/var/log/cyford-security/application.log',
    ],
    'whitelist' => [
        'ips_file' => '/usr/local/share/cyford/security/lists/whitelist_ips.txt',
        'domains_file' => '/usr/local/share/cyford/security/lists/whitelist_domains.txt',
        'emails_file' => '/usr/local/share/cyford/security/lists/whitelist_emails.txt',
    ],
    'blacklist' => [
        'ips_file' => '/usr/local/share/cyford/security/lists/blacklist_ips.txt',
        'domains_file' => '/usr/local/share/cyford/security/lists/blacklist_domains.txt',
        'emails_file' => '/usr/local/share/cyford/security/lists/blacklist_emails.txt',
    ],

    'errors' => [
        'report_errors' => 1,
        'error_log_location' => '/var/log/cyford-security/errors/error.log',
    ],
];