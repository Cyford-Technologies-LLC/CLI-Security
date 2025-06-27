<?php

// Configuration for API endpoints, authentication, etc.
return [
    'api' => [
        'login_endpoint' => 'https://api.cyfordtechnologies.com/api/auth/v1/login', // Login URL
        'report_endpoint' => 'https://api.cyfordtechnologies.com/api/security/v1/report-ip', // Report URL
    ],
    'postfix' => [
        'requeue_method' => 'smtp', // Options: smtp , sendmail, postdrop , postpickup (SMTP  is the only working method as of now)
        'main_config' => '/etc/postfix/main.cf', // Path to Postfix main configuration file
        'master_config' => '/etc/postfix/master.cf', // Path to Postfix master configuration file
        'postfix_command' => '/usr/sbin/postfix', // Path to Postfix executable
        'allow_modification' => true, // Set to true to allow automatic configuration changes
        'backup_directory' => '/var/backups/postfix', // Path to store configuration file backups
        'spam_handling' => [
            'action' => 'quarantine', // Options: 'reject', 'quarantine', 'allow'
            'bounce_message' => 'Your message has been rejected due to spam content by Cyford Web Armor. Please contact the administrator if you believe this is an error.',
            'quarantine_folder' => 'Spam', // Folder name to create for spam emails
            'add_footer' => true, // Add spam filter footer to clean emails
            'footer_text' => '\n\n--- This email has been scanned by Cyford Web Armor ---',
            'spam_log_file' => '/var/log/cyford-security/spam.log', // Detailed spam log with raw emails
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
    ],
    'credentials' => [
        'email' => '',  // Account email for login
        'password' => '',             // Account password for login
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
        'error_log_location' =>  __DIR__ . '/var/log/cyford-security/errors/error.log',
    ],
];