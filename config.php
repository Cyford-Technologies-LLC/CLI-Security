<?php

// Configuration for API endpoints, authentication, etc.
return [
    'api' => [
        'login_endpoint' => 'https://api.cyfordtechnologies.com/api/auth/v1/login', // Login URL
        'report_endpoint' => 'https://api.cyfordtechnologies.com/api/security/v1/report-ip', // Report URL
    ],
    'postfix' => [
        'requeue_method' => 'postdrop', // Options: sendmail, postdrop , postpickup  , smtp
        'main_config' => '/etc/postfix/main.cf', // Path to Postfix main configuration file
        'master_config' => '/etc/postfix/master.cf', // Path to Postfix master configuration file
        'postfix_command' => '/usr/sbin/postfix', // Path to Postfix executable
        'allow_modification' => true, // Set to true to allow automatic configuration changes
        'backup_directory' => '/var/backups/postfix', // Path to store configuration file backups
        'spam_handling' => [
            'action' => 'quarantine', // Options: 'reject', 'quarantine', 'allow'
            'bounce_message' => 'Your message has been rejected due to spam content. Please contact the administrator if you believe this is an error.',
            'quarantine_folder' => 'Spam', // Folder name to create for spam emails
            'add_footer' => true, // Add spam filter footer to clean emails
            'footer_text' => '\n\n--- This email has been scanned by Cyford Security Filter ---',
        ],
    ],
    'credentials' => [
        'email' => '',  // Account email for login
        'password' => '',             // Account password for login
    ],
    'log' => [
        'file_path' => '/var/log/cyford-security/application.log',
    ],

    'errors' => [
        'report_errors' => 1,
        'error_log_location' =>  __DIR__ . '/var/log/cyford-security/errors/error.log',
    ],
];