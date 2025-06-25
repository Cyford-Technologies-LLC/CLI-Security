<?php

// Configuration for API endpoints, authentication, etc.
return [
    'api' => [
        'login_endpoint' => 'https://api.cyfordtechnologies.com/api/auth/v1/login', // Login URL
        'report_endpoint' => 'https://api.cyfordtechnologies.com/api/security/v1/report-ip', // Report URL
    ],
    'credentials' => [
        'email' => '',  // Account email for login
        'password' => '',             // Account password for login
    ],
    'errors' => [
        'report_errors' => 1,
    ],
];