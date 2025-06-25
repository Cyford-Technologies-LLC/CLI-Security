<?php

// Standalone PHP CLI-based script that logs in and reports IPs to an API endpoint

// Ensure the script runs in CLI
if (php_sapi_name() != 'cli') {
    die("This script must be run from the CLI.");
}
// Load configuration
$config = require 'config.php';


if ($config['errors']['report_errors'] === 1){
// Turn on strict error reporting
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
}

// Helper function to send HTTP requests
function sendRequest(string $url, string $method = 'POST', array $data = [], array $headers = [], array $options = []): array
{
    $ch = curl_init();

    // Set options for the curl
    $defaultOptions = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST => strtoupper($method),
        CURLOPT_HTTPHEADER    => $headers,
        CURLOPT_TIMEOUT       => 45,
    ];

    if ($method === 'POST') {
        $defaultOptions[CURLOPT_POSTFIELDS] = json_encode($data);
    }

    // Merge custom options
    $finalOptions = $defaultOptions + $options;
    $finalOptions[CURLOPT_URL] = $url;
    curl_setopt_array($ch, $finalOptions);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if (curl_errno($ch)) {
        $errorMessage = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException("Error during API request: $errorMessage");
    }

    curl_close($ch);

    // Decode and return the response
    return [
        'status_code' => $httpCode,
        'response'    => json_decode($response, true),
    ];
}

// Logic for obtaining authentication token (login)
function login(): string
{
    try {
        $loginData = [
            'email'    => EMAIL,
            'password' => PASSWORD,
        ];

        // Send login request
        $response = sendRequest(LOGIN_ENDPOINT, 'POST', $loginData, [
            'Content-Type: application/json',
            'Accept: application/json',
        ]);

        // Parse the response
        if ($response['status_code'] === 200 && isset($response['response']['token'])) {
            echo "Successfully logged in. Token retrieved.\n";
            return $response['response']['token']; // Return the API token
        } else {
            throw new RuntimeException("Login failed: " . json_encode($response['response']));
        }
    } catch (Exception $e) {
        die("Login error: " . $e->getMessage() . "\n");
    }
}

// Logic for reporting an IP
function reportIp(string $token, string $ip, ?array $categories = null): void
{
    try {
        $reportData = [
            'IP'         => $ip,
            'categories' => $categories, // Set this to any category you need
        ];

        // Send report request
        $response = sendRequest(REPORT_ENDPOINT . '?' . http_build_query($reportData), 'POST', [], [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $token,
        ]);

        // Handle and display the result
        if ($response['status_code'] === 200) {
            echo "Successfully reported IP: $ip\n";
        } else {
            echo "Failed to report IP: $ip\n";
            print_r($response['response']);
        }
    } catch (Exception $e) {
        echo "IP report failed. Error: " . $e->getMessage() . "\n";
    }
}

// Main CLI logic
try {
    echo "Starting script...\n";

    // Login to get the token
    $token = login();

    // List of IPs to report (replace this; can come from dynamic input or database)
    $ipsToReport = [
        '8.8.8.8',
        '127.0.0.1',
        '192.168.1.10',
    ];

    // Categories for report, replace null with real category array if needed
    $categories = [3, 5, 8]; // Example: categories like hacking, abuse, etc. Replace based on your need

    // Report each IP
    foreach ($ipsToReport as $ip) {
        reportIp($token, $ip, $categories);
    }

    echo "Script finished.\n";
} catch (Exception $e) {
    die("Critical error in script execution: " . $e->getMessage() . "\n");
}