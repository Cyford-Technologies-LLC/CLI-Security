<?php
namespace Cyford\Security\Classes;

use Exception;
use RuntimeException;

class ApiClient
{
    private string $loginEndpoint;
    private string $reportEndpoint;
    private string $analyzeSpamEndpoint;
    private string $email;
    private string $password;
    private ?string $token = null;
    private $logger;

    public function __construct(array $config, $logger)
    {
        if (!$logger) {
            throw new RuntimeException("Logger is required for ApiClient");
        }
        
        $this->logger = $logger;
        $this->logger->info("DEBUG: ApiClient constructor started");
        
        // Validate required config
        if (empty($config['api']['login_endpoint'])) {
            $this->logger->error("ERROR: Missing api.login_endpoint");
            throw new RuntimeException("Missing required config: api.login_endpoint");
        }
        if (empty($config['api']['report_endpoint'])) {
            $this->logger->error("ERROR: Missing api.report_endpoint");
            throw new RuntimeException("Missing required config: api.report_endpoint");
        }
        if (empty($config['api']['credentials']['email'])) {
            $this->logger->error("ERROR: Missing api.credentials.email");
            throw new RuntimeException("Missing required config: api.credentials.email");
        }
        if (empty($config['api']['credentials']['password'])) {
            $this->logger->error("ERROR: Missing api.credentials.password");
            throw new RuntimeException("Missing required config: api.credentials.password");
        }
        
        $this->loginEndpoint = $config['api']['login_endpoint'];
        $this->reportEndpoint = $config['api']['report_endpoint'];
        $this->analyzeSpamEndpoint = $config['api']['analyze_spam_endpoint'] ?? 'https://api.cyfordtechnologies.com/api/security/v1/analyze-spam';
        $this->email = $config['api']['credentials']['email'];
        $this->password = $config['api']['credentials']['password'];
        
        $this->logger->info("DEBUG: ApiClient constructor completed");
    }

    public function login(): void
    {
        $this->logger->info("DEBUG: Starting login process");
        
        $loginData = [
            'email' => $this->email,
            'password' => $this->password,
        ];

        $response = $this->sendRequest($this->loginEndpoint, 'POST', $loginData, [
            'Content-Type: application/json',
            'Accept: application/json',
        ]);

        if ($response['status_code'] === 200 && isset($response['response']['token'])) {
            $this->token = $response['response']['token'];
            $this->logger->info("DEBUG: Login successful, token retrieved");
        } else {
            throw new RuntimeException("Login failed: " . json_encode($response['response']));
        }
    }

    public function analyzeSpam(string $fromEmail, string $body, $headers, array $options = []): array
    {
        $this->logger->info("DEBUG: analyzeSpam called");
        
        if (!$this->token) {
            throw new RuntimeException("No token found. Please login first.");
        }

        $params = [
            'IP' => $options['ip'] ?? '127.0.0.1',
            'from_email' => $fromEmail,
            'body' => $body,
            'headers' => json_encode($this->parseRawHeaders($headers)),
            'threshold' => $options['threshold'] ?? 70
        ];

        if (isset($options['hostname'])) $params['hostname'] = $options['hostname'];
        if (isset($options['to_email'])) $params['to_email'] = $options['to_email'];

        return $this->sendRequest(
            $this->analyzeSpamEndpoint . '?' . http_build_query($params),
            'GET',
            [],
            ['Authorization: Bearer ' . $this->token]
        );
    }

    private function parseRawHeaders($headers): array
    {
        if (is_array($headers)) return $headers;
        
        $parsed = [];
        $lines = explode("\n", $headers);
        
        foreach ($lines as $line) {
            if (strpos($line, ':') !== false) {
                [$key, $value] = explode(':', $line, 2);
                $parsed[trim($key)] = trim($value);
            }
        }
        
        return $parsed;
    }

    private function sendRequest(string $url, string $method = 'POST', array $data = [], array $headers = [], array $options = []): array
    {
        if ($this->logger) $this->logger->info("DEBUG: sendRequest to $url");
        
        $ch = curl_init();
        
        $defaultOptions = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => false,
        ];

        if ($method === 'POST') {
            $defaultOptions[CURLOPT_POSTFIELDS] = json_encode($data);
        }

        $finalOptions = $defaultOptions + $options;
        $finalOptions[CURLOPT_URL] = $url;

        curl_setopt_array($ch, $finalOptions);
        
        if ($this->logger) $this->logger->info("DEBUG: Executing cURL request");
        $response = curl_exec($ch);
        
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if ($this->logger) {
            $this->logger->info("DEBUG: HTTP Code: $httpCode");
            $this->logger->info("DEBUG: Response length: " . strlen($response ?: ''));
        }

        if (curl_errno($ch)) {
            $errorMessage = curl_error($ch);
            if ($this->logger) $this->logger->error("ERROR: cURL Error: $errorMessage");
            curl_close($ch);
            throw new RuntimeException("cURL Error: $errorMessage");
        }

        curl_close($ch);

        if (empty($response)) {
            if ($this->logger) $this->logger->error("ERROR: Empty response from API");
            throw new RuntimeException("Empty response from API");
        }

        try {
            $decodedResponse = json_decode($response, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            if ($this->logger) $this->logger->error("ERROR: Invalid JSON: " . $e->getMessage());
            throw new RuntimeException("Invalid JSON response: " . $e->getMessage());
        }

        return [
            'status_code' => $httpCode,
            'response' => $decodedResponse,
        ];
    }
}