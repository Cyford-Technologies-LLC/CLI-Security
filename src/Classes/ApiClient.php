<?php
namespace Cyford\Security\Classes;

use Exception;
use RuntimeException;
use Cyford\Security\Classes\Database;
use Cyford\Security\Classes\Logger;
use Cyford\Security\Classes\Systems;

class ApiClient
{
    private const API_BASE_URL = 'https://api.cyfordtechnologies.com';
    private const LOGIN_URI = '/api/auth/v1/login';
    private const REPORT_URI = '/api/security/v1/report-ip';
    private const ANALYZE_SPAM_URI = '/api/security/v1/analyze-spam';
    private const GENERATE_CLIENT_ID_URI = '/api/security/v1/generate-client-id';
    private const GET_ALGORITHMS_URI = '/api/security/v1/get-algorithms';
    private const MARK_HASH_URI = '/api/security/v1/mark-hash';
    private const HASH_OPERATIONS_URI = '/api/security/v1/hash';
    
    private string $baseUrl;
    private string $email;
    private string $password;
    private ?string $token = null;
    private ?string $clientId = null;
    private array $config;
    private $logger;
    private $database;
    private $systems;

    public function __construct(array $config, $logger)
    {
        if (!$logger) {
            throw new RuntimeException("Logger is required for ApiClient");
        }
        
        $this->logger = $logger;
        $this->logger->info("DEBUG: ApiClient constructor started");
        
        // Validate required config
        if (empty($config['api']['credentials']['email'])) {
            $this->logger->error("ERROR: Missing api.credentials.email");
            throw new RuntimeException("Missing required config: api.credentials.email");
        }
        if (empty($config['api']['credentials']['password'])) {
            $this->logger->error("ERROR: Missing api.credentials.password");
            throw new RuntimeException("Missing required config: api.credentials.password");
        }
        
        // Set base URL based on the environment
        $isDocker = Database::isDocker();
        $this->baseUrl = $isDocker ? 'http://host.docker.internal' : self::API_BASE_URL;
        
        if ($isDocker) {
            $this->logger->info("DEBUG: Docker environment detected, using host.docker.internal");
        }
        
        $this->config = $config;
        $this->email = $config['api']['credentials']['email'];
        $this->database = new Database($config);
        $this->password = $config['api']['credentials']['password'];
        $this->systems = new Systems();
        $this->clientId = $this->getClientId();


        $this->logger->info("DEBUG: ApiClient constructor completed");
    }

    public function login(): void
    {
        $this->logger->info("DEBUG: Starting login process");
        
        $loginData = [
            'email' => $this->email,
            'password' => $this->password,
        ];

        $headers = $this->addClientIdHeader([
            'Content-Type: application/json',
            'Accept: application/json',
        ]);
        
        $response = $this->sendRequest($this->baseUrl . self::LOGIN_URI, 'POST', $loginData, $headers);

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

        // URL parameters for auth/middleware
        $urlParams = [
            'IP' => $options['ip'] ?? '127.0.0.1',
            'from_email' => $fromEmail,
            'threshold' => $options['threshold'] ?? 70
        ];

        if (isset($options['hostname'])) $urlParams['hostname'] = $options['hostname'];
        if (isset($options['to_email'])) $urlParams['to_email'] = $options['to_email'];

        // POST body for large content
        $postData = [
            'subject' => $headers['Subject'] ?? '',
            'body' => $body,
            'headers' => $this->parseRawHeaders($headers)
        ];

        $requestHeaders = $this->addClientIdHeader([
            'Authorization: Bearer ' . $this->token,
            'Content-Type: application/json'
        ]);
        
        return $this->sendRequest(
            $this->baseUrl . self::ANALYZE_SPAM_URI . '?' . http_build_query($urlParams),
            'POST',
            $postData,
            $requestHeaders
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
            CURLOPT_TIMEOUT => 30,
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

    /**
     * Get or generate client ID
     */
    private function getClientId(): string
    {
        // Check if client ID exists in config (from .env)
        if (!empty($this->config['api']['client_id'])) {
            return $this->config['api']['client_id'];
        }
        
        // Only request from server if missing - login first
        $this->logger->info("DEBUG: No client ID found, requesting from server");
        try {
            if (!$this->token) {
                $this->login();
            }
            return $this->requestClientIdFromServer();
        } catch (Exception $e) {
            $this->logger->error("ERROR: Failed to fetch client ID: " . $e->getMessage());
            throw new RuntimeException("Issues fetching client ID: " . $e->getMessage());
        }
    }

    /**
     * Request new client ID from server
     */

    private function requestClientIdFromServer(): string
    {
        $hostname = $this->systems->getOSInfo()['hostname'];

        // Construct URL
        $url = $this->baseUrl . self::GENERATE_CLIENT_ID_URI . '?hostname=' . urlencode($hostname);

        // Log the request for debugging
        $this->logger->info("DEBUG: Sending request to URL: {$url}");

        // Send the HTTP request
        $response = $this->sendRequest(
            $url,
            'POST',
            [],
            [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $this->token
            ]
        );

        // Log the full response for debugging
        $this->logger->info("DEBUG: Final Response: " . json_encode($response));

        // Check and extract the client ID from the nested structure
        if (
            isset($response['status_code']) &&
            $response['status_code'] === 200 &&
            isset($response['response']['success']) &&
            $response['response']['success'] === true &&
            isset($response['response']['data']['client_id']) &&
            !empty($response['response']['data']['client_id'])
        ) {
            $clientId = $response['response']['data']['client_id']; // Extract client_id properly
            $this->saveClientIdToConfig($clientId); // Save it if needed
            $this->logger->info("Client ID successfully received and saved: {$clientId}");
            return $clientId;
        }

        // Handle the case where extraction fails
        $this->logger->error("ERROR: Invalid response from server. Response: " . json_encode($response));
        throw new RuntimeException("Server response did not include a valid client_id.");
    }


    /**
     * Save client ID to .env file
     */
    private function saveClientIdToConfig(string $clientId): void
    {
        $envPath = __DIR__ . '/../../.env';
        $envContent = file_exists($envPath) ? file_get_contents($envPath) : '';

        if (strpos($envContent, 'API_CLIENT_ID=') !== false) {
            // Update existing entry
            $envContent = preg_replace('/^API_CLIENT_ID=.*$/m', "API_CLIENT_ID={$clientId}", $envContent);
        } else {
            // Add new entry
            $envContent .= "\nAPI_CLIENT_ID={$clientId}\n";
        }

        file_put_contents($envPath, $envContent);
        $_ENV['API_CLIENT_ID'] = $clientId;
        $this->config['api']['client_id'] = $clientId;
    }

    /**
     * Add client ID header to requests
     */
    private function addClientIdHeader(array $headers): array
    {
        if ($this->clientId) {
            $headers[] = 'X-Client-ID: ' . $this->clientId;
        }
        return $headers;
    }

    /**
     * Get algorithm updates from server
     */
    public function getAlgorithms(int $clientVersion = 0, array $categories = []): array
    {
        if (!$this->token) {
            $this->login(); // This likely initializes or sets the token.
        }

        $params = [
            'client_id' => $this->clientId,
            'client_version' => $clientVersion
        ];

        if (!empty($categories)) {
            $params['categories'] = implode(',', $categories);
        }

        $headers = $this->addClientIdHeader([
            'Authorization: Bearer ' . $this->token
        ]);

        return $this->sendRequest(
            $this->baseUrl . self::GET_ALGORITHMS_URI . '?' . http_build_query($params),
            'POST',
            [],
            $headers
        );
    }


    public function updateAlgorithms(): void
    {
        try {

            $this->logger->info("INFO: Fetching updated algorithms from the API...");

            // Call the API to get updated algorithms
            $apiResponse = $this->getAlgorithms(clientVersion: 1); // Assume your current clientVersion is 1
            $updatedAlgorithms = $apiResponse['response']['data']['algorithms'];

            if (!empty($updatedAlgorithms)) {

                $this->logger->info("Response : " . json_encode($updatedAlgorithms, JSON_THROW_ON_ERROR));

                if (!is_array($updatedAlgorithms)) {
                    $this->logger->error("Invalid data passed to syncDetectionAlgorithm. Data: " . var_export($updatedAlgorithms, true));
                    throw new RuntimeException("Expected array for syncDetectionAlgorithm, got: " . gettype($updatedAlgorithms));
                }





               if (!empty($updatedAlgorithms)){
                   // Synchronize algorithms from the server response
                   foreach ($updatedAlgorithms as $algorithmData) {
                       $this->database->syncDetectionAlgorithm($algorithmData);
                       $this->logger->info("INFO: Processed algorithm '{$algorithmData['name']}' from server.");
                   }
               }else{
                   $this->logger->warning("WARNING: No algorithms received from API.");
               }

                $this->logger->info("INFO: Algorithms updated successfully.");
            }
            else {
                $this->logger->warning("WARNING: No algorithms received from API.");
                return;
            }
        } catch (RuntimeException $exception) {
            $this->logger->error("ERROR: Failed to update algorithms. Details: {$exception->getMessage()}");
        } catch (\JsonException $e) {
        }
    }


    /**
     * Mark hash reputation (spam/clean)
     */
    public function markHash(string $contentHash, string $classification, string $scope = 'account', string $reason = ''): array
    {
        if (!$this->token) {
            throw new RuntimeException("No token found. Please login first.");
        }

        $params = [
            'client_id' => $this->clientId,
            'content_hash' => $contentHash,
            'classification' => $classification,
            'scope' => $scope
        ];

        if (!empty($reason)) {
            $params['reason'] = $reason;
        }

        $headers = $this->addClientIdHeader([
            'Authorization: Bearer ' . $this->token
        ]);

        return $this->sendRequest(
            $this->baseUrl . self::MARK_HASH_URI . '?' . http_build_query($params),
            'POST',
            [],
            $headers
        );
    }

    /**
     * Hash operations (generate, validate, consensus)
     */
    public function hashOperation(string $action, array $data = []): array
    {
        if (!$this->token) {
            throw new RuntimeException("No token found. Please login first.");
        }

        $headers = $this->addClientIdHeader([
            'Authorization: Bearer ' . $this->token,
            'Content-Type: application/json'
        ]);

        if ($action === 'consensus') {
            // GET request for consensus
            $params = ['action' => $action] + $data;
            return $this->sendRequest(
                $this->baseUrl . self::HASH_OPERATIONS_URI . '?' . http_build_query($params),
                'GET',
                [],
                $headers
            );
        }

        // POST request for generate/validate
        $postData = ['action' => $action] + $data;
        return $this->sendRequest(
            $this->baseUrl . self::HASH_OPERATIONS_URI,
            'POST',
            $postData,
            $headers
        );
    }
    /**
     * Report an IP address to the API
     *
     * @param string $ip IP address to report
     * @param array $categories Categories for this IP (e.g., [3, 5] for spam and brute force)
     * @param string $source Source of the report (e.g., 'fail2ban', 'manual', 'firewall')
     * @param array $metadata Additional metadata about the IP
     * @return array API response
     * @throws RuntimeException
     */
    public function reportIp(string $ip, array $categories, string $source = 'manual', array $metadata = []): array
    {
        $this->logger->info("DEBUG: reportIp called for IP: {$ip}");

        if (!$this->token) {
            $this->login();
        }

        // Validate IP address
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new RuntimeException("Invalid IP address: {$ip}");
        }

        // Convert categories to comma-separated string if needed
        $categoriesParam = is_array($categories) ? implode(',', $categories) : $categories;
        $metadataString = json_encode($metadata);


        // Prepare request parameters
        $params = [
            'ips' => $ip,
            'IP' => $ip,
            'categories' => $categoriesParam,
            'Comment' => $metadataString,
            'data' => $metadataString,
            'source' => $source
        ];

        // Add metadata if provided
        if (!empty($metadata)) {
            $params['metadata'] = json_encode($metadata);
        }

        // Prepare headers
        $headers = $this->addClientIdHeader([
            'Authorization: Bearer ' . $this->token,
            'Content-Type: application/json'
        ]);

        $categoriesParam = is_array($categories) ? implode(',', $categories) : $categories;

        $urlParams = [
            'IP' => $ip,              // Important: Use 'IP' instead of 'ips' as URL parameter
            'categories' => $categoriesParam,
            'Comment' => $metadataString,
            'data' => $metadataString,
            'source' => $source
        ];


        // For API authentication
        if (!empty($this->email)) {
            $urlParams['email'] = $this->email;
        }


        // Create the URL with query parameters
        $url = $this->baseUrl . self::REPORT_URI . '?' . http_build_query($urlParams);



        // Send the request
        return $this->sendRequest(
            $url,
            'POST',
            $params,
            $headers
        );
    }

    /**
     * Report multiple IP addresses to the API
     *
     * @param array $ips Array of IP addresses to report
     * @param array $categories Categories for these IPs
     * @param string $source Source of the report
     * @param array $metadata Additional metadata about the IPs
     * @return array API response
     * @throws RuntimeException
     */
    public function reportMultipleIps(array $ips, array $categories, string $source = 'batch', array $metadata = []): array
    {
        $this->logger->info("DEBUG: reportMultipleIps called for " . count($ips) . " IPs");

        if (!$this->token) {
            $this->login();
        }

        // Validate IP addresses
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                throw new RuntimeException("Invalid IP address in batch: {$ip}");
            }
        }

        // Convert arrays to comma-separated strings
        $ipsParam = implode(',', $ips);
        $categoriesParam = implode(',', $categories);

        // Prepare request parameters
        $params = [
            'ips' => $ipsParam,
            'categories' => $categoriesParam,
            'source' => $source
        ];

        // Add metadata if provided
        if (!empty($metadata)) {
            $params['metadata'] = json_encode($metadata);
        }

        // Prepare headers
        $headers = $this->addClientIdHeader([
            'Authorization: Bearer ' . $this->token,
            'Content-Type: application/json'
        ]);

        // Send the request
        return $this->sendRequest(
            $this->baseUrl . self::REPORT_URI,
            'POST',
            $params,
            $headers
        );
    }

}