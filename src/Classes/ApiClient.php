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

    public function __construct(array $config, $logger = null)
    {
        // Validate required config
        if (empty($config['api']['login_endpoint'])) {
            throw new RuntimeException("Missing required config: api.login_endpoint");
        }
        if (empty($config['api']['report_endpoint'])) {
            throw new RuntimeException("Missing required config: api.report_endpoint");
        }
        if (empty($config['api']['credentials']['email'])) {
            throw new RuntimeException("Missing required config: api.credentials.email");
        }
        if (empty($config['api']['credentials']['password'])) {
            throw new RuntimeException("Missing required config: api.credentials.password");
        }
        
        $this->loginEndpoint = $config['api']['login_endpoint'];
        $this->reportEndpoint = $config['api']['report_endpoint'];
        $this->analyzeSpamEndpoint = $config['api']['analyze_spam_endpoint'] ?? 'https://api.cyfordtechnologies.com/api/security/v1/analyze-spam';
        $this->email = $config['api']['credentials']['email'];
        $this->password = $config['api']['credentials']['password'];
        $this->logger = $logger;

        if ($config['errors']['report_errors'] === 1) {
            ini_set('display_errors', 1);
            ini_set('display_startup_errors', 1);
            error_reporting(E_ALL);
        }
    }

    /**
     * Login and get the token
     *
     * @throws Exception
     */
    public function login(): void
    {
        try {
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
                echo "Successfully logged in. Token retrieved.\n";
            } else {
                throw new RuntimeException("Login failed: " . json_encode($response['response']));
            }
        } catch (Exception $e) {
            die("Login error: " . $e->getMessage() . "\n");
        }
    }

    /**
     * Report an IP address
     *
     * @param string $ip
     * @param array|null $categories
     */
    public function reportIp(string $ip, ?array $categories = null): void
    {
        if (!$this->token) {
            throw new RuntimeException("No token found. Please login first.");
        }

        try {
            $reportData = [
                'IP' => $ip,
                'categories' => $categories,
            ];

            $response = $this->sendRequest($this->reportEndpoint . '?' . http_build_query($reportData), 'POST', [], [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $this->token,
            ]);

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

    /**
     * Analyze email content for spam detection
     *
     * @param string $fromEmail Sender email address
     * @param string $body Email body content
     * @param array $headers Email headers
     * @param array $options Additional options (ip, hostname, to_email, threshold)
     * @return array API response
     */
    public function analyzeSpam(string $fromEmail, string $body, $headers, array $options = []): array
    {
        if ($this->logger) {
            $this->logger->info("DEBUG: analyzeSpam called with fromEmail: $fromEmail");
            $this->logger->info("DEBUG: Body length: " . strlen($body));
            $this->logger->info("DEBUG: Headers type: " . gettype($headers));
        }
        
        if (!$this->token) {
            throw new RuntimeException("No token found. Please login first.");
        }
        
        if ($this->logger) $this->logger->info("DEBUG: Token exists, building params...");

        $params = [
            'IP' => $options['ip'] ?? '127.0.0.1',
            'from_email' => $fromEmail,
            'body' => $body,
            'headers' => json_encode($this->parseRawHeaders($headers)),
            'threshold' => $options['threshold'] ?? 70
        ];

        if (isset($options['hostname'])) $params['hostname'] = $options['hostname'];
        if (isset($options['to_email'])) $params['to_email'] = $options['to_email'];
        
        if ($this->logger) {
            $this->logger->info("DEBUG: Params built, about to call sendRequest...");
            $this->logger->info("DEBUG: URL will be: " . $this->analyzeSpamEndpoint . '?' . http_build_query($params));
        }

        return $this->sendRequest(
            $this->analyzeSpamEndpoint . '?' . http_build_query($params),
            'GET',
            [],
            ['Authorization: Bearer ' . $this->token]
        );
    }

    /**
     * Report spam content to server
     *
     * @param array $options Optional parameters (IP, email, content)
     * @return array API response
     */
    public function reportSpam(array $options = []): array
    {
        if (!$this->token) {
            throw new RuntimeException("No token found. Please login first.");
        }

        $params = [];
        if (isset($options['ip'])) $params['IP'] = $options['ip'];
        if (isset($options['email'])) $params['email'] = $options['email'];
        if (isset($options['content'])) $params['content'] = $options['content'];

        echo "Reporting spam to API - Email: " . ($options['email'] ?? 'none') . "\n";
        
        $response = $this->sendRequest(
            'https://api.cyfordtechnologies.com/api/security/v1/report-spam?' . http_build_query($params),
            'POST',
            [],
            ['Authorization: Bearer ' . $this->token]
        );
        
        if ($response['status_code'] === 200) {
            echo "Successfully reported spam to server\n";
        } else {
            echo "Failed to report spam. Status: " . $response['status_code'] . "\n";
        }
        
        return $response;
    }

    /**
     * Parse raw headers string into array
     */
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

    /**
     * Send HTTP request and handle response
     *
     * @param string $url
     * @param string $method
     * @param array $data
     * @param array $headers
     * @param array $options
     * @return array
     * @throws RuntimeException
     * @throws \JsonException
     */
    private function sendRequest(string $url, string $method = 'POST', array $data = [], array $headers = [], array $options = []): array
    {
        $ch = curl_init();

        if ($this->logger) {
            $this->logger->info("DEBUG: Starting API request to: $url");
            $this->logger->info("DEBUG: Method: $method");
            $this->logger->info("DEBUG: Headers: " . json_encode($headers));
        }
        
        $defaultOptions = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => 10, // Reduced timeout
            CURLOPT_CONNECTTIMEOUT => 5, // Connection timeout
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_VERBOSE => true
        ];

        if ($method === 'POST') {
            $defaultOptions[CURLOPT_POSTFIELDS] = json_encode($data);
        }

        $finalOptions = $defaultOptions + $options;
        $finalOptions[CURLOPT_URL] = $url;

        if ($this->logger) $this->logger->info("DEBUG: Setting cURL options...");
        curl_setopt_array($ch, $finalOptions);
        
        if ($this->logger) $this->logger->info("DEBUG: Executing cURL request...");
        $response = curl_exec($ch);
        if ($this->logger) $this->logger->info("DEBUG: cURL execution completed");
        
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($this->logger) {
            $this->logger->info("DEBUG: HTTP Code: $httpCode");
            $this->logger->info("DEBUG: Response length: " . strlen($response ?: ''));
        }

        if (curl_errno($ch)) {
            $errorMessage = curl_error($ch);
            $errorCode = curl_errno($ch);
            echo "ERROR: cURL Error #{$errorCode}: {$errorMessage}\n";
            curl_close($ch);
            throw new RuntimeException("Error during API request: $errorMessage");
        }

        curl_close($ch);
        
        // Validate response
        if ($httpCode === 0) {
            echo "ERROR: No HTTP response received (connection failed)\n";
            throw new RuntimeException("No HTTP response received");
        }
        
        if (empty($response)) {
            echo "ERROR: Empty response from API\n";
            throw new RuntimeException("Empty response from API");
        }
        
        echo "DEBUG: Raw response: " . substr($response, 0, 200) . "...\n";
        
        try {
            $decodedResponse = json_decode($response, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            echo "ERROR: Invalid JSON response: " . $e->getMessage() . "\n";
            echo "DEBUG: Response content: $response\n";
            throw new RuntimeException("Invalid JSON response: " . $e->getMessage());
        }

        return [
            'status_code' => $httpCode,
            'response' => $decodedResponse,
        ];
    }
}