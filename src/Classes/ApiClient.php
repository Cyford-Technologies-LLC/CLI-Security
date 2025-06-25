<?php

class ApiClient
{
    private string $loginEndpoint;
    private string $reportEndpoint;
    private string $email;
    private string $password;
    private ?string $token = null;

    public function __construct(array $config)
    {
        $this->loginEndpoint = $config['api']['login_endpoint'];
        $this->reportEndpoint = $config['api']['report_endpoint'];
        $this->email = $config['credentials']['email'];
        $this->password = $config['credentials']['password'];

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
     * Send HTTP request and handle response
     *
     * @param string $url
     * @param string $method
     * @param array $data
     * @param array $headers
     * @param array $options
     * @return array
     * @throws RuntimeException
     */
    private function sendRequest(string $url, string $method = 'POST', array $data = [], array $headers = [], array $options = []): array
    {
        $ch = curl_init();

        $defaultOptions = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => 45,
        ];

        if ($method === 'POST') {
            $defaultOptions[CURLOPT_POSTFIELDS] = json_encode($data);
        }

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

        return [
            'status_code' => $httpCode,
            'response' => json_decode($response, true),
        ];
    }
}