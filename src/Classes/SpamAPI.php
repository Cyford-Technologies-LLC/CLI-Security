<?php
namespace Cyford\Security\Classes;

class SpamAPI
{
    private string $endpoint;
    private array $credentials;
    private string $authToken = '';
    private Database $database;
    private array $sentHashes = [];
    private array $sentIPs = [];
    private string $hostname;
    private string $serviceModule;

    public function __construct(array $config, string $serviceModule = 'unknown')
    {
        $this->endpoint = $config['api']['spam_check_endpoint'] ?? '';
        $this->credentials = $config['api']['credentials'] ?? [];
        $this->database = new Database($config);
        $this->hostname = gethostname() ?: 'unknown';
        $this->serviceModule = $serviceModule;
        $this->loadSentTracking();
    }

    /**
     * Check if email content is spam via API
     */
    public function checkSpam(string $subject, string $body, array $headers = []): array
    {
        $data = [
            'hostname' => $this->hostname,
            'service_module' => $this->serviceModule,
            'subject' => $subject,
            'body' => $body,
            'headers' => $headers,
            'timestamp' => time()
        ];

        return $this->makeRequest('POST', '/spam/check', $data);
    }

    /**
     * Report spam to improve detection
     */
    public function reportSpam(string $subject, string $body, array $metadata = []): array
    {
        $data = [
            'hostname' => $this->hostname,
            'service_module' => $this->serviceModule,
            'subject' => $subject,
            'body' => $body,
            'metadata' => $metadata,
            'timestamp' => time()
        ];

        return $this->makeRequest('POST', '/spam/report', $data);
    }
    
    /**
     * Report spam with full headers for complete analysis
     */
    public function reportSpamWithHeaders(string $subject, string $body, array $headers, array $metadata = []): array
    {
        $data = [
            'hostname' => $this->hostname,
            'service_module' => $this->serviceModule,
            'subject' => $subject,
            'body' => $body,
            'headers' => $headers,
            'metadata' => $metadata,
            'timestamp' => time()
        ];

        return $this->makeRequest('POST', '/spam/report', $data);
    }

    /**
     * Make authenticated API request
     */
    private function makeRequest(string $method, string $path, array $data = []): array
    {
        if (empty($this->authToken)) {
            $this->authenticate();
        }

        $url = rtrim($this->endpoint, '/') . $path;
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $this->authToken
            ],
            CURLOPT_POSTFIELDS => json_encode($data),
            CURLOPT_TIMEOUT => 10
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            throw new \RuntimeException("API request failed: HTTP $httpCode");
        }

        return json_decode($response, true) ?? [];
    }

    /**
     * Check if hash was already sent to API
     */
    private function isHashSent(string $hash): bool
    {
        return in_array($hash, $this->sentHashes) || 
               $this->database->getCache("sent_hash_{$hash}") !== null;
    }
    
    /**
     * Check if IP was already sent to API
     */
    private function isIPSent(string $ip): bool
    {
        return in_array($ip, $this->sentIPs) || 
               $this->database->getCache("sent_ip_{$ip}") !== null;
    }
    
    /**
     * Mark hash as sent
     */
    private function markHashSent(string $hash): void
    {
        $this->sentHashes[] = $hash;
        $this->database->setCache("sent_hash_{$hash}", true, 86400); // 24 hours
    }
    
    /**
     * Mark IP as sent
     */
    private function markIPSent(string $ip): void
    {
        $this->sentIPs[] = $ip;
        $this->database->setCache("sent_ip_{$ip}", true, 86400); // 24 hours
    }
    
    /**
     * Load previously sent tracking from cache
     */
    private function loadSentTracking(): void
    {
        // Load from memory cache - database cache is checked in is*Sent methods
        $this->sentHashes = [];
        $this->sentIPs = [];
    }
    
    /**
     * Send spam data only if not already sent
     */
    public function sendSpamDataIfNew(string $subject, string $body, string $clientIP = '', array $headers = []): bool
    {
        $subjectHash = hash('sha256', trim(strtolower($subject)));
        $bodyHash = hash('sha256', trim(preg_replace('/\s+/', ' ', strip_tags($body))));
        $contentHash = hash('sha256', $subject . $body);
        
        $sent = false;
        
        // Send hash data if not already sent
        if (!$this->isHashSent($contentHash)) {
            $metadata = [
                'type' => 'content_hash',
                'subject_hash' => $subjectHash,
                'body_hash' => $bodyHash,
                'combined_hash' => $contentHash
            ];
            
            if (!empty($clientIP)) {
                $metadata['client_ip'] = $clientIP;
            }
            
            // Send full content with hashes for analysis
            $this->reportSpamWithHeaders($subject, $body, $headers, $metadata);
            $this->markHashSent($contentHash);
            $sent = true;
        }
        
        // Send IP data separately if provided and not already sent
        if (!empty($clientIP) && !$this->isIPSent($clientIP)) {
            $this->reportSpamWithHeaders($subject, $body, $headers, [
                'type' => 'ip_report', 
                'client_ip' => $clientIP,
                'subject_hash' => $subjectHash,
                'body_hash' => $bodyHash
            ]);
            $this->markIPSent($clientIP);
            $sent = true;
        }
        
        return $sent;
    }

    /**
     * Authenticate with API
     */
    private function authenticate(): void
    {
        // Implementation for getting auth token
        // This will connect to your Cyford Web Armor auth endpoint
    }
}