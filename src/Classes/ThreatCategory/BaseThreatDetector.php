<?php
namespace Cyford\Security\Classes\ThreatCategory;

use Cyford\Security\Classes\Database;
use Cyford\Security\Classes\Logger;

abstract class BaseThreatDetector
{
    protected array $config;
    protected Database $database;
    protected Logger $logger;
    protected string $category;
    private static array $algorithmCache = [];
    
    public function __construct(array $config)
    {
        $this->config = $config;
        $this->logger = new Logger($config);
        $this->database = new Database($config);
    }
    
    /**
     * Get cached algorithms for this category
     */
    protected function getAlgorithms(): array
    {
        $cacheKey = "algorithms_$this->category";
        
        if (!isset(self::$algorithmCache[$cacheKey])) {
            self::$algorithmCache[$cacheKey] = $this->database->getDetectionAlgorithms($this->category);
        }
        $this->logger->info("Retrieved Algorithems" ,  self::$algorithmCache[$cacheKey]);
        return self::$algorithmCache[$cacheKey];
    }
    
    /**
     * Clear algorithm cache (call after database updates)
     */
    public static function clearCache(): void
    {
        self::$algorithmCache = [];
    }

    /**
     * Execute a single algorithm
     * @throws \JsonException
     */
    protected function executeAlgorithm(array $algorithm, array $headers, string $body): bool
    {
        $target = $algorithm['target'];
        $pattern = $algorithm['pattern'];
        $type = $algorithm['detection_type'];
        
        // Get content to check based on target
        $content = $this->getTargetContent($target, $headers, $body);
        
        // Execute based on detection type
        switch ($type) {
            case 'keyword':
                return stripos($content, $pattern) !== false;
                
            case 'regex':
//                return preg_match($pattern, $content);
                if (strlen($pattern) < 2 || !in_array($pattern[0], ['/', '#', '~', '@', '%']) || $pattern[0] !== $pattern[strlen($pattern) - 1]) {
                    $pattern = '/' . str_replace('/', '\/', $pattern) . '/i';
                }
                return (bool)preg_match($pattern, $content);


            case 'domain':
                return $this->checkDomain($content, $pattern);
                
            case 'header_check':
                return $this->checkHeader($headers, $pattern);
                
            case 'url_scan':
                return $this->checkUrls($content, $pattern);
                
            default:
                return false;
        }
    }

    /**
     * Get content based on target specification
     * @throws \JsonException
     */
    private function getTargetContent(string $target, array $headers, string $body): string
    {
        $targets = explode(',', $target);
        $content = '';
        
        foreach ($targets as $t) {
            $t = trim($t);
            switch ($t) {
                case 'subject':
                    $content .= ' ' . ($headers['Subject'] ?? '');
                    break;
                case 'body':
                    $content .= ' ' . $body;
                    break;
                case 'from':
                    $content .= ' ' . ($headers['From'] ?? '');
                    break;
                case 'headers':
                    $content .= ' ' . json_encode($headers, JSON_THROW_ON_ERROR);
                    break;
            }
        }
        
        return trim($content);
    }
    
    /**
     * Check domain patterns
     */
    private function checkDomain(string $content, string $pattern): bool
    {
        if (preg_match_all('/https?:\/\/([^\/\s]+)/i', $content, $matches)) {
            foreach ($matches[1] as $domain) {
                if (stripos($domain, $pattern) !== false) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check header patterns
     * @throws \JsonException
     */
    private function checkHeader(array $headers, string $pattern): bool
    {
        $headerString = json_encode($headers, JSON_THROW_ON_ERROR);
        return stripos($headerString, $pattern) !== false;
    }
    
    /**
     * Check URL patterns
     */
    private function checkUrls(string $content, string $pattern): bool
    {
        return $this->checkDomain($content, $pattern);
    }
    
    /**
     * Abstract method for threat analysis
     */
    abstract public function analyze(array $headers, string $body): array;
}