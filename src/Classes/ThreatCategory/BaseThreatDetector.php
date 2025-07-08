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
            $this->logger->info("Fetching detection algorithms for category: {$this->category}");
            self::$algorithmCache[$cacheKey] = $this->database->getDetectionAlgorithms($this->category);
            $count = count(self::$algorithmCache[$cacheKey]);
            $this->logger->info("Retrieved {$count} algorithms for {$this->category}");

            // Log the details of each algorithm for debugging
            if ($count > 0) {
                foreach (self::$algorithmCache[$cacheKey] as $index => $algorithm) {
                    $this->logger->info("Algorithm #{$index}: {$algorithm['name']}", [
                        'type' => $algorithm['detection_type'],
                        'pattern' => $algorithm['pattern'],
                        'target' => $algorithm['target']
                    ]);
                }
            } else {
                $this->logger->warning("No algorithms found for {$this->category} - threat detection will be ineffective");
            }
        }

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
        $algorithmName = $algorithm['name'] ?? 'unnamed';  // Add this line to define $algorithmName


        // Get content to check based on target
        $content = $this->getTargetContent($target, $headers, $body);
        
        // Execute based on detection type
        switch ($type) {
            case 'keyword':
                return $this->processKeywordPattern($pattern, $content, $algorithmName);

            case 'regex':
                // Check if the pattern already has delimiters
                return $this->processRegexPattern($pattern, $content, $algorithmName);

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






    /**
     * Safely processes a regex pattern and handles potential errors
     *
     * @param string $pattern The pattern to process
     * @param string $content The content to check against
     * @param string $algorithmName Name of the algorithm for logging
     * @return bool True if pattern matches content
     */
    protected function processRegexPattern(string $pattern, string $content, string $algorithmName): bool
    {
        // Log the original pattern for debugging
        $this->logger->info("Processing regex pattern for $algorithmName: '$pattern'");

        // The pattern might be stored with text delimiters and modifiers
        // Common format in the database seems to be: '/pattern/i...'

        // Extract the actual pattern from database format
        if (preg_match('/^\'?\/(.+?)\/([a-zA-Z]*)\.\.\.\'?$/i', $pattern, $matches)) {
            // This handles patterns stored like '/pattern/i...' or ''/pattern/i...''
            $patternContent = $matches[1];
            $modifiers = $matches[2] ?? 'i';

            // Construct a proper regex pattern
            $pattern = '/' . str_replace('/', '\/', $patternContent) . '/' . $modifiers;
            $this->logger->info("Extracted pattern from database format: $pattern");
        }
        // Check if it's a regular pattern that just needs delimiters
        else if (!preg_match('/^\/.*\/[a-zA-Z]*$/', $pattern)) {
            // Not already a valid regex with delimiters, add them
            $pattern = '/' . str_replace('/', '\/', $pattern) . '/i';
            $this->logger->info("Added delimiters to pattern: $pattern");
        } else {
            $this->logger->info("Using existing pattern: $pattern");
        }

        // Safely execute the regex
        try {
            $result = (bool)preg_match($pattern, $content);
            $this->logger->info("Regex check result: " . ($result ? "MATCH" : "no match"));
            return $result;
        } catch (\Exception $e) {
            $this->logger->error("Invalid regex pattern in algorithm $algorithmName: " . $e->getMessage(), [
                'pattern' => $pattern,
                'original' => $algorithm['pattern'] ?? 'unknown'
            ]);

            // As a fallback, try a simple substring match
            $simpleMatch = stripos($content, trim(preg_replace('/[\/\\\\\(\)\[\]\{\}\^\$\*\+\?\.\|\-]/', '', $pattern))) !== false;
            $this->logger->info("Falling back to simple text match: " . ($simpleMatch ? "MATCH" : "no match"));
            return $simpleMatch;
        }
    }


    /**
     * Process a keyword pattern against content with both exact and partial matching
     *
     * @param string $pattern The keyword pattern to check
     * @param string $content The content to check against
     * @param string $algorithmName Name of the algorithm for logging
     * @return bool True if pattern matches content
     */
    protected function processKeywordPattern(string $pattern, string $content, string $algorithmName): bool
    {
        // First try exact match (case-insensitive)
        if (stripos($content, $pattern) !== false) {
            $this->logger->info("Exact keyword match found for '$algorithmName': '$pattern'");
            return true;
        }

        // If exact match fails, try a more flexible approach for multi-word patterns
        $patternWords = explode(' ', strtolower($pattern));

        // Only proceed with partial matching if there are multiple words
        if (count($patternWords) <= 1) {
            return false;
        }

        $contentLower = strtolower($content);
        $allWordsFound = true;
        $matchedWords = [];

        // Check if all significant words (longer than 3 chars) exist in the content
        foreach ($patternWords as $word) {
            if (strlen($word) > 3) {
                if (stripos($contentLower, $word) === false) {
                    $allWordsFound = false;
                    break;
                } else {
                    $matchedWords[] = $word;
                }
            }
        }

        // Only consider it a match if all significant words were found
        if ($allWordsFound && !empty($matchedWords)) {
            $this->logger->info("Partial keyword match found for '$algorithmName': '" .
                implode(', ', $matchedWords) . "' from pattern '$pattern'");
            return true;
        }

        return false;
    }









}