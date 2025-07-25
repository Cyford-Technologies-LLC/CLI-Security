<?php
namespace Cyford\Security\Classes;

use PDO;
use PDOException;
use RuntimeException;

class Database
{
    private PDO $pdo;
    private static array $cache = [];
    private int $cacheTtl;
    private array $config;
    
    public function __construct(array $config)
    {
        $this->config = $config;
        $this->initializeEnvironment();
        $dbPath = $config['database']['path'] ?? '/tmp/security.db';
        $this->cacheTtl = $config['database']['cache_ttl'] ?? 300;
        
        // Ensure database directory exists
        $dbDir = dirname($dbPath);
        if (!is_dir($dbDir)) {
            if (!mkdir($dbDir, 0775, true)) {
                throw new RuntimeException("Failed to create database directory: {$dbDir}");
            }
        }
        
        try {
            $this->pdo = new PDO("sqlite:$dbPath");
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->initializeTables();
        } catch (PDOException $e) {
            throw new RuntimeException("Database connection failed: " . $e->getMessage());
        }
    }
    
    /**
     * Initialize database tables
     */
    private function initializeTables(): void
    {
        $tables = [
            // Spam log table
            'spam_log' => "
                CREATE TABLE IF NOT EXISTS spam_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    recipient TEXT NOT NULL,
                    sender TEXT,
                    subject TEXT,
                    message_id TEXT,
                    spam_reason TEXT,
                    raw_email TEXT,
                    action TEXT
                )
            ",
            
            // Email statistics
            'email_stats' => "
                CREATE TABLE IF NOT EXISTS email_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date DATE DEFAULT (date('now')),
                    total_emails INTEGER DEFAULT 0,
                    spam_emails INTEGER DEFAULT 0,
                    clean_emails INTEGER DEFAULT 0,
                    bounced_emails INTEGER DEFAULT 0,
                    quarantined_emails INTEGER DEFAULT 0,
                    UNIQUE(date)
                )
            ",
            
            // IP reputation cache
            'ip_reputation' => "
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip TEXT PRIMARY KEY,
                    reputation_score INTEGER DEFAULT 0,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    spam_count INTEGER DEFAULT 0,
                    clean_count INTEGER DEFAULT 0
                )
            ",
            
            // Spam hash tracking for duplicate detection
            'spam_hashes' => "
                CREATE TABLE IF NOT EXISTS spam_hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject_hash TEXT,
                    body_hash TEXT,
                    combined_hash TEXT UNIQUE,
                    sample_subject TEXT,
                    sample_body_preview TEXT,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    count INTEGER DEFAULT 1,
                    is_spam BOOLEAN DEFAULT 1
                )
            ",
            
            // Cache table for general caching
            'cache' => "
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    expires_at DATETIME
                )
            ",
            
            // Detection algorithms table
            'detection_algorithms' => "
                CREATE TABLE IF NOT EXISTS detection_algorithms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER,
                    name TEXT NOT NULL,
                    threat_category TEXT NOT NULL,
                    detection_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    score INTEGER DEFAULT 0,
                    enabled BOOLEAN DEFAULT 1,
                    priority INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    server_updated_at DATETIME
                )
            "
        ];
        
        foreach ($tables as $name => $sql) {
            $this->pdo->exec($sql);
        }
        
        // Create indexes separately for SQLite compatibility
        $indexes = [
            'CREATE INDEX IF NOT EXISTS idx_spam_log_timestamp ON spam_log(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_spam_log_recipient ON spam_log(recipient)',
            'CREATE INDEX IF NOT EXISTS idx_ip_reputation_last_seen ON ip_reputation(last_seen)',
            'CREATE INDEX IF NOT EXISTS idx_spam_hashes_combined ON spam_hashes(combined_hash)',
            'CREATE INDEX IF NOT EXISTS idx_spam_hashes_subject ON spam_hashes(subject_hash)',
            'CREATE INDEX IF NOT EXISTS idx_spam_hashes_body ON spam_hashes(body_hash)',
            'CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache(expires_at)',
            'CREATE INDEX IF NOT EXISTS idx_detection_algorithms_server_id ON detection_algorithms(server_id)',
            'CREATE INDEX IF NOT EXISTS idx_detection_algorithms_category ON detection_algorithms(threat_category)',
            'CREATE INDEX IF NOT EXISTS idx_detection_algorithms_enabled ON detection_algorithms(enabled)',
            'CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_algorithms_server_unique ON detection_algorithms(server_id) WHERE server_id IS NOT NULL'
        ];
        
        foreach ($indexes as $indexSql) {
            $this->pdo->exec($indexSql);
        }
    }
    
    /**
     * Log spam email to database
     */
    public function logSpam(array $data): void
    {
        $sql = "INSERT INTO spam_log (recipient, sender, subject, message_id, spam_reason, raw_email, action) 
                VALUES (?, ?, ?, ?, ?, ?, ?)";
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            $data['recipient'] ?? '',
            $data['sender'] ?? '',
            $data['subject'] ?? '',
            $data['message_id'] ?? '',
            $data['spam_reason'] ?? '',
            $data['raw_email'] ?? '',
            $data['action'] ?? ''
        ]);
        
        // Update daily stats
        $this->updateEmailStats('spam');
    }
    
    /**
     * Update email statistics
     */
    public function updateEmailStats(string $type): void
    {
        $sql = "INSERT OR IGNORE INTO email_stats (date) VALUES (date('now'))";
        $this->pdo->exec($sql);
        
        $column = match($type) {
            'spam' => 'spam_emails',
            'clean' => 'clean_emails',
            'bounce' => 'bounced_emails',
            'quarantine' => 'quarantined_emails',
            default => 'total_emails'
        };
        
        $sql = "UPDATE email_stats SET $column = $column + 1, total_emails = total_emails + 1 
                WHERE date = date('now')";
        $this->pdo->exec($sql);
    }
    
    /**
     * Get cached value
     */
    public function getCache(string $key)
    {
        // Check memory cache first
        if (isset(self::$cache[$key])) {
            $cached = self::$cache[$key];
            if ($cached['expires'] > time()) {
                return $cached['value'];
            }
            unset(self::$cache[$key]);
        }
        
        // Check database cache
        $sql = "SELECT value FROM cache WHERE key = ? AND expires_at > datetime('now')";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$key]);
        
        $result = $stmt->fetchColumn();
        if ($result !== false) {
            $value = json_decode($result, true);
            // Store in memory cache
            self::$cache[$key] = [
                'value' => $value,
                'expires' => time() + $this->cacheTtl
            ];
            return $value;
        }
        
        return null;
    }
    
    /**
     * Set cached value
     */
    public function setCache(string $key, $value, ?int $ttl = null): void
    {
        $ttl = $ttl ?? $this->cacheTtl;
        $expires = time() + $ttl;
        
        // Store in memory cache
        self::$cache[$key] = [
            'value' => $value,
            'expires' => $expires
        ];
        
        // Store in database cache
        $sql = "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, datetime('now', '+$ttl seconds'))";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$key, json_encode($value)]);
    }
    
    /**
     * Update IP reputation
     */
    public function updateIPReputation(string $ip, bool $isSpam): void
    {
        $sql = "INSERT OR IGNORE INTO ip_reputation (ip) VALUES (?)";
        $this->pdo->prepare($sql)->execute([$ip]);
        
        $column = $isSpam ? 'spam_count' : 'clean_count';
        $reputationChange = $isSpam ? -1 : 1;
        
        $sql = "UPDATE ip_reputation 
                SET $column = $column + 1, 
                    reputation_score = reputation_score + ?, 
                    last_seen = CURRENT_TIMESTAMP 
                WHERE ip = ?";
        $this->pdo->prepare($sql)->execute([$reputationChange, $ip]);
    }
    
    /**
     * Get IP reputation score
     */
    public function getIPReputation(string $ip): int
    {
        $sql = "SELECT reputation_score FROM ip_reputation WHERE ip = ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$ip]);
        
        return (int)$stmt->fetchColumn();
    }
    
    /**
     * Get spam statistics
     */
    public function getSpamStats(int $days = 7): array
    {
        $sql = "SELECT date, total_emails, spam_emails, clean_emails, bounced_emails, quarantined_emails 
                FROM email_stats 
                WHERE date >= date('now', '-$days days') 
                ORDER BY date DESC";
        
        return $this->pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Clean old cache entries
     */
    public function cleanCache(): void
    {
        $sql = "DELETE FROM cache WHERE expires_at < datetime('now')";
        $this->pdo->exec($sql);
        
        // Clean memory cache
        foreach (self::$cache as $key => $cached) {
            if ($cached['expires'] <= time()) {
                unset(self::$cache[$key]);
            }
        }
    }
    
    /**
     * Generate secure hash using 3-step HMAC algorithm
     */
    private function generateSecureHash(string $subject, string $body, int $version = 1): string
    {
        if ($version !== 1) {
            throw new RuntimeException("Unsupported hash version: $version");
        }

        
        $primaryKey = 'CYFORD_SECURITY_CLI_2025';
        $secondaryKey = 'CYFORD_WEB_ARMOR_2025';
        
        // Clean content
        $cleanSubject = trim(strtolower($subject));
        $cleanBody = trim(preg_replace('/\s+/', ' ', strip_tags($body)));
        
        // 3-step HMAC process
        $step1 = hash_hmac('sha256', $cleanSubject . '|' . $cleanBody, $primaryKey);
        $step2 = hash_hmac('sha256', $step1, $secondaryKey);
        return hash_hmac('sha256', $step2, date('Y-m-d'));
    }
    
    /**
     * Check if email hash is known spam (previously confirmed by spam filter)
     */
    public function isKnownSpamHash(string $subject, string $body): bool
    {
        $combinedHash = $this->generateSecureHash($subject, $body);
        
        // Try new secure hash first
        $sql = "SELECT is_spam FROM spam_hashes WHERE combined_hash = ? AND is_spam = 1";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$combinedHash]);
        
        $result = $stmt->fetchColumn();
        
        if ($result) {
            // Update last seen count for statistics
            $sql = "UPDATE spam_hashes SET last_seen = CURRENT_TIMESTAMP, count = count + 1 WHERE combined_hash = ?";
            $this->pdo->prepare($sql)->execute([$combinedHash]);
            return true;
        }
        
        // Fallback to legacy hash for backward compatibility
        $legacySubjectHash = hash('sha256', trim(strtolower($subject)));
        $legacyBodyHash = hash('sha256', trim(preg_replace('/\s+/', ' ', strip_tags($body))));
        $legacyCombinedHash = hash('sha256', $legacySubjectHash . $legacyBodyHash);
        
        $sql = "SELECT is_spam FROM spam_hashes WHERE combined_hash = ? AND is_spam = 1";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$legacyCombinedHash]);
        
        $legacyResult = $stmt->fetchColumn();
        
        if ($legacyResult) {
            // Migrate to new hash format
            $this->recordEmailHash($subject, $body, true);
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if email hash is known clean (previously confirmed as legitimate)
     */
    public function isKnownCleanHash(string $subject, string $body): bool
    {
        $combinedHash = $this->generateSecureHash($subject, $body);
        
        // Try new secure hash first
        $sql = "SELECT is_spam FROM spam_hashes WHERE combined_hash = ? AND is_spam = 0";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$combinedHash]);
        
        $result = $stmt->fetchColumn();
        
        if ($result !== false) {
            // Update last seen count for statistics
            $sql = "UPDATE spam_hashes SET last_seen = CURRENT_TIMESTAMP, count = count + 1 WHERE combined_hash = ?";
            $this->pdo->prepare($sql)->execute([$combinedHash]);
            return true;
        }
        
        // Fallback to legacy hash for backward compatibility
        $legacySubjectHash = hash('sha256', trim(strtolower($subject)));
        $legacyBodyHash = hash('sha256', trim(preg_replace('/\s+/', ' ', strip_tags($body))));
        $legacyCombinedHash = hash('sha256', $legacySubjectHash . $legacyBodyHash);
        
        $sql = "SELECT is_spam FROM spam_hashes WHERE combined_hash = ? AND is_spam = 0";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$legacyCombinedHash]);
        
        $legacyResult = $stmt->fetchColumn();
        
        if ($legacyResult !== false) {
            // Migrate to new hash format
            $this->recordEmailHash($subject, $body, false);
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if email is spam based on hash (DEPRECATED - use isKnownSpamHash)
     */
    public function checkSpamHash(string $subject, string $body, int $threshold = 3): bool
    {
        // This method is deprecated to prevent false positives from legitimate bulk emails
        return $this->isKnownSpamHash($subject, $body);
    }
    
    /**
     * Record email hash (spam or clean)
     */
    public function recordEmailHash(string $subject, string $body, bool $isSpam): void
    {
        $combinedHash = $this->generateSecureHash($subject, $body);
        $subjectHash = hash('sha256', trim(strtolower($subject)));
        $bodyHash = hash('sha256', trim(preg_replace('/\s+/', ' ', strip_tags($body))));
        
        // Create preview of body (first 200 chars, no HTML)
        $bodyPreview = substr(trim(preg_replace('/\s+/', ' ', strip_tags($body))), 0, 200);
        
        $sql = "INSERT OR REPLACE INTO spam_hashes 
                (subject_hash, body_hash, combined_hash, sample_subject, sample_body_preview, first_seen, last_seen, count, is_spam) 
                VALUES (?, ?, ?, ?, ?, 
                    COALESCE((SELECT first_seen FROM spam_hashes WHERE combined_hash = ?), CURRENT_TIMESTAMP),
                    CURRENT_TIMESTAMP,
                    COALESCE((SELECT count FROM spam_hashes WHERE combined_hash = ?), 0) + 1,
                    ?)
                ";
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$subjectHash, $bodyHash, $combinedHash, $subject, $bodyPreview, $combinedHash, $combinedHash, $isSpam ? 1 : 0]);
    }
    
    /**
     * Get similar spam by subject or body hash
     */
    public function getSimilarSpam(string $subject, string $body, int $limit = 10): array
    {
        $subjectHash = hash('sha256', trim(strtolower($subject)));
        $bodyHash = hash('sha256', trim(preg_replace('/\s+/', ' ', strip_tags($body))));
        
        $sql = "SELECT combined_hash, count, first_seen, last_seen 
                FROM spam_hashes 
                WHERE (subject_hash = ? OR body_hash = ?) AND is_spam = 1
                ORDER BY count DESC, last_seen DESC 
                LIMIT ?";
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$subjectHash, $bodyHash, $limit]);
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Mark hash as false positive (not spam)
     */
    public function markHashAsClean(string $subject, string $body): void
    {
        $subjectHash = hash('sha256', trim(strtolower($subject)));
        $bodyHash = hash('sha256', trim(preg_replace('/\s+/', ' ', strip_tags($body))));
        $combinedHash = hash('sha256', $subjectHash . $bodyHash);
        
        $sql = "UPDATE spam_hashes SET is_spam = 0 WHERE combined_hash = ?";
        $this->pdo->prepare($sql)->execute([$combinedHash]);
    }

    /**
     * Get all blocked spam patterns with sample text
     */
    public function getBlockedSpamPatterns(int $limit = 50): array
    {
        $sql = "SELECT id, sample_subject, sample_body_preview, first_seen, last_seen, count 
                FROM spam_hashes 
                WHERE is_spam = 1 
                ORDER BY last_seen DESC 
                LIMIT ?";
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$limit]);
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Get all known clean patterns with sample text
     */
    public function getCleanEmailPatterns(int $limit = 50): array
    {
        $sql = "SELECT id, sample_subject, sample_body_preview, first_seen, last_seen, count 
                FROM spam_hashes 
                WHERE is_spam = 0 
                ORDER BY last_seen DESC 
                LIMIT ?";
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$limit]);
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Search blocked spam patterns by text
     */
    public function searchSpamPatterns(string $searchTerm, int $limit = 20): array
    {
        $searchTerm = '%' . $searchTerm . '%';
        
        $sql = "SELECT id, sample_subject, sample_body_preview, first_seen, last_seen, count 
                FROM spam_hashes 
                WHERE is_spam = 1 
                AND (sample_subject LIKE ? OR sample_body_preview LIKE ?) 
                ORDER BY count DESC, last_seen DESC 
                LIMIT ?";
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$searchTerm, $searchTerm, $limit]);
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Get spam pattern statistics
     */
    public function getSpamPatternStats(): array
    {
        $sql = "SELECT 
                    COUNT(*) as total_patterns,
                    SUM(count) as total_blocked_emails,
                    AVG(count) as avg_blocks_per_pattern,
                    MAX(count) as max_blocks_single_pattern,
                    MIN(first_seen) as oldest_pattern,
                    MAX(last_seen) as newest_block
                FROM spam_hashes 
                WHERE is_spam = 1";
        
        return $this->pdo->query($sql)->fetch(PDO::FETCH_ASSOC);
    }
    
    /**
     * Remove spam pattern (unblock)
     */
    public function removeSpamPattern(int $patternId): bool
    {
        $sql = "DELETE FROM spam_hashes WHERE id = ? AND is_spam = 1";
        $stmt = $this->pdo->prepare($sql);
        return $stmt->execute([$patternId]);
    }

    /**
     * Get all enabled detection algorithms by category
     */
    public function getDetectionAlgorithms(?string $category = null): array
    {
        $sql = "SELECT * FROM detection_algorithms WHERE enabled = 1";
        $params = [];
        
        if ($category) {
            $sql .= " AND threat_category = ?";
            $params[] = $category;
        }
        
        $sql .= " ORDER BY priority DESC, id ASC";
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Update or insert detection algorithm from server
     */
    public function syncDetectionAlgorithm(array $data): void
    {


        if (isset($data['id'])) {
            // Update existing algorithm
            $sql = "UPDATE detection_algorithms SET 
                    name = ?, threat_category = ?, detection_type = ?, target = ?, 
                    pattern = ?, score = ?, enabled = ?, priority = ?, 
                    updated_at = CURRENT_TIMESTAMP, server_updated_at = CURRENT_TIMESTAMP
                    WHERE server_id = ?";
            
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute([
                $data['name'], $data['category'], $data['detection_type'],
                $data['target'], $data['pattern'], $data['score'],
                $data['enabled'] ?? 1, $data['priority'] ?? 0, $data['id']
            ]);
            
            // If no rows affected, insert new
            if ($stmt->rowCount() === 0) {
                $this->insertDetectionAlgorithm($data);
            }
        } else {
            $this->insertDetectionAlgorithm($data);
        }
    }
    
    /**
     * Insert new detection algorithm
     */
    private function insertDetectionAlgorithm(array $data): void
    {

        $category = $data['threat_category'] ?? $data['category'];
        $sql = "INSERT INTO detection_algorithms 
                (server_id, name, threat_category, detection_type, target, pattern, score, enabled, priority, server_updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)";
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            $data['id'] ?? null, $data['name'], $category,
            $data['detection_type'], $data['target'], $data['pattern'],
            $data['score'] ?? 0, $data['enabled'] ?? 1, $data['priority'] ?? 0
        ]);
    }
    
    /**
     * Delete detection algorithm by server_id
     */
    public function deleteDetectionAlgorithm(int $serverId): void
    {
        $sql = "DELETE FROM detection_algorithms WHERE server_id = ?";
        $this->pdo->prepare($sql)->execute([$serverId]);
    }

    /**
     * Initialize environment detection
     */
    private function initializeEnvironment(): void
    {
        $envFile = '/tmp/cyford-security/env.txt';
        $envDir = dirname($envFile);
        
        // Create directory if it doesn't exist
        if (!is_dir($envDir)) {
            mkdir($envDir, 0755, true);
        }
        
        // Check if env file exists and is valid
        if (file_exists($envFile)) {
            $content = trim(file_get_contents($envFile));
            if ($content === 'docker=1' || $content === 'docker=0') {
                return; // Valid environment file exists
            }
        }
        
        // Detect environment and create file
        $isDocker = $this->detectDockerEnvironment();
        $envContent = $isDocker ? 'docker=1' : 'docker=0';
        
        file_put_contents($envFile, $envContent);
        chmod($envFile, 0644);
    }
    
    /**
     * Detect if running in Docker environment
     */
    private function detectDockerEnvironment(): bool
    {
        // Method 1: Check for .dockerenv file
        if (file_exists('/.dockerenv')) {
            return true;
        }
        
        // Method 2: Check environment variables
        if (!empty($_ENV['DOCKER_ENV']) || !empty(getenv('DOCKER_ENV'))) {
            return true;
        }
        
        // Method 3: Check cgroup for docker
        if (file_exists('/proc/1/cgroup')) {
            $cgroup = file_get_contents('/proc/1/cgroup');
            if (strpos($cgroup, 'docker') !== false || strpos($cgroup, 'containerd') !== false) {
                return true;
            }
        }
        
        // Method 4: Check for container-specific files
        if (file_exists('/run/.containerenv')) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if running in Docker (static method for global use)
     */
    public static function isDocker(): bool
    {
        $envFile = '/tmp/cyford-security/env.txt';
        
        if (file_exists($envFile)) {
            $content = trim(file_get_contents($envFile));
            return $content === 'docker=1';
        }
        
        // Fallback detection if file doesn't exist
        return file_exists('/.dockerenv') || 
               !empty($_ENV['DOCKER_ENV']) || 
               !empty(getenv('DOCKER_ENV'));
    }

    /**
     * Get database connection for custom queries
     */
    public function getPDO(): PDO
    {
        return $this->pdo;
    }


    /**
     * Log reported IP information to the database
     *
     * @param string $ip IP address that was reported
     * @param string $source Source of the report (e.g., 'fail2ban', 'manual')
     * @param string $reason Reason for reporting
     * @param array $metadata Additional metadata about the report
     * @param bool $success Whether the report was successful
     * @return bool Success status
     */
    public function logReportedIP(string $ip, string $source = 'manual', string $reason = '', array $metadata = [], bool $success = true): bool
    {
        try {
            // Ensure the reported_ips table exists
            $this->createReportedIpsTableIfNotExists();

            $stmt = $this->db->prepare("
            INSERT INTO reported_ips (
                ip_address, 
                source, 
                reason, 
                metadata,
                reported_at,
                report_success
            ) VALUES (?, ?, ?, ?, ?, ?)
        ");

            $metadataJson = !empty($metadata) ? json_encode($metadata) : '{}';
            $currentTime = date('Y-m-d H:i:s');
            $reportSuccess = $success ? 1 : 0;

            $stmt->execute([
                $ip,
                $source,
                $reason,
                $metadataJson,
                $currentTime,
                $reportSuccess
            ]);

            return true;
        } catch (\PDOException $e) {
            if (isset($this->logger)) {
                $this->logger->error("Failed to log reported IP: " . $e->getMessage());
            }
            return false;
        }
    }

    /**
     * Create the reported_ips table if it doesn't exist
     */
    private function createReportedIpsTableIfNotExists(): void
    {
        $this->db->exec("
        CREATE TABLE IF NOT EXISTS reported_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            source TEXT NOT NULL,
            reason TEXT,
            metadata TEXT,
            reported_at DATETIME NOT NULL,
            report_success INTEGER DEFAULT 1
        )
    ");

        // Create an index for faster lookups
        $this->db->exec("
        CREATE INDEX IF NOT EXISTS idx_reported_ips_ip_address 
        ON reported_ips (ip_address)
    ");
    }

    /**
     * Check if an IP has been reported recently
     *
     * @param string $ip IP address to check
     * @param int $withinSeconds Time window in seconds to check
     * @return bool Whether the IP has been reported recently
     */
    public function hasIpBeenReportedRecently(string $ip, int $withinSeconds = 86400): bool
    {
        try {
            $this->createReportedIpsTableIfNotExists();

            $stmt = $this->db->prepare("
            SELECT COUNT(*) as count 
            FROM reported_ips 
            WHERE ip_address = ? 
            AND reported_at > datetime('now', '-' || ? || ' seconds')
            AND report_success = 1
        ");

            $stmt->execute([$ip, $withinSeconds]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            return ($result['count'] > 0);
        } catch (\PDOException $e) {
            if (isset($this->logger)) {
                $this->logger->error("Failed to check reported IP: " . $e->getMessage());
            }
            return false;
        }
    }







}