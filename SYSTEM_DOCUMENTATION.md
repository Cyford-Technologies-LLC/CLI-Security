# Cyford Web Armor - System Documentation

## Overview
This is a comprehensive email security system that integrates with Postfix to filter spam using local algorithms and cloud-based API analysis.

## System Architecture

### Core Components
1. **Local Spam Filter** - Primary filtering using local algorithms
2. **API Integration** - Cloud-based spam analysis via Cyford API
3. **Hash Detection** - Database-based pattern matching
4. **Task Queue System** - Background processing for spam handling

## Algorithm Configuration

### Threat Categories
The system uses configurable threat categories passed via command line:
```bash
--categories=3
```

Categories include:
- Category 1: Basic spam patterns
- Category 2: Advanced phishing detection  
- Category 3: Malware/attachment scanning
- Category 4: Social engineering detection
- Category 5: Advanced persistent threats

### Current Algorithm System
**MIGRATED TO DATABASE-DRIVEN DETECTION**

Algorithms are now stored in the `detection_algorithms` database table and executed via:
- `src/Classes/ThreatCategory/Spam.php` - Main spam detection
- `src/Classes/ThreatCategory/BaseThreatDetector.php` - Algorithm execution engine

#### Database-Driven Algorithm Structure
```sql
CREATE TABLE detection_algorithms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,                    -- Server sync ID
    name TEXT NOT NULL,                   -- Algorithm name
    threat_category TEXT NOT NULL,        -- 'spam', 'phishing', 'malware'
    detection_type TEXT NOT NULL,         -- 'keyword', 'regex', 'domain', 'header_check', 'url_scan'
    target TEXT NOT NULL,                 -- 'subject', 'body', 'from', 'headers'
    pattern TEXT NOT NULL,                -- Detection pattern/keyword
    score INTEGER DEFAULT 0,              -- Threat score weight
    enabled BOOLEAN DEFAULT 1,            -- Active/inactive
    priority INTEGER DEFAULT 0,           -- Execution priority
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    server_updated_at DATETIME            -- Last server sync
);
```

#### Algorithm Execution Types
1. **keyword** - Simple string matching (case-insensitive)
2. **regex** - Regular expression pattern matching
3. **domain** - URL domain checking
4. **header_check** - Email header analysis
5. **url_scan** - Link scanning and validation

#### Target Content Areas
- **subject** - Email subject line
- **body** - Email body content
- **from** - Sender information
- **headers** - All email headers
- **Multiple targets** - Comma-separated (e.g., "subject,body")

#### Current Algorithm Flow
```php
// In Spam.php
public function analyze(array $headers, string $body): array
{
    $algorithms = $this->getAlgorithms();  // Load from database
    
    foreach ($algorithms as $algorithm) {
        if ($this->executeAlgorithm($algorithm, $headers, $body)) {
            $totalScore += $algorithm['score'];
        }
    }
    
    return [
        'is_threat' => $totalScore >= $threshold,
        'total_score' => $totalScore,
        'matches' => $results
    ];
}
```

#### Server Algorithm Updates
Algorithms are synced from server via:
- `Database::syncDetectionAlgorithm()` - Update/insert algorithms
- `Database::deleteDetectionAlgorithm()` - Remove obsolete algorithms
- Server pushes updates with `server_id` for tracking

## API Integration

### Current Implementation (GET - NEEDS CHANGE TO POST)
```php
$apiResult = $apiClient->analyzeSpam($fromEmail, $body, $headers, $options);
```

**CRITICAL ISSUE**: Large HTML emails cause URL length limits with GET requests.

### Required Change to POST
The API calls need to be converted from GET to POST to handle large email content:

```php
// Current problematic GET approach
$url = $endpoint . '?' . http_build_query($params); // Fails with large content

// Required POST approach  
$data = [
    'from_email' => $fromEmail,
    'body' => $body, // Can be large HTML content
    'headers' => $headers,
    'threshold' => $threshold
];
// Send as POST body instead of URL parameters
```

### API Endpoints
- **Login**: `POST /api/auth/v1/login`
- **Spam Analysis**: `GET /api/security/v1/analyze-spam` (NEEDS TO BE POST)
- **Report Spam**: `POST /api/security/v1/report-spam`

## Server Algorithm Updates

### Update Mechanism
The server sends algorithm updates via API responses containing:

1. **Pattern Updates**: New spam patterns to detect
2. **Threshold Adjustments**: Dynamic scoring thresholds
3. **Whitelist/Blacklist Updates**: Domain and IP reputation changes
4. **Rule Engine Updates**: New detection logic

### Update Storage
Updates are stored in local database tables:
- `algorithm_patterns` - Detection patterns
- `algorithm_thresholds` - Scoring thresholds  
- `algorithm_rules` - Logic rules
- `reputation_data` - IP/domain reputation

## Database Tables

### Core Tables

#### `spam_hashes`
```sql
CREATE TABLE spam_hashes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    content_hash VARCHAR(64) UNIQUE,
    is_spam BOOLEAN,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

#### `algorithm_patterns`
```sql
CREATE TABLE algorithm_patterns (
    id INT PRIMARY KEY AUTO_INCREMENT,
    category_id INT,
    pattern_type ENUM('subject', 'body', 'header'),
    pattern_value TEXT,
    weight DECIMAL(3,2),
    active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP
);
```

#### `algorithm_thresholds`
```sql
CREATE TABLE algorithm_thresholds (
    id INT PRIMARY KEY AUTO_INCREMENT,
    category_id INT,
    threshold_name VARCHAR(50),
    threshold_value DECIMAL(5,2),
    updated_at TIMESTAMP
);
```

#### `reputation_data`
```sql
CREATE TABLE reputation_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
    type ENUM('ip', 'domain', 'email'),
    value VARCHAR(255),
    reputation_score INT,
    category ENUM('whitelist', 'blacklist', 'greylist'),
    updated_at TIMESTAMP
);
```

#### `task_queue`
```sql
CREATE TABLE task_queue (
    id VARCHAR(50) PRIMARY KEY,
    task_type VARCHAR(50),
    task_data JSON,
    status ENUM('pending', 'processing', 'completed', 'failed'),
    created_at TIMESTAMP,
    processed_at TIMESTAMP
);
```

## How the System Works

### Email Processing Flow
1. **Postfix Integration**: Email received via content filter
2. **Hash Check**: Quick lookup for known spam/clean patterns
3. **Local Filter**: Run through local algorithms
4. **API Check**: If local filter passes, check with cloud API
5. **Decision**: Spam/Clean determination
6. **Action**: Quarantine, bounce, or deliver based on config

### Configuration Files
- `config.json` - Main system configuration
- `postfix/master.cf` - Postfix integration settings
- Database connection settings

### Key Configuration Options
```json
{
  "postfix": {
    "spam_handling": {
      "hash_detection": true,
      "threshold": 70,
      "action": "quarantine",
      "quarantine_folder": "Spambox"
    }
  },
  "api": {
    "check_spam_against_server": true,
    "spam_threshold": 70,
    "credentials": {
      "email": "info@cyfordtechnologies.com",
      "password": "..."
    }
  }
}
```

## Current Algorithm Status

### ✅ IMPLEMENTED FEATURES
- **Database-Driven**: All algorithms stored in SQLite database
- **Server Sync**: Algorithms can be updated from remote server
- **Multi-Category**: Supports spam, phishing, malware detection
- **Flexible Targeting**: Can target subject, body, headers, or combinations
- **Scoring System**: Weighted threat scoring with configurable thresholds
- **Caching**: Algorithm caching for performance

### ❌ CURRENT LIMITATIONS
- **No Active Algorithms**: Database may be empty (need to populate)
- **No Learning**: Static pattern matching only
- **Limited Detection Types**: Basic keyword/regex matching
- **No Bayesian**: No statistical analysis
- **No ML**: No machine learning classification

### 🔧 ALGORITHM POPULATION NEEDED
The database table `detection_algorithms` needs to be populated with actual detection patterns.

**Example Algorithm Entries:**
```sql
INSERT INTO detection_algorithms (name, threat_category, detection_type, target, pattern, score, enabled, priority) VALUES
('Generic Subject Spam', 'spam', 'keyword', 'subject', 'urgent', 25, 1, 1),
('Suspicious Body Pattern', 'spam', 'regex', 'body', '/(no inquiryso resolve)/i', 50, 1, 2),
('Malicious Domain', 'spam', 'domain', 'body', 'ebikrat.run', 75, 1, 3);
```

## Critical Issues for Next AI

### 1. POPULATE ALGORITHM DATABASE
**Priority: CRITICAL**
- Database table `detection_algorithms` exists but may be empty
- Need to populate with actual spam detection patterns
- Current system has no active algorithms to execute

### 2. GET to POST Conversion
**Priority: HIGH**
- Current API calls use GET with large email content in URL
- Causes server errors with HTML emails
- Must convert to POST with JSON body

### 3. Algorithm Update Sync
- Server sync mechanism exists (`syncDetectionAlgorithm`)
- Need to implement server-side algorithm management
- Implement update versioning system

### 3. Performance Optimization
- Hash detection for quick filtering
- Local algorithms run first
- API only called if needed

### 4. Error Handling
- Retry logic for API failures
- Fallback to local-only filtering
- Task queue for background processing

## File Locations
- Main entry: `/usr/local/share/cyford/security/index.php`
- Classes: `/usr/local/share/cyford/security/src/Classes/`
- Config: `/usr/local/share/cyford/security/config.json`
- Logs: `/var/log/cyford-security/`
- Database: SQLite at `/usr/local/share/cyford/security/data/security.db`

## Next Steps
1. Convert API calls from GET to POST
2. Implement algorithm update mechanism
3. Optimize hash detection performance
4. Add comprehensive error handling
5. Implement real-time algorithm updates from server