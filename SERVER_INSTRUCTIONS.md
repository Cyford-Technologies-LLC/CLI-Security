# SERVER INSTRUCTIONS

## 1. Weighted Hash Reputation System

**Hash Generation Code (IDENTICAL ON CLIENT AND SERVER):**

```php
function generateHash($subject, $body, $version = 1) {
    // Load keys
    $primaryKey = trim(file_get_contents('/etc/cyford-security/keys/primary.key'));
    $secondaryKey = trim(file_get_contents('/etc/cyford-security/keys/secondary.key'));
    
    // Clean content
    $cleanSubject = trim(strtolower($subject));
    $cleanBody = trim(preg_replace('/\s+/', ' ', strip_tags($body)));
    
    // Version 1 hash algorithm
    if ($version == 1) {
        $step1 = hash_hmac('sha256', $cleanSubject . '|' . $cleanBody, $primaryKey);
        $step2 = hash_hmac('sha256', $step1, $secondaryKey);
        $step3 = hash_hmac('sha256', $step2, date('Y-m-d'));
        return $step3;
    }
    
    // Future versions can be added here
    throw new Exception("Unsupported hash version: $version");
}
```

**Version Compatibility:**
- Current version: 1
- Server must accept hashes from different client versions
- Server can convert between hash versions if needed

**Example:**
```
Input: Subject="URGENT" Body="<p>Click here</p>"
Clean: subject="urgent" body="Click here"
Step1: hash_hmac('sha256', "urgent|Click here", primary_key)
Step2: hash_hmac('sha256', step1_result, secondary_key)
Step3: hash_hmac('sha256', step2_result, "2025-01-03")
Result: 64-character hex string
```

**Data Client Sends:**
```json
{
    "client_id": "64-char-unique-id",
    "content_hash": "generated-hash",
    "hash_version": 1,
    "classification": "spam" or "clean",
    "scope": "account" or "client"
}
```

**Data Server Returns:**
```json
{
    "accepted": true,
    "personal_updated": true,
    "global_consensus": "spam",
    "confidence_level": 67
}
```

**Voting System:**
- If 1 admin says something, it takes 10 regular users to change it globally
- Admin votes have 10x weight of regular users
- Check user's admin status in existing user account system

## 2. Client ID System

**Client Requests ID:**
```json
POST /api/security/v1/generate-client-id
{
    "hostname": "mail.example.com"
}
```

**Server Returns:**
```json
{
    "client_id": "64-character-random-string",
    "expires": null
}
```

**Requirements:**
- Generate 64-character unique ID per client installation
- No client can connect without valid ID
- Client stores ID locally and sends in all requests

## 3. Threat Algorithm Updater

**Client Requests Updates:**
```json
POST /api/security/v1/sync-algorithms
{
    "client_version": 15,
    "categories": ["spam", "phishing", "malware", "virus"]
}
```

**Server Returns:**
```json
{
    "algorithms": [
        {
            "id": 123,
            "name": "Suspicious Subject",
            "category": "spam",
            "detection_type": "keyword",
            "target": "subject",
            "pattern": "urgent",
            "score": 25,
            "enabled": true
        }
    ],
    "deleted_ids": [45, 67],
    "latest_version": 16
}
```

## 4. Spam/Clean Marking API

**Client Marks Hash:**
```json
POST /api/security/v1/mark-hash
{
    "client_id": "64-char-id",
    "content_hash": "hash-value",
    "classification": "spam" or "clean",
    "scope": "account",
    "reason": "False positive"
}
```

**Server Returns:**
```json
{
    "marked": true,
    "scope_applied": "account",
    "global_impact": false
}
```

## Current Client Database Tables

**Client already has these tables:**
- `spam_log` - Spam email logging
- `email_stats` - Daily email statistics
- `ip_reputation` - IP reputation tracking
- `spam_hashes` - Hash-based spam detection
- `cache` - General caching
- `detection_algorithms` - Algorithm storage (currently empty)

**Client has detection_algorithms table with existing threat detection rules.**

**Detection Algorithm Execution:**

1. **Load all enabled algorithms for category**
2. **For each algorithm:**
   - Get target content (subject, body, headers, etc.)
   - Execute detection type logic
   - If match found, add score to total
3. **Compare total score to threshold**
4. **Return threat classification and matched algorithms**

**Target Areas:**
- `subject` - Email subject line
- `body` - Email body content
- `from` - Sender information
- `headers` - All email headers

**Algorithm Logic Server Must Implement:**

**Keyword Detection:**
```
IF target_content CONTAINS pattern (case-insensitive)
THEN add score points
```

**Regex Detection:**
```
IF pattern MATCHES target_content
THEN add score points
```

**Domain Detection:**
```
FIND all URLs in target_content
FOR each URL domain
  IF domain CONTAINS pattern
  THEN add score points
```

**Header Check:**
```
IF email_headers CONTAINS pattern
THEN add score points
```

**URL Scan:**
```
FIND all URLs in target_content
FOR each URL
  IF URL CONTAINS pattern
  THEN add score points
```

**Scoring Logic:**
```
total_score = 0
FOR each algorithm WHERE enabled = true
  IF algorithm matches content
  THEN total_score += algorithm.score

IF total_score >= threshold
THEN classification = threat
ELSE classification = clean
```

**Current Threat Detection Algorithms (from client):**

**SPAM CATEGORY:**
- 'hello' in subject (keyword, score: 10)
- 'hi' in subject (keyword, score: 10) 
- 'urgent' in subject (keyword, score: 15)
- 'no inquiryso resolve' in body (regex, score: 25)
- 'amounted old strictly' or 'timed blind' in body (regex, score: 20)

**PHISHING CATEGORY:**
- 'invoice' in subject/body (keyword, score: 15)
- 'payment' in subject/body (keyword, score: 15)
- 'click here' in body (keyword, score: 20)
- 'verify account' in body (keyword, score: 25)
- 'bit.ly' domain (domain, score: 20)
- 'tinyurl.com' domain (domain, score: 20)

**MALWARE CATEGORY:**
- 'optussnet.com.au' domain (domain, score: 50)
- 'emlmind.com' domain (domain, score: 50)

**Server Must Create These Exact Algorithms:**
```sql
INSERT INTO detection_algorithms (name, category, detection_type, target, pattern, score, enabled, priority) VALUES
('Suspicious Subject - Hello', 'spam', 'keyword', 'subject', 'hello', 10, 1, 1),
('Suspicious Subject - Hi', 'spam', 'keyword', 'subject', 'hi', 10, 1, 1),
('Suspicious Subject - Urgent', 'spam', 'keyword', 'subject', 'urgent', 15, 1, 1),
('Spam Pattern - No Inquiry', 'spam', 'regex', 'body', '/(\\bno inquiryso resolve\\b)/i', 25, 1, 2),
('Spam Pattern - Amounted Old', 'spam', 'regex', 'body', '/\\b(amounted old strictly|timed blind)\\b/i', 20, 1, 2),
('Phishing Keyword - Invoice', 'phishing', 'keyword', 'subject,body', 'invoice', 15, 1, 1),
('Phishing Keyword - Payment', 'phishing', 'keyword', 'subject,body', 'payment', 15, 1, 1),
('Phishing Keyword - Click Here', 'phishing', 'keyword', 'body', 'click here', 20, 1, 1),
('Phishing Keyword - Verify Account', 'phishing', 'keyword', 'body', 'verify account', 25, 1, 1),
('Suspicious Domain - bit.ly', 'phishing', 'domain', 'body', 'bit.ly', 20, 1, 2),
('Suspicious Domain - tinyurl', 'phishing', 'domain', 'body', 'tinyurl.com', 20, 1, 2),
('Malicious Domain - optussnet', 'malware', 'domain', 'body', 'optussnet.com.au', 50, 1, 3),
('Malicious Domain - emlmind', 'malware', 'domain', 'body', 'emlmind.com', 50, 1, 3);
```

**Threat Category Thresholds:**
- Spam: 70 points
- Phishing: 50 points
- Malware: 75 points
- Virus: 80 points

## Database Tables Server Needs

```sql
-- Client ID tracking
CREATE TABLE client_ids (
    client_id TEXT PRIMARY KEY,
    account_email TEXT NOT NULL,
    hostname TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Hash markings (spam/clean)
CREATE TABLE hash_markings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content_hash TEXT NOT NULL,
    hash_version INTEGER DEFAULT 1,
    client_id TEXT NOT NULL,
    account_email TEXT NOT NULL,
    classification TEXT NOT NULL,
    scope TEXT DEFAULT 'account',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Detection algorithms
CREATE TABLE detection_algorithms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    detection_type TEXT NOT NULL,
    target TEXT NOT NULL,
    pattern TEXT NOT NULL,
    score INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT 1,
    version INTEGER DEFAULT 1
);
```

## API Endpoints Required

1. `POST /api/security/v1/generate-client-id` - Generate client ID
2. `POST /api/security/v1/mark-hash` - Mark hash as spam/clean
3. `POST /api/security/v1/sync-algorithms` - Get algorithm updates

## Security Requirements

- All requests require valid Bearer token (existing auth)
- All requests require valid client ID header
- Hash algorithm must be IDENTICAL on client and server
- Same key files must exist on both systems
- Daily salt ensures hash changes each day
- Account reputation prevents abuse
- Personal filtering takes effect immediately
- Global consensus requires weighted votes