# TODO List - Code Cleanup & Features

## Database Cleanup (src/Classes/Database.php)

### Remove Unused Methods
- [ ] Remove `checkSpamHash()` - marked as DEPRECATED
- [ ] Remove `recordEmailHash()` - replaced by hash reputation system
- [ ] Remove `getSimilarSpam()` - not used
- [ ] Remove `markHashAsClean()` - replaced by hash marking API
- [ ] Remove `getBlockedSpamPatterns()` - only used in Internal.php
- [ ] Remove `getCleanEmailPatterns()` - not used
- [ ] Remove `searchSpamPatterns()` - not used
- [ ] Remove `getSpamPatternStats()` - only used in Internal.php
- [ ] Remove `removeSpamPattern()` - only used in Internal.php

### Remove Unused Tables
- [ ] Consider removing `spam_hashes` table - replaced by server hash system
- [ ] Consider removing `ip_reputation` table - not actively used
- [ ] Consider removing `email_stats` table - basic logging only

### Simplify Hash Methods
- [ ] Keep only `isKnownSpamHash()` and `isKnownCleanHash()` if still needed
- [ ] Or remove entirely if server handles all hash logic

### Clean Up Cache System
- [ ] Review if database cache is needed vs memory cache
- [ ] Simplify cache methods if possible

## Hash Algorithm Update

### Replace Current Hash System
- [ ] Current: Simple SHA256 hash in `isKnownSpamHash()` and `isKnownCleanHash()`
- [ ] Replace with: Secure 2-key HMAC system from SERVER_INSTRUCTIONS.md
- [ ] Update hash generation in Database.php methods

### New Hash Algorithm Implementation
- [ ] Add secure hash generation function to Database.php
- [ ] Load primary and secondary keys from `/etc/cyford-security/keys/`
- [ ] Implement 3-step HMAC process:
  - Step 1: HMAC-SHA256(subject|body, primary_key)
  - Step 2: HMAC-SHA256(step1, secondary_key)
  - Step 3: HMAC-SHA256(step2, date('Y-m-d'))

### Update Hash Methods
- [ ] Update `isKnownSpamHash()` to use new algorithm
- [ ] Update `isKnownCleanHash()` to use new algorithm
- [ ] Add version compatibility for old vs new hashes
- [ ] Consider migration strategy for existing hashes

### Key Management
- [ ] Ensure key files exist: `/etc/cyford-security/keys/primary.key`
- [ ] Ensure key files exist: `/etc/cyford-security/keys/secondary.key`
- [ ] Add error handling for missing key files
- [ ] Document key deployment process

## Client ID Implementation

### Add Client ID Management
- [ ] Add method to request client ID from server
- [ ] Add method to save client ID locally (config or database)
- [ ] Add method to load client ID for API requests
- [ ] Add client ID to all API requests

### Client ID Storage Options
- [ ] Option 1: Store in config.json file
- [ ] Option 2: Store in database cache table
- [ ] Option 3: Store in .env file

### API Client Updates
- [ ] Update ApiClient.php to include client ID in all requests
- [ ] Add X-Client-ID header to all API calls
- [ ] Handle client ID registration on first run

## Internal.php Cleanup

### Remove Migration Functions
- [ ] Remove `migrateExistingAlgorithms()` - not needed with pre-populated database
- [ ] Remove related migration commands

### Simplify Commands
- [ ] Remove spam pattern management commands (view, clear, search)
- [ ] Keep only essential commands for debugging

## SpamFilter.php Cleanup

### Consider Removal
- [ ] Evaluate if SpamFilter.php is still needed
- [ ] All logic moved to ThreatCategory classes
- [ ] May be completely obsolete

## Configuration Cleanup

### Remove Unused Config Options
- [ ] Remove old SpamFilter configuration options
- [ ] Remove hash detection config (if moving to server-only)
- [ ] Clean up postfix spam_handling config

## Priority Order

### High Priority
1. **Client ID Implementation** - Required for server communication
2. **Update Hash Algorithm** - Replace old simple hash with secure 2-key HMAC system
3. **Database Method Cleanup** - Remove deprecated/unused methods
4. **API Client Updates** - Add client ID to requests

### Medium Priority
5. **Table Cleanup** - Remove unused tables
6. **Internal.php Cleanup** - Remove migration functions
7. **Configuration Cleanup** - Remove obsolete options

### Low Priority
8. **SpamFilter.php Evaluation** - Determine if still needed
9. **Cache System Review** - Optimize if needed

## Notes

- Keep changes backward compatible during transition
- Test thoroughly after each cleanup phase
- Document any breaking changes
- Consider creating backup before major cleanups