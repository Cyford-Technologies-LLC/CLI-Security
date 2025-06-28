<?php
#!/usr/bin/env php
<?php

// Load configuration
$config = require __DIR__ . '/config.php';

echo "Setting up Cyford Security Database...\n";

try {
    // Create database outside chroot with proper permissions
    $database = new \Cyford\Security\Classes\Database($config);
    echo "✅ Database created successfully at: " . $config['database']['path'] . "\n";
    
    // Set proper permissions for Postfix user
    $dbPath = $config['database']['path'];
    $dbDir = dirname($dbPath);
    
    // Make sure postfix user can access the database
    exec("sudo chown postfix:postfix " . escapeshellarg($dbPath));
    exec("sudo chmod 664 " . escapeshellarg($dbPath));
    exec("sudo chown postfix:postfix " . escapeshellarg($dbDir));
    exec("sudo chmod 755 " . escapeshellarg($dbDir));
    
    echo "✅ Database permissions set for Postfix user\n";
    
    // Test database functionality
    $database->setCache('test_key', 'test_value', 60);
    $testValue = $database->getCache('test_key');
    
    if ($testValue === 'test_value') {
        echo "✅ Database functionality test passed\n";
    } else {
        echo "❌ Database functionality test failed\n";
    }
    
    echo "\n🎉 Database setup complete! You can now enable hash_detection in config.php\n";
    
} catch (Exception $e) {
    echo "❌ Database setup failed: " . $e->getMessage() . "\n";
    exit(1);
}