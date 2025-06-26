<?php
// Ensure this test script is executed with appropriate system user permissions.

function testPostfixPickupWrite($pickupFilePath, $emailData)
{
    echo "Testing Postfix Pickup Write as PHP user...\n";
    echo exec('whoami');


    try {
        // Attempt to write to the specified pickup file
        $result = file_put_contents($pickupFilePath, $emailData);

        if ($result === false) {
            throw new RuntimeException("Failed to write email data to {$pickupFilePath}");
        }

        // Set permissions for the file
        chmod($pickupFilePath, 0644);

        echo "Email successfully written to Postfix pickup file: {$pickupFilePath}\n";
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
    }
}

// Simulate email data
$emailData = "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test Email\r\n\r\nThis is a test email.";

// Unique ID for the test pickup file
$queueId = uniqid('test_', true);
$pickupFilePath = "/var/spool/postfix/pickup/{$queueId}";

// Run the test
testPostfixPickupWrite($pickupFilePath, $emailData);