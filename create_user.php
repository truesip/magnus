<?php

// MagnusBilling API Configuration
$apiKey = 'nmdkjfn78yirhnzscewury87eka83hs';
$apiSecret = 'hkbduf6riw3yei3yr78q2wjhs828q7';
$magnusBillingUrl = 'https://sip.dialerone.net/panel/mbilling/api';

// User data to create
$userData = [
    'username' => 'newuser',
    'password' => 'SecurePass123!',
    'id_group' => 3,
    'id_plan' => 1,
    'firstname' => 'John',
    'lastname' => 'Doe',
    'email' => 'newuser@example.com',
    'phone' => '1234567890'
];

// Prepare the request
$endpoint = $magnusBillingUrl . '/user';
$timestamp = time();

// Create signature (adjust based on MagnusBilling's authentication method)
$signature = hash_hmac('sha256', $apiKey . $timestamp, $apiSecret);

// Initialize cURL
$ch = curl_init($endpoint);

// Set cURL options
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($userData));
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json',
    'X-API-KEY: ' . $apiKey,
    'X-API-SECRET: ' . $apiSecret,
    'X-Signature: ' . $signature,
    'X-Timestamp: ' . $timestamp
]);

// Execute request
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error = curl_error($ch);

curl_close($ch);

// Handle response
if ($error) {
    echo "cURL Error: " . $error . "\n";
    exit(1);
}

echo "HTTP Status Code: " . $httpCode . "\n";
echo "Response:\n";
echo $response . "\n";

$result = json_decode($response);

if ($httpCode >= 200 && $httpCode < 300 && $result) {
    if (isset($result->status) && $result->status === 'success') {
        echo "\n✓ User created successfully!\n";
        if (isset($result->data)) {
            echo "Username: " . ($result->data->username ?? 'N/A') . "\n";
            echo "User ID: " . ($result->data->id ?? 'N/A') . "\n";
        }
    } else {
        echo "\n✗ Error creating user: " . ($result->message ?? 'Unknown error') . "\n";
    }
} else {
    echo "\n✗ Request failed with HTTP code: " . $httpCode . "\n";
}

?>
