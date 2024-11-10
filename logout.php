<?php
session_start(); // Start the session

// Destroy the session and unset cookies
session_unset();
session_destroy();

// Clear the username cookie by setting its expiration time to the past
if (isset($_COOKIE['username'])) {
    setcookie('username', '', time() - 3600, '/');
}

// Redirect to the home or login page (index.php)
header("Location: ../ideaProfile.php");
exit;
?>
