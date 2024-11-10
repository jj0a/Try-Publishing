<?php
//Our header for download

header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="urComment.php"'); // Name of the file to be downloaded
header('Expires: 0');
header('Cache-Control: must-revalidate');
header('Pragma: public');

ob_clean();
flush();

// Output the content of the file
readfile('urComment.php'); // Path to the actual urComment.php file
exit;
?>
