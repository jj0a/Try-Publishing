<!--Our database connection-->
<?php
$severname = "localhost";
$dbusername = "root";
$dbpassword = "";
$dbName = "dbprofilewebsite";

$conn = mysqli_connect($severname, $dbusername, $dbpassword, $dbName);

if(!$conn){
    die("Connection failed: " .mysqli_connect_error());
}
