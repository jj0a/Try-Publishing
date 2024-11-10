<?php 

include 'connect.php';

if(isset($_POST['signUp'])){
    $name = $_POST['name'];
    $email = $_POST['email'];
    $password = $_POST['password'];
    $password = md5($password);

    $checkEmail = "SELECT * FROM register_user WHERE email = ?";
    $stmt = $conn->prepare($checkEmail);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if($result->num_rows > 0){
        echo "Email Address Already Exists!";
    } else {
        $stmt = $conn->prepare("INSERT INTO register_user (name, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $name, $email, $password);

        // Check if the statement executed successfully
        if($stmt->execute()){
            header("Location: CafeLogin.php");
            exit(); // Always exit after a header redirect
        } else {
            echo "Error: " . $stmt->error; // Use $stmt for errors
        }
    }
}

// Login connection
if(isset($_POST['signIn'])){
   $email = $_POST['email'];
   $password = $_POST['password'];
   $password = md5($password);

   // Prepare the SQL statement
   $stmt = $conn->prepare("SELECT * FROM register_user WHERE email = ? AND password = ?");
   $stmt->bind_param("ss", $email, $password);
   $stmt->execute();
   $result = $stmt->get_result(); // Get the result of the query

   if($result->num_rows > 0){
       session_start();
       $row = $result->fetch_assoc();
       $_SESSION['email'] = $row['email'];
       header("Location: ../CafePractice.php");  // Or use an absolute path if preferred
       exit();
   } else {
       echo "Not Found, Incorrect Email or Password";
   }
}
?>
