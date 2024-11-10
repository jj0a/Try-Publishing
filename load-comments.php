<?php
include('dbh.inc.php');  //Connect the database again

//This is trigger everytime na click natin yung button. dito nag papadala ng request
$commentNewCount = $_POST['commentNewCount']; // Get the number of comments already loaded

// Fetch next 2 comments starting from the last loaded comment (OFFSET: Defines how many rows to skip before starting to return rows.)
$sql = "SELECT * FROM comments LIMIT 2 OFFSET $commentNewCount";  //Meaning this part, select comments limit 2 starting from the number of commentNewCount
$result = mysqli_query($conn, $sql);


//Next, same process lang we check and output it. meaning kapag na click na ni user ang button ito na yung nag echo ng data
if (mysqli_num_rows($result) > 0) {                            
    while ($row = mysqli_fetch_assoc($result)) {
        // Display new comments
        echo '<div class="comment-box">';
        echo '<strong>' . $row['author'] . '</strong><br>';
        echo '<p>' . $row['message'] . '</p>';
        echo '</div>';
    }
} else {
    // If there are no more comments, send a message
   // echo '<div class="notify" style="color:red; display:flex; justify-content:center;">';
    echo "No more comments to load.";
    //echo '</div>';
}
?>
