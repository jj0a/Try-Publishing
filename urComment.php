<?php 
include('dbh.inc.php');    

session_start(); 

//Our session code starts here
if (isset($_SESSION['username'])) {
    $username = $_SESSION['username']; 
} else {
    $username = "Guest"; 
}
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.0/jquery.min.js"></script>
    <link rel="stylesheet" href="urComment.css">
    <title>Ur Comment</title>
<script>
    //AJAX with Jquery code starts here
$(document).ready(function() {
    var commentCount = 2; // Start with 2 comments initially

    //Diba may 2 comment na naka display then if we click the button this is the function that will work na
    //This method works everytime the button is click, it is to load more comments
    $("button.load-more").click(function() {
        $.post("load-comments.php", { commentNewCount: commentCount }, function(data) {   //Method: si $.post make an HTTP POST request to load-comments.php kasama ang bilang na ilang comments na daapt kunin and ang data (na maaaring bagong HTML ng comments) ay ipapasa sa callback function bilang data.
         
             // Hide the button if no more comments are returned
             if (data.trim() === "No more comments to load.") {
                $("button.load-more").hide(); // Hide the button when all comments are loaded
            }else{
                $(".box-content").append(data);     // Append new comments to the existing comments
                commentCount += 2;                  // Increase the count by 2 after loading new comments para sa paninagong request nanaman
                                                    /*Kapag ang user ay nag-click muli sa "Load More," ang commentCount ay magiging 4, at ang susunod na request ay 
                                                      magkakaroon ng commentNewCount na 4. 
                                                      Ito ay magiging basehan para sa server upang makuha ang susunod na set ng comments mula sa database, simula sa ika-4 na comment.
                                                      Para di paulit-ulit ang data te*/

            }
          
           
        });
    });
});
</script>
</head>
<body>

    <!-- Comment structure starts here -->
    <div class="popup-urComment" id="comments">
        <a href="ideaProfile.php">
            <div class="close-comment-btn">&times;</div>
        </a>
        <h1>🌷🌷🌷🌷🌷🌷</h1>
        <h2>Hello <?php echo htmlspecialchars($username); //To output the session?></h2>
        
        
        <div class="box-content">

            <!--Actually, this is what is going to be seen first in the comment box content-->
            <?php 
            $sql = "SELECT * FROM comments LIMIT 2";                      //Retrieve data from my database, only 2
            $result = mysqli_query($conn, $sql);                          //query for database connection and my sql variable

            if (mysqli_num_rows($result) > 0) {                           //if number of rows that is selected is greater than 0
                while ($row = mysqli_fetch_assoc($result)) {              //we use loop to fetch the result and put it muna ky $row variable
                    echo '<div class="comment-box">';          
                    echo '<strong>' . $row['author'] . '</strong><br>';   //Then we output the fetched author
                    echo '<p>' . $row['message'] . '</p>';                //And the fetched message
                    echo '</div>';
                }
            } else {
                echo "There are no comments!";
            }
            ?>
        </div>

        <div class="form-element-urComment">
            <button type="button" class="load-more">Load more comments</button>
            <a href="downloadFile.php">Download urComment.php?</a>
        </div>
        <h1>🌷🌷🌷🌷🌷🌷</h1>
    </div>
</body>
</html>

