<!DOCTYPE html>
<?php
//сделать проверку на разрешение доступа и log out 
	if ($_COOKIE['username'] == "")
		header("Location: login.php", true, 303);
	$username = $_COOKIE['username'];

	echo "hi, $username";
?>
<html>
<head>
	<meta charset="UTF-8">
</head>
<body>
<br/>
<a href = "login.php">
	Log out
</a>
</body>
</html>