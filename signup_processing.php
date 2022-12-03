<?php
	$login = $_GET['user'];
	$pass = $_GET['pass'];
	$linkbaza = mysqli_connect('localhost', 'root', 'root', 'baza');
	if ($linkbaza == false)
		echo mysqli_connect_error();
	mysqli_set_charset($linkbaza, "utf8");
	$pass = md5($pass);
	$logins = "SELECT user FROM users WHERE user='$login'";
	$res = mysqli_query($linkbaza, $logins);
	$flag = 0;
	echo($login);
	while ($row = mysqli_fetch_array($res)) 
	{
    	if ($row['user'] == $login)
    	{
    		$flag = 1;
    	}
	}
	if ($flag > 0)
	{
		setcookie("message", "Уже существует юзер с таким никнеймом", time() + 30);
    	header("Location: signup.php", true, 303);
	}
    else 
    {
    	$sql = "INSERT INTO users (user, pass) VALUES ('$login', '$pass')";
		$res = mysqli_query($linkbaza, $sql);
		mysqli_close($linkbaza);
		setcookie("username", $login, time() + 30);
		header("Location: hi.php", true, 303);		
   	}	
?>