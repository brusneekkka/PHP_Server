<?php
	$login = $_GET['user'];
	$pass = $_GET['pass'];
	//сделать обработку на допустимость лог пароля и вывод ошибки
	$linkbaza = mysqli_connect('localhost', 'root', 'root', 'baza');
	if ($linkbaza == false)
		echo mysqli_connect_error();
	mysqli_set_charset($linkbaza, "utf8");
	$pass = md5($pass);
	$sql = "SELECT pass FROM users WHERE user='$login'";
	$res = mysqli_query($linkbaza, $sql);
	$hashpass = mysqli_fetch_array($res);
	if (!strcmp($hashpass['pass'], $pass))
	{
		mysqli_close($linkbaza);
		setcookie("username", $login, time() + 30);
		header("Location: hi.php", true, 303);
	}else{
		mysqli_close($linkbaza);
		setcookie('name', '');
		setcookie("message", "Неверный логин или пароль", time() + 30);
		header("Location: login.php", true, 303);
	}
?>