# HTTP аутентификация

## Задание

Спроектировать и разработать систему авторизации пользователей на протоколе HTTP

**1. [Пользовательский интерфейс](https://www.figma.com/file/jfshw1Isat8ymfdXXgeAdc/Lab_1?node-id=0%3A1)**

**2. Пользовательские сценарии работы**

1. [Страница авторизации]()
2. [Страница регистрации]()
3. [Профиль]()

**3. API сервера и хореография**

**4. Структура базы данных**

```
id user_name secret_word login email pass expire_pass
```
```
id: INT, NOT NULL, UNIQUE, PRIMARY KEY, AUTO_INCREMENT
(уникальный идентификатор пользователя)
user_name: VARCHAR(100), NOT NULL;
(имя|фамилия пользователя)
secret_word: VARCHAR(32), NOT NULL;
(хешированное секретное слово для восстановления пароля)
login: VARCHAR(100), NOT NULL;
(логин)
email: VARCHAR(100), NOT NULL;
(почта)
pass: VARCHAR(60), NOT NULL;
(хешированный пароль)
expire_pass: INT, NOT NULL.
(срок действия пароля)
```
**4. Алгоритмы**

**4. Пример HTTP запросов/ответов**


### GET

URL-адрес запроса: [http://site/](http://site/)
Метод запроса: GET
Код состояния: 200 OK
Удаленный адрес: 127.0.0.1:

**Запрос:**
_GET / HTTP/1.
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8,application/signed-
exchange;v=b3;q=0.
Accept-Encoding: gzip, deflate
Accept-Language: ru,en;q=0.9,en-GB;q=0.8,en-US;q=0.
Cache-Control: no-cache
Connection: keep-alive
Cookie: PHPSESSID=ioqb1nl8g2d6io3tqc0erdvn4s1agme
Host: site
Pragma: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343._

**Ответ:**
_HTTP/1.1 200 OK
Date: Wed, 05 Oct 2022 17:14:19 GMT
Server: Apache
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 839
Keep-Alive: timeout=120, max=
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-_

**POST**

URL-адрес запроса: [http://site/php/sign_in.php](http://site/php/sign_in.php)
Метод запроса: POST
Код состояния: 302 Found
Удаленный адрес: 127.0.0.1:

**Запрос:**
_POST /php/sign_in.php HTTP/1.
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8,application/signed-
exchange;v=b3;q=0.
Accept-Encoding: gzip, deflate_


_Accept-Language: ru,en;q=0.9,en-GB;q=0.8,en-US;q=0.
Cache-Control: no-cache
Connection: keep-alive
Content-Length: 22
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=fbku0r0gso1stqmb64rjcfig987c7vkk
Host: site
Origin: [http://site](http://site)
Pragma: no-cache
Referer: [http://site/index.php](http://site/index.php)
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343._

**Ответ:**
_HTTP/1.1 302 Found
Date: Wed, 05 Oct 2022 17:21:30 GMT
Server: Apache
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: ../index.php
Content-Length: 0
Keep-Alive: timeout=120, max=
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-_

### GET

URL-адрес запроса: [http://site/register.php](http://site/register.php)
Метод запроса: GET
Код состояния: 200 OK
Удаленный адрес: 127.0.0.1:

**Запрос:**
_GET /register.php HTTP/1.
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8,application/signed-
exchange;v=b3;q=0.
Accept-Encoding: gzip, deflate
Accept-Language: ru,en;q=0.9,en-GB;q=0.8,en-US;q=0.
Cache-Control: no-cache
Connection: keep-alive
Cookie: PHPSESSID=ioqb1nl8g2d6io3tqc0erdvn4s1agme
Host: site
Pragma: no-cache_


_Referer: [http://site/](http://site/)
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343._

**Ответ:**
_HTTP/1.1 200 OK
Date: Wed, 05 Oct 2022 17:18:21 GMT
Server: Apache
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: PHPSESSID=ioqb1nl8g2d6io3tqc0erdvn4s1agme6; expires=Wed, 05-Oct-2022 17:20:21 GMT; Max-
Age=120; path=/
Content-Length: 1255
Keep-Alive: timeout=120, max=
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-_

**POST**

URL-адрес запроса: [http://site/php/sign_up.php](http://site/php/sign_up.php)
Метод запроса: POST
Код состояния: 302 Found
Удаленный адрес: 127.0.0.1:

**Запрос:**
_POST /php/sign_up.php HTTP/1.
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8,application/signed-
exchange;v=b3;q=0.
Accept-Encoding: gzip, deflate
Accept-Language: ru,en;q=0.9,en-GB;q=0.8,en-US;q=0.
Cache-Control: no-cache
Connection: keep-alive
Content-Length: 49
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=fbku0r0gso1stqmb64rjcfig987c7vkk
Host: site
Origin: [http://site](http://site)
Pragma: no-cache
Referer: [http://site/register.php](http://site/register.php)
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343._

**Ответ:**
_HTTP/1.1 302 Found_


_Date: Wed, 05 Oct 2022 17:28:51 GMT
Server: Apache
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: ../register.php
Content-Length: 0
Keep-Alive: timeout=120, max=
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-_

### GET

URL-адрес запроса: [http://site/recover.php](http://site/recover.php)
Метод запроса: GET
Код состояния: 200 OK
Удаленный адрес: 127.0.0.1:

**Запрос:**
_GET /recover.php HTTP/1.
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8,application/signed-
exchange;v=b3;q=0.
Accept-Encoding: gzip, deflate
Accept-Language: ru,en;q=0.9,en-GB;q=0.8,en-US;q=0.
Cache-Control: no-cache
Connection: keep-alive
Cookie: PHPSESSID=ioqb1nl8g2d6io3tqc0erdvn4s1agme
Host: site
Pragma: no-cache
Referer: [http://site/index.php](http://site/index.php)
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343._

**Ответ:**
_HTTP/1.1 200 OK
Date: Wed, 05 Oct 2022 17:20:02 GMT
Server: Apache
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 889
Keep-Alive: timeout=120, max=
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-_


### GET

URL-адрес запроса: [http://site/profile.php](http://site/profile.php)
Метод запроса: GET
Код состояния: 200 OK
Удаленный адрес: 127.0.0.1:

**Запрос:**
_GET /profile.php HTTP/1.
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8,application/signed-
exchange;v=b3;q=0.
Accept-Encoding: gzip, deflate
Accept-Language: ru,en;q=0.9,en-GB;q=0.8,en-US;q=0.
Cache-Control: no-cache
Connection: keep-alive
Cookie: PHPSESSID=cudt2ergtqvfjqd938gb7ftbe4lp68u
Host: site
Pragma: no-cache
Referer: [http://site/index.php](http://site/index.php)
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343._

**Ответ:**
_HTTP/1.1 200 OK
Date: Wed, 05 Oct 2022 17:32:12 GMT
Server: Apache
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: PHPSESSID=cudt2ergtqvfjqd938gb7ftbe4lp68u0; expires=Wed, 05-Oct-2022 18:32:12 GMT; Max-
Age=3600; path=/
Content-Length: 1267
Keep-Alive: timeout=120, max=
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-_

**4. Значимые фрагменты кода (исходный код)**

Проверка на существование пользователя в базе данных при входе (index.php)

```
if (password_verify($pass, $pass_hash)) {
$cur_time = time();
$expire_pass = mysqli_fetch_assoc(mysqli_query($conn, "SELECT `expire_pass`
FROM `users`WHERE `login` = '$login'"))['expire_pass'];
if ($cur_time > $expire_pass) {
```

```
$_SESSION['login'] = $login;
$_SESSION['expire'] = "The password has expired!";
header('Location: ../recover.php');
exit();
}
if($check_user = mysqli_query($conn, "SELECT * FROM `users` WHERE `login` =
'$login'")) {
$user = mysqli_fetch_assoc($check_user);
$_SESSION['user'] = [
"user_name" => $user['user_name'],
"email" => $user['email'],
"auth" => true
];
header('Location: ../profile.php');
$conn->close();
exit();
}
else {
$_SESSION['error'] = "An error has occurred...";
header('Location: ../index.php');
exit();
}
}
else {
$_SESSION['error'] = "Incorrect login or password!";
header('Location: ../index.php');
}
```
Валидация полей при регистрации + проверка на уникальность логина (register.php)

```
$login = mysqli_real_escape_string($conn, $login);
$check_user = mysqli_query($conn, "SELECT * FROM `users` WHERE `login` =
'$login'");
if (mysqli_num_rows($check_user) > 0 ) {
$_SESSION['error'] = "This login is already in use!";
header('Location: ../register.php');
exit();
}
else if (!$login || !$email || !$pass || !$pass_conf || !$secret) {
$_SESSION['error'] = "Check the fields!";
header('Location: ../register.php');
exit();
}
else if (!check_email($email)) {
header('Location: ../register.php');
exit();
}
else if (!check_pass($pass)) {
header('Location: ../register.php');
exit();
}
else if ($pass != $pass_conf) {
```

```
$_SESSION['error'] = "Passwords do not match!";
header('Location: ../register.php');
exit();
}
```
Хеширование пароля/секретного слова, установка срока действия пароля, экранирование SQL-запроса

```
$pass = password_hash($pass, PASSWORD_BCRYPT);
$expire_pass = time() + 3600 * 168 ;
$secret = md5($secret."salt159242");
$user_name = mysqli_real_escape_string($conn, $user_name);
$email = mysqli_real_escape_string($conn, $email);
```
Функции для валидации пароля и почты

```
function check_pass($val) {
if (strlen($val) < 8 ) {
$_SESSION['error'] = "Password less than 8 characters!";
return false;
}
else if (!preg_match("#[0-9]+#", $val)) {
$_SESSION['error'] = "Password must include at least one number!";
return false;
}
else if (!preg_match("#[a-zA-Z]+#", $val)) {
$_SESSION['error'] = "Password must include at least one letter!";
return false;
}
return true;
}
```
```
function check_email($val) {
if (!filter_var($val, FILTER_VALIDATE_EMAIL)) {
$_SESSION['error'] = "Incorrect e-mail!";
return false;
}
return true;
}
```
Функция для сообщения пользователю о результате его действий

```
function message() {
if (isset($_SESSION['error'])) {
echo '<p class="error_msg"> '. $_SESSION['error']. '</p>';
unset($_SESSION['error']);
}
else if (isset($_SESSION['success'])) {
```

```
echo '<p class="success_msg"> '. $_SESSION['success']. '</p>';
unset($_SESSION['success']);
}
else if (isset($_SESSION['expire'])) {
echo '<p class="error_msg"> '. $_SESSION['expire']. '</p>';
}
}
```
Защита от прямого перехода к запрещенным файлам

```
if (isset($_SERVER['HTTP_REFERER']) != "http://site/...php") {
http_response_code( 403 );
exit();
}
```

