<?php
// Pruebas unitarias del ruleset (semgrep --test).
// "ruleid:" = la línea siguiente DEBE ser detectada.
// "ok:"     = la línea siguiente NO debe ser detectada (código corregido).

// ---------- 1. SQLi ----------
$title = $_GET["title"];
$sql = "SELECT * FROM movies WHERE title LIKE '%" . $title . "%'";
// ruleid: php-sql-injection
$recordset = mysql_query($sql, $link);
$id = intval($_GET["id"]);
// ok: php-sql-injection
$r = mysqli_query($link, "SELECT * FROM movies WHERE id = " . $id);
$stmt = $mysqli->prepare("SELECT * FROM movies WHERE title LIKE ?");
// ok: php-sql-injection
$stmt->bind_param("s", $title);

// ---------- 2. Command injection ----------
$target = $_POST["target"];
// ruleid: php-command-injection
$out = shell_exec("nslookup " . $target);
// ok: php-command-injection
$out = shell_exec("nslookup " . escapeshellarg($target));

// ---------- 3. eval ----------
// ruleid: php-code-injection-eval
@eval($_REQUEST["eval"]);
// ok: php-code-injection-eval
eval("return 1;");

// ---------- 4. XSS reflejado ----------
$firstname = $_GET["firstname"];
// ruleid: php-reflected-xss
echo "Welcome " . $firstname;
// ok: php-reflected-xss
echo "Welcome " . htmlspecialchars($firstname, ENT_QUOTES, "UTF-8");

// ---------- 5. LFI / RFI ----------
$language = $_GET["language"];
// ruleid: php-file-inclusion
include($language);
// ok: php-file-inclusion
include("lang_en.php");

// ---------- 6. LDAP ----------
$user = $_POST["user"];
$filter = "(sAMAccountName=" . $user . ")";
// ruleid: php-ldap-injection
$sr = ldap_search($ds, $dn, $filter);
// ok: php-ldap-injection
$sr = ldap_search($ds, $dn, "(sAMAccountName=" . ldap_escape($user, "", LDAP_ESCAPE_FILTER) . ")");

// ---------- 7. Mail injection ----------
$email = $_POST["email"];
// ruleid: php-mail-injection
$status = @mail($recipient, $subject, $content, "From: $email");
// ok: php-mail-injection
$status = mail("admin@example.com", "Asunto", "Texto fijo");

// ---------- 8. Open redirect ----------
// ruleid: php-open-redirect
header("Location: " . $_GET["url"]);
// ok: php-open-redirect
header("Location: portal.php");

// ---------- 9. Hash débil ----------
// ruleid: php-weak-hash
$h = md5($password);
// ruleid: php-weak-hash
$h = hash("sha1", $password);
// ok: php-weak-hash
$h = password_hash($password, PASSWORD_DEFAULT);

// ---------- 10. Cripto débil ----------
// ruleid: php-weak-crypto
$secret = base64_encode($secret);
// ruleid: php-weak-crypto
$c = openssl_encrypt($data, "des-ecb", $key);
// ok: php-weak-crypto
$c = openssl_encrypt($data, "aes-256-gcm", $key, 0, $iv, $tag);

// ---------- 11. Deserialización ----------
// ruleid: php-insecure-deserialization
$obj = unserialize($_COOKIE["data"]);
// ok: php-insecure-deserialization
$obj = unserialize($raw, ["allowed_classes" => false]);

// ---------- 12. extract ----------
// ruleid: php-extract-usage
extract($_POST);
// ok: php-extract-usage
extract($row, EXTR_SKIP);

// ---------- 13. Credenciales embebidas ----------
// ruleid: php-hardcoded-credentials
$db_password = "bug";
// ok: php-hardcoded-credentials
$db_password = "";
// ok: php-hardcoded-credentials
$db_password = getenv("DB_PASSWORD");

// ---------- 14. phpinfo ----------
// ruleid: php-phpinfo-exposure
phpinfo();
