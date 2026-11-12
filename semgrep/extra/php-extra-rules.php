<?php
// Pruebas unitarias de las reglas extra (semgrep --test).

// ---------- 15. Path traversal ----------
$file = $_GET["page"];
// ruleid: php-path-traversal
$fp = fopen($file, "r");
// ruleid: php-path-traversal
show_file($file);
// ok: php-path-traversal
$fp = fopen("documents/" . basename($file), "r");
// ok: php-path-traversal
readfile("message.txt");

// ---------- 16. Unrestricted file upload ----------
$dir = $_REQUEST["uploadDir"];
$name = $_FILES["file"]["name"];
// ruleid: php-unrestricted-file-upload
@move_uploaded_file($_FILES["file"]["tmp_name"], $dir . "/" . $name);
// ruleid: php-unrestricted-file-upload
move_uploaded_file($_FILES["file"]["tmp_name"], "images/" . $_FILES["file"]["name"]);
// ok: php-unrestricted-file-upload
move_uploaded_file($_FILES["file"]["tmp_name"], "/srv/uploads/" . uniqid() . ".jpg");
