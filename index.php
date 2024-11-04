<?php

/*=============================================
Mostrar errores
=============================================*/

ini_set('display_errors', 1);
ini_set("log_errors", 1);
ini_set("error_log", "D:/xampp/htdocs/apirest-dinamica/php_error_log");

/*=============================================
CORS
=============================================*/

header('Access-Control-Allow-Origin: *');
header("Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept");
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Credentials:true');
header('content-type: application/json; charset=utf-8');


if ($_SERVER ['REQUEST_METHOD']== 'OPTIONS'){
    http_response_code(200);
    exit();
} 
/*=============================================
Requerimientos
=============================================*/

require_once "controllers/routes.controller.php";

$index = new RoutesController();
$index->index();