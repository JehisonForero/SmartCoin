<?php

require_once "models/Connection.php";
require_once "controllers/post.controller.php";

use Firebase\JWT\JWT;


 /* separa las propiedades del arreglo*/
 $colums=array();
 foreach(array_keys($_POST)as $key=>$values){
    array_push($colums, $values);
 }
 
 /* validamos las tablas y las columnas*/ 
 if(empty(Connection::getColumnsData($table, $colums))){
    $json = array(
        'result'=>400,
        'result'=>"Los nombres de los cmpos de la base de datos no coinciden"
    );
    echo json_encode($json,http_response_code($json["status"]));
    return;
 }
 $response = new PostController();

 /* peticion post para registro de usuarios*/
 if(isset($_GET["register"])&& $_GET["register"==true]){
    $suffix =$_GET["suffix"]?? "user";

    $response ->postRegister($table,$_POST,$suffix);

    /*cuando recibe una peticion post de login */

 }else if (isset($_GET["login"])&& $_GET["login"]==true){
    $suffix=$_GET["suffix"]?? "user";
    $response -> postLogin($table,$_POST,$suffix);
 }else{
    if(isset($_GET["token"])){
        $token = $_GET["token"];
        /*
        $secretKey = "tu_secret_key"; // Reemplaza con tu secret key
        $databaseToken = Connection::connect(); // Obtén el token desde la base de datos

        // Validar cuando no se envía el token
        if (empty($token)) {
            $json = array(
                'result' => 401,
                'message' => 'No se envió el token'
            );
            echo json_encode($json, http_response_code($json["status"]));
            return;
        }

        // Validar cuando el token no coincide con el de la base de datos
        if ($token !== $databaseToken) {
            $json = array(
                'result' => 401,
                'message' => 'Token inválido'
            );
            echo json_encode($json, http_response_code($json["status"]));
            return;
        }

        // Validar cuando el token expiro
        $decoded = JWT::decode($token, $secretKey, ['HS256']);
        if ($decoded->exp < time()) {
            $json = array(
                'result' => 401,
                'message' => 'Token expirado'
            );
            echo json_encode($json, http_response_code($json["status"]));
            return;
        }

        // Peticion post para usuarios autorizados
        $response->postAuthorized($table, $_POST);
        } else {
        // Peticion post para usuarios no autorizados
        $response->postUnauthorized($table, $_POST);
    */
    }
 }

?>
