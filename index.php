<?php
header('Acces-Control-Allow-Origin:*');
header('Acces-Control-Allow-Credentials:true');
header('Acces-Control-Allow-Headers:Origin, x-requested-whit,content-type,Accept,Autorization');
header('Acces-Control-Allow-Methods:GET,POST,PUT,DELETE');//TAREA: montar la api en un hostin consumir api, verificar errores de cors
header('content-type:Aplication/json charset=utf-8');

/* llamamos a nuetsro routers controller */

require_once "controllers/routes.controller.php";
$index=new RoutesController();
$index->index();

?>