<?php

require_once "models/connection.php";
require_once "controllers/get.controller.php";

$routesArray = explode("/", $_SERVER['REQUEST_URI']);
$routesArray = array_filter($routesArray);

/*===== Cuando no se hace ninguna peticion a la API =======*/

if(count($routesArray) == 0){

	$json = array(

		'status' => 404,
		'results' => 'Not Found'

	);

	echo json_encode($json, http_response_code($json["status"]));

	return;

}

if(count($routesArray) == 1 && isset($_SERVER['REQUEST_METHOD'])){

	$table = explode("?", $routesArray[1])[0]; 


	if(!isset(getallheaders()["Authorization"]) || getallheaders()["Authorization"] != Connection::apikey()){

		if($table!='relations'&&in_array($table, Connection::publicAccess()) == 0){
	
			$json = array(
		
				'status' => 400,
				"results" => "Usuario no autorizado"
				
			);
			echo json_encode($json, http_response_code($json["status"]));
			return;

		}/*else{		
	    	$response = new GetController();
			$response -> getData($table, "*",null,null,null,null);
            
			return;
		}*/
	
	}
	if($_SERVER['REQUEST_METHOD'] == "GET"){
		include "services/get.php";

	}

}