<?php

require_once "connection.php";

class PostModel
{

	/*=============================================
	Peticion POST para crear datos de forma dinámica
	=============================================*/

	static public function postData($table, $data)
	{

		$columns = "";
		$params = "";



		foreach ($data as $key => $value) {

			$columns .= $key . ",";

			$params .= ":" . $key . ",";
		}



		$columns = substr($columns, 0, -1);
		$params = substr($params, 0, -1);


		$sql = "INSERT INTO $table ($columns) VALUES ($params)";

		$link = Connection::connect();
		$stmt = $link->prepare($sql);

		foreach ($data as $key => $value) {

			$stmt->bindParam(":" . $key, $data[$key], PDO::PARAM_STR);
		}

		if ($stmt->execute()) {

			$response = array(

				"lastId" => $link->lastInsertId(),
				"comment" => "The process was successful"

			);

			return $response;
		} else {

			return $link->errorInfo();
		}
	}

	/*=============================================
	  Guardar token en base de datos
	=============================================*/

	function saveTokenToDatabase($email, $code, $expiration)
	{
		$connection = new Connection(); // 
		$db = $connection->connect();

		$stmt = $db->prepare("UPDATE users SET reset_code_user = ?, reset_code_exp_user = ? WHERE email_user = ?");
		$stmt->execute([$code, $expiration, $email]);
	}

	/*=============================================
	  Actualizar contraseña en base de datos
	=============================================*/

	function updatePasswordInDatabase($email, $hashedPassword)
	{
		$connection = new Connection();
		$db = $connection->connect();

		$stmt = $db->prepare("UPDATE users SET password_user = ? WHERE email_user = ?");
		$stmt->execute([$hashedPassword, $email]);
	}
}
