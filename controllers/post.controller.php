<?php
require_once "models/post.model.php";
require_once "models/get.model.php";
require_once "models/put.model.php";
require_once "models/connection.php";
require_once "vendor/autoload.php";
require_once "controllers/email.php";

use Firebase\JWT\JWT;

class PostController
{
	/*Peticion para crear datos */
	static public function postData($table, $data)
	{
		$response = PostModel::postData($table, $data);

		$return = new PostController();
		$return->fncResponse($response, null, null);
	}

	/*Peticion POST para el registro de usuario*/
	static public function postRegister($table, $data, $suffix)
	{
		/*Encriptar contraseña*/
		if (isset($data["password_" . $suffix]) && isset($data["password_" . $suffix]) != null) {
			/*encriptar contraseña*/
			$crypt = crypt($data["password_" . $suffix], '$2a$07$asxx54ahjppfDGsystemdev$'); /*debe enpezar por $2a$07$ y finalizar con el signo $ y lo de la mitad es aleatorio*/
			$data["password_" . $suffix] = $crypt;

			$response = PostModel::postData($table, $data);
			$return = new PostController();
			$return->fncResponse($response, null, $suffix);
		} else {
			/*Registro de usuarios desde apps externas*/
			$response = PostModel::postData($table, $data);
			if (isset($response["comment"]) && $response["comment"] == "The process was successful") {

				/*Validar que el usuario exista en base de datos*/
				$response = GetModel::getDataFilter($table, "*", "email_" . $suffix, $data["email_" . $suffix], null, null, null, null);

				if (!empty($response)) {

					$token = Connection::jwt($response[0]->{"id_" . $suffix}, $response[0]->{"email_" . $suffix});

					$secretKey = "wqfdghfgfdsqwdsgfhrg"; /*Llave*/
					$keyType = 'HS256';/*Algoritmo de firma que se utiliza para codificar el JWT*/

					$jwt = JWT::encode($token, $secretKey, $keyType);

					/*Actualizar la base de datos con el token del usuario*/
					$data = array(
						"token_" . $suffix => $jwt,
						"token_exp_" . $suffix => $token["exp"]
					);

					$update = PutModel::putData($table, $data, $response[0]->{"id_" . $suffix}, "id_" . $suffix);

					if (isset($update["comment"]) && $update["comment"] == "The process was successful") {

						$response[0]->{"token_" . $suffix} = $jwt;
						$response[0]->{"token_exp_" . $suffix} = $token["exp"];

						$return = new PostController();
						$return->fncResponse($response, null, $suffix);
					}
				}
			}
		}
	}

	/*Peticion POST para el login de usuario*/
	static public function postLogin($table, $data, $suffix)
	{
		/*Validar que el usuario exista en base de datos*/
		$response = GetModel::getDataFilter($table, "*", "email_" . $suffix, $data["email_" . $suffix], null, null, null, null);

		if (!empty($response)) {

			if ($response[0]->{"password_" . $suffix} != null) {/*El usuario se registro de forma directa*/

				/*encriptar contraseña*/
				$crypt = crypt($data["password_" . $suffix], '$2a$07$asxx54ahjppfDGsystemdev$'); /*debe enpezar por $2a$07$ y finalizar con el signo $ y lo de la mitad es aleatorio*/

				if ($response[0]->{"password_" . $suffix} == $crypt) {

					$token = Connection::jwt($response[0]->{"id_" . $suffix}, $response[0]->{"email_" . $suffix});

					$secretKey = "wqfdghfgfdsqwdsgfhrg"; /*Llave*/
					$keyType = 'HS256';/*Algoritmo de firma que se utiliza para codificar el JWT*/

					$jwt = JWT::encode($token, $secretKey, $keyType);

					/*Actualizar la base de datos con el token del usuario*/
					$data = array(
						"token_" . $suffix => $jwt,
						"token_exp_" . $suffix => $token["exp"]
					);

					$update = PutModel::putData($table, $data, $response[0]->{"id_" . $suffix}, "id_" . $suffix);

					if (isset($update["comment"]) && $update["comment"] == "The process was successful") {

						$response[0]->{"token_" . $suffix} = $jwt;
						$response[0]->{"token_exp_" . $suffix} = $token["exp"];

						$return = new PostController();
						$return->fncResponse($response, null, $suffix);
					}
				} else {
					$response = null;
					$return = new PostController();
					$return->fncResponse($response, "Error: Wrong password", $suffix);
				}
			} else {
				/*Actualizar token para usuarios logueados desde apps externas*/
				$token = Connection::jwt($response[0]->{"id_" . $suffix}, $response[0]->{"email_" . $suffix});

				$secretKey = "wqfdghfgfdsqwdsgfhrg"; /*Llave*/
				$keyType = 'HS256';/*Algoritmo de firma que se utiliza para codificar el JWT*/

				$jwt = JWT::encode($token, $secretKey, $keyType);

				/*Actualizar la base de datos con el token del usuario*/
				$data = array(
					"token_" . $suffix => $jwt,
					"token_exp_" . $suffix => $token["exp"]
				);

				$update = PutModel::putData($table, $data, $response[0]->{"id_" . $suffix}, "id_" . $suffix);

				if (isset($update["comment"]) && $update["comment"] == "The process was successful") {

					$response[0]->{"token_" . $suffix} = $jwt;
					$response[0]->{"token_exp_" . $suffix} = $token["exp"];

					$return = new PostController();
					$return->fncResponse($response, null, $suffix);
				}
			}
		} else {
			$response = null;
			$return = new PostController();
			$return->fncResponse($response, "Error: Wrong e-mail", $suffix);
		}
	}
	/*respuesta del controlador*/
	public function fncResponse($response, $error, $suffix)
	{
		if (!empty($response)) {

			/*Quitar la contraseña de la respuesta*/
			if (isset($response[0]->{"password_" . $suffix})) {
				unset($response[0]->{"password_" . $suffix});
			}

			$json = array(
				'status' => 200,
				'results' => $response

			);
		} else {
			if ($error != null) {
				$json = array(
					'status' => 404,
					'results' => 'Not Found',
					'method' => $error
				);
			} else {
				$json = array(
					'status' => 404,
					'results' => 'Not Found',
					'method' => 'post'
				);
			}
		}
		echo json_encode($json, http_response_code($json["status"]));
	}

	/*Peticion POST para el login de usuari*/
	static public function postRecuperation($table, $data, $suffix)
	{
		/*Validar que el usuario exista en base de datos*/
		$response = GetModel::getDataFilter($table, "*", "email_" . $suffix, $data["email_" . $suffix], null, null, null, null);

		if (!empty($response)) {
		} else {
			$response = null;
			$return = new PostController();
			$return->fncResponse($response, "Error: Wrong e-mail", $suffix);
		}
	}
}
