<?php

require_once "models/get.model.php";
require_once "models/post.model.php";
require_once "models/connection.php";

require_once "vendor/autoload.php";

use Firebase\JWT\JWT;

require_once "models/put.model.php";

class PostController
{

	/*=============================================
	Peticion POST para crear datos
	=============================================*/

	static public function postData($table, $data)
	{

		$response = PostModel::postData($table, $data);

		$return = new PostController();
		$return->fncResponse($response, null, null);
	}

	/*=============================================
	Peticion POST para registrar usuario
	=============================================*/

	static public function postRegister($table, $data, $suffix)
	{

		if (isset($data["password_" . $suffix]) && $data["password_" . $suffix] != null) {

			$crypt = crypt($data["password_" . $suffix], '$2a$07$azybxcags23425sdg23sdfhsd$');

			$data["password_" . $suffix] = $crypt;

			$response = PostModel::postData($table, $data);

			$return = new PostController();
			$return->fncResponse($response, null, $suffix);
		} else {

			/*=============================================
			Registro de usuarios desde APP externas
			=============================================*/

			$response = PostModel::postData($table, $data);

			if (isset($response["comment"]) && $response["comment"] == "The process was successful") {

				/*=============================================
				Validar que el usuario exista en BD
				=============================================*/

				$response = GetModel::getDataFilter($table, "*", "email_" . $suffix, $data["email_" . $suffix], null, null, null, null);

				if (!empty($response)) {

					$token = Connection::jwt($response[0]->{"id_" . $suffix}, $response[0]->{"email_" . $suffix});

					$jwt = JWT::encode($token, "dfhsdfg34dfchs4xgsrsdry46");

					/*=============================================
					Actualizamos la base de datos con el Token del usuario
					=============================================*/

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

	/*=============================================
	Peticion POST para login de usuario
	=============================================*/

	static public function postLogin($table, $data, $suffix)
	{

		/*=============================================
		Validar que el usuario exista en BD
		=============================================*/

		$response = GetModel::getDataFilter($table, "*", "email_" . $suffix, $data["email_" . $suffix], null, null, null, null);

		if (!empty($response)) {

			if ($response[0]->{"password_" . $suffix} != null) {

				/*=============================================
				Encriptamos la contraseña
				=============================================*/

				$crypt = crypt($data["password_" . $suffix], '$2a$07$azybxcags23425sdg23sdfhsd$');

				if ($response[0]->{"password_" . $suffix} == $crypt) {

					$token = Connection::jwt($response[0]->{"id_" . $suffix}, $response[0]->{"email_" . $suffix});

					$jwt = JWT::encode($token, "dfhsdfg34dfchs4xgsrsdry46");

					/*=============================================
					Actualizamos la base de datos con el Token del usuario
					=============================================*/

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
					$return->fncResponse($response, "Wrong password", $suffix);
				}
			} else {

				/*=============================================
				Actualizamos el token para usuarios logueados desde app externas
				=============================================*/

				$token = Connection::jwt($response[0]->{"id_" . $suffix}, $response[0]->{"email_" . $suffix});

				$jwt = JWT::encode($token, "dfhsdfg34dfchs4xgsrsdry46");

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
			$return->fncResponse($response, "Wrong email", $suffix);
		}
	}

	/*=============================================
	 Método para verificar si el código es válido
	=============================================*/

	public function isCodeValid($email, $code)
	{
		$storedTokenData = $this->getStoredToken($email); // Recuperar el código y la expiración

		if ($storedTokenData['reset_code_user'] === $code) {
			$currentDateTime = date("Y-m-d H:i:s");
			if ($currentDateTime <= $storedTokenData['reset_code_exp_user']) {
				return true; // Código válido
			} else {
				echo json_encode(['message' => 'Code expired']);
				return false;
			}
		} else {
			echo json_encode(['message' => 'Invalid code']);
			return false;
		}
	}

	/*=============================================
	  Maneja la confirmación del reseteo de contraseña
	=============================================*/

	public function handlePasswordReset()
	{
		if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'], $_POST['code'], $_POST['new_password'])) {
			$email = $_POST['email'];
			$code = $_POST['code'];
			$newPassword = $_POST['new_password'];

			if ($this->isCodeValid($email, $code)) {
				$hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT); // Hashea la nueva contraseña
				$this->updatePasswordInDatabase($email, $hashedPassword); // Actualiza la contraseña en la base de datos
				echo json_encode(['message' => 'Password updated successfully']);
			}
		}
	}

	/*=============================================
	Método para obtener el código de reseteo y su expiración de la base de datos
	=============================================*/

	private function getStoredToken($email)
	{
		// Lógica para obtener el token de la base de datos
		// Por ejemplo, una consulta a la tabla 'users' para obtener 'reset_code_user' y 'reset_code_exp_user'
		$response = GetModel::getDataFilter('users', 'reset_code_user, reset_code_exp_user', 'email_user', $email, null, null, null, null);
		return isset($response[0]) ? (array) $response[0] : null;
	}

	/*=============================================
	Método para actualizar la contraseña en la base de datos
	=============================================*/

	private function updatePasswordInDatabase($email, $newPassword)
	{
		$data = array("password_user" => $newPassword);
		return PutModel::putData("users", $data, $email, "email_user");
	}

	/*=============================================
	Respuestas del controlador
	=============================================*/

	public function fncResponse($response, $error, $suffix)
	{

		if (!empty($response)) {

			/*=============================================
			Quitamos la contraseña de la respuesta
			=============================================*/

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
					'status' => 400,
					"results" => $error
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
}
