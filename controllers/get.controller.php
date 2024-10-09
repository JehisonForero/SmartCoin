<?php

require_once "models/get.model.php";

class GetController
{

	/*=============================================
	Peticiones GET sin filtro
	=============================================*/

	static public function getData($table, $select, $orderBy, $orderMode, $startAt, $endAt)
	{

		$response = GetModel::getData($table, $select, $orderBy, $orderMode, $startAt, $endAt);

		$return = new GetController();
		$return->fncResponse($response);
	}

	/*=============================================
	Peticiones GET con filtro
	=============================================*/

	static public function getDataFilter($table, $select, $linkTo, $equalTo, $orderBy, $orderMode, $startAt, $endAt)
	{

		$response = GetModel::getDataFilter($table, $select, $linkTo, $equalTo, $orderBy, $orderMode, $startAt, $endAt);

		$return = new GetController();
		$return->fncResponse($response);
	}

	/*=============================================
	Peticiones GET sin filtro entre tablas relacionadas
	=============================================*/

	static public function getRelData($rel, $type, $select, $orderBy, $orderMode, $startAt, $endAt)
	{

		$response = GetModel::getRelData($rel, $type, $select, $orderBy, $orderMode, $startAt, $endAt);

		$return = new GetController();
		$return->fncResponse($response);
	}


	/*=============================================
	Peticiones GET con filtro entre tablas relacionadas
	=============================================*/

	static public function getRelDataFilter($rel, $type, $select, $linkTo, $equalTo, $orderBy, $orderMode, $startAt, $endAt)
	{

		$response = GetModel::getRelDataFilter($rel, $type, $select, $linkTo, $equalTo, $orderBy, $orderMode, $startAt, $endAt);

		$return = new GetController();
		$return->fncResponse($response);
	}

	/*=============================================
	Peticiones GET para el buscador sin relaciones
	=============================================*/

	static public function getDataSearch($table, $select, $linkTo, $search, $orderBy, $orderMode, $startAt, $endAt)
	{

		$response = GetModel::getDataSearch($table, $select, $linkTo, $search, $orderBy, $orderMode, $startAt, $endAt);

		$return = new GetController();
		$return->fncResponse($response);
	}

	/*=============================================
	Peticiones GET para el buscador entre tablas relacionadas
	=============================================*/

	static public function getRelDataSearch($rel, $type, $select, $linkTo, $search, $orderBy, $orderMode, $startAt, $endAt)
	{

		$response = GetModel::getRelDataSearch($rel, $type, $select, $linkTo, $search, $orderBy, $orderMode, $startAt, $endAt);

		$return = new GetController();
		$return->fncResponse($response);
	}

	/*=============================================
	Peticiones GET para selección de rangos
	=============================================*/

	static public function getDataRange($table, $select, $linkTo, $between1, $between2, $orderBy, $orderMode, $startAt, $endAt, $filterTo, $inTo)
	{

		$response = GetModel::getDataRange($table, $select, $linkTo, $between1, $between2, $orderBy, $orderMode, $startAt, $endAt, $filterTo, $inTo);

		$return = new GetController();
		$return->fncResponse($response);
	}

	/*=============================================
	Peticiones GET para selección de rangos con relaciones
	=============================================*/

	static public function getRelDataRange($rel, $type, $select, $linkTo, $between1, $between2, $orderBy, $orderMode, $startAt, $endAt, $filterTo, $inTo)
	{

		$response = GetModel::getRelDataRange($rel, $type, $select, $linkTo, $between1, $between2, $orderBy, $orderMode, $startAt, $endAt, $filterTo, $inTo);

		$return = new GetController();
		$return->fncResponse($response);
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

	public function fncResponse($response)
	{

		if (!empty($response)) {

			$json = array(

				'status' => 200,
				'total' => count($response),
				'results' => $response

			);
		} else {

			$json = array(

				'status' => 404,
				'results' => 'Not Found',
				'method' => 'get'

			);
		}

		echo json_encode($json, http_response_code($json["status"]));
	}
}
