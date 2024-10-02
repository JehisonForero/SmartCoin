<?php
require_once "vendor/autoload.php";

use Firebase\JWT\JWT;

class PostController{

    /* peticion post para crear datos */

    static public function postData($table, $data)
    {
        $response = PostModel::postData($table, $data);
        $return = new PostController();
        $return->fncResponse($response, null, null);
    }

    /* peticion post para registrar usuarios*/
    static public function postRegister($table, $data, $suffix)
    {
        if (isset($data["password_" . $suffix]) && $data["password_" . $suffix] != null) {
            $crypyt = crypt($data["password_" . $suffix], " ");
            $data["password_" . $suffix] = $crypyt;
            $response = PostModel::postData($table, $data);
            $return = new PostController();
            $return->fncResponse($response, null, $suffix);
        } else {
            return self::postExternalApp($table,$data);
        }
    }
    /*peticion post para app externas */
    static private function postExternalApp($table,$data)
    {
        if (empty($data['email'])) {
            return ['status' => 'error', 'message' => 'El email es requerido.'];
        } elseif (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            return ['status' => 'error', 'message' => 'El email es inválido.'];
        }
        $response = PostModel::postData($table, $data);
        return  ['status' => 'success', 'data' => $response];
    }
  /* peticion login para el usuario*/ 
    static public function postLogin($table, $data, $suffix)
    {
        /*validar que el usuario exita en la base datos */
        $response = GetModel::getRelDataFilter($table, "*", "email_" . $suffix, $data["email_" . $suffix], null, null, null, null,null);
        if (!empty($response)) {
            if ($response[0]->{"password_" . $suffix} != null) {
                $crypyt = crypt($data["password_" . $suffix], '$2a$07$azybxcags23425sdg23sdfhsd$');
                if ($response[0]->{"password_" . $suffix} == $crypyt) {
                    $token = Connection::jwt($response[0]->{"id_" . $suffix}, $response[0]->{"email_" . $suffix});
                    $jwt = JWT::encode($token, "zsdfxgchvjbkytghb5685$$");
                    /* actualizar la base de datos */
                    $data = array(
                        "token_" . $suffix => $jwt,
                        "token_exp_" . $suffix = $token["exp"]
                    );

                    $update = PutModel::putData($table, $data, $response[0]->{"id_" . $suffix}, "id_" . $suffix);
                    if (isset($update["comentario"]) && $update["comentartio"] == "el proceso fue satisfactorio") {
                        $response[0]->{"token_" . $suffix} = $jwt;
                        $response[0]->{"token_exp" . $suffix} = $token["exp"];

                        $return = new PostController();
                        $return->fncResponse($response, null, null);
                    }
                }
            }
        }
    }
    public function fncResponse($response, $error, $suffix)
    {
        if (!empty($response)) {
            if (isset($response[0]->{"password_" . $suffix})) {
                unset($response[0]->{"password_" . $suffix});
            }
            $json = array(
                'status' => 200,
                'result' => $response
            );
        } else {
            if ($error != null) {
                $json = array(
                    'status' => 400,
                    'result' => $error
                );
            }
        }
        echo json_encode($json, http_response_code($json["status"]));
    }
}
?>