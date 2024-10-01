<?php
class PutController {
     /* Petición PUT para actualizar datos */
     static public function putData($table, $data, $id, $nameId) {
        $response = PutModel::putData($table, $data, $id, $nameId);
        $return = new PutController();
        $return->fncResponse($response);
    }

    public function fncResponse($response) {
        if (!empty($response)) {
            $json = array(
                'status' => 200,
                'result' => $response
            );
        } else {
            $json = array(
                'status' => 404,
                'result' => 'not found'
            );
        }

        echo json_encode($json, http_response_code($json["status"]));
    }
}

?>
