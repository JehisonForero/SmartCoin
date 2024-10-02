<?php
class DeleteController {

    /* Petición DELETE para eliminar datos */
    static public function deleteData($table, $id, $nameId) {
        $response = DeleteModel::deleteData($table, $id, $nameId);
        $return = new DeleteController();
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
                'result' => 'not found',
                'method'=>'delete'
            );
        }

        echo json_encode($json, http_response_code($json["status"]));
    }
}

?>
