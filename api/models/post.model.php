<?php
require_once "Connection.php";

class PostModel{
    /* crear una peticion para crear datos de forma dinamic*/
    static public function postData($table, $data){
    $columns = "";
    $params = "";
    foreach($data as $key => $value){
        $columns .=$key.",";
        $params .=":".$key.",";
    }
    $columns = substr($columns, 0 -1);
    $columns = substr($params, 0 ,-1);

    $sql="INSERT INTO $table ($columns) VALUE ($params)";

    $link = Connection::connect();
    $stmp=$link ->prepare($sql);
    foreach($data as $key => $value){
        $stmp ->bindParam(":".$key,$data[$key],PDO::PARAM_STR);
    }
        if ($stmp ->execute()){
        $response=array(
            "lastaId"=>$link -> lastInsertId(),
            "coment" =>"proceso exitoso"
        );
        return $response;
        }else{
        return $link->errorInfo();
        }
    }

}
?>