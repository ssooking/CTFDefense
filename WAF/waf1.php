<?php
error_reporting(0);
if (!function_exists('getallheaders')) {
    function getallheaders() {
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }
}

$input = "GET : ".print_r( $_GET , true );
$input .= "POST : ".print_r( $_POST , true );
$input .= "Cookies : ".print_r( $_COOKIE , true );

//if ( preg_match( "/select|insert|update|delete|and|or|eval|\'|\/\*|\*|\.\.\/|\.\/|union|into|load_file|outfile|sub|hex/i", $input ) && !( $_COOKIE['dzkxx'] == 'wojiubugaosuni' || $_GET['super'] == 'wojiubugaosuni')) 
if ( preg_match( "((?:')|(?:--)|(/\\*(?:.|[\\n\\r])*?\\*/)|(\\b(select|update|and|or|delete|insert|trancate|char|into|substr|ascii|declare|exec|count|master|into|drop|execute)\\b))", $input ) && !( $_COOKIE['dzkxx'] == '666' || $_GET['super'] == '666')) 
{
    $data = "IP : ".$_SERVER["REMOTE_ADDR"]."\r\nREQUEST_METHOD : ".$_SERVER['REQUEST_METHOD'];
    $data .= "\r\n".$input;
    $data .= "Http-Request : " . print_r( getallheaders(), true ) . "\r\n";
    $log = "file:" . $_SERVER["SCRIPT_NAME"] . "\r\n" . $data . "\r\n";
    $logfn = "/var/www/xctf_" . date( "Y-m-d" ) . ".log";
    file_put_contents( $logfn, "### " . date( "Y-m-d H:m:s" ) . " ###\r\n" . $log . "\r\n", FILE_APPEND );
    //die("Don't hack me!");
}

?>
