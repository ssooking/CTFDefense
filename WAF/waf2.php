<?php
//error_reporting(E_ALL);
//ini_set('display_errors', 1);

/*
** 线下攻防php版本waf
**
** Author: 落
*/

/*
检测请求方式，除了get和post之外拦截下来并写日志。
*/
if($_SERVER['REQUEST_METHOD'] != 'POST' && $_SERVER['REQUEST_METHOD'] != 'GET'){
	write_attack_log("method");
}

$url = $_SERVER['REQUEST_URI']; //获取uri来进行检测

$data = file_get_contents('php://input'); //获取post的data，无论是否是mutipart

$headers = get_all_headers(); //获取header

filter_attack_keyword(filter_invisible(urldecode(filter_0x25($url)))); //对URL进行检测，出现问题则拦截并记录
filter_attack_keyword(filter_invisible(urldecode(filter_0x25($data)))); //对POST的内容进行检测，出现问题拦截并记录

/*
检测过了则对输入进行简单过滤
*/
foreach ($_GET as $key => $value) {
	$_GET[$key] = filter_dangerous_words($value);
}
foreach ($_POST as $key => $value) {
	$_POST[$key] = filter_dangerous_words($value);
}
foreach ($headers as $key => $value) {
	filter_attack_keyword(filter_invisible(urldecode(filter_0x25($value)))); //对http请求头进行检测，出现问题拦截并记录
	$_SERVER[$key] = filter_dangerous_words($value); //简单过滤
}

/*
获取http请求头并写入数组
*/
function get_all_headers() { 
	$headers = array(); 
 
	foreach($_SERVER as $key => $value) { 
		if(substr($key, 0, 5) === 'HTTP_') { 
			$headers[$key] = $value; 
		} 
	} 
 
	return $headers; 
} 


/*
检测不可见字符造成的截断和绕过效果，注意网站请求带中文需要简单修改
*/
function filter_invisible($str){
	for($i=0;$i<strlen($str);$i++){
		$ascii = ord($str[$i]);
		if($ascii>126 || $ascii < 32){ //有中文这里要修改
			if(!in_array($ascii, array(9,10,13))){
				write_attack_log("interrupt");
			}else{
				$str = str_replace($ascii, " ", $str);
			}
		}
	}
	$str = str_replace(array("`","|",";",","), " ", $str);
	return $str;
}

/*
检测网站程序存在二次编码绕过漏洞造成的%25绕过，此处是循环将%25替换成%，直至不存在%25
*/
function filter_0x25($str){
	if(strpos($str,"%25") !== false){
		$str = str_replace("%25", "%", $str);
		return filter_0x25($str);
	}else{
		return $str;
	}
}

/*
攻击关键字检测，此处由于之前将特殊字符替换成空格，即使存在绕过特性也绕不过正则的\b
*/
function filter_attack_keyword($str){
	if(preg_match("/select\b|insert\b|update\b|drop\b|delete\b|dumpfile\b|outfile\b|load_file|rename\b|floor\(|extractvalue|updatexml|name_const|multipoint\(/i", $str)){
		write_attack_log("sqli");
	}

	//此处文件包含的检测我真的不会写了，求高人指点。。。
	if(substr_count($str,$_SERVER['PHP_SELF']) < 2){
		$tmp = str_replace($_SERVER['PHP_SELF'], "", $str);
		if(preg_match("/\.\.|.*\.php[35]{0,1}/i", $tmp)){ 
			write_attack_log("LFI/LFR");;
		}
	}else{
		write_attack_log("LFI/LFR");
	}
	if(preg_match("/base64_decode|eval\(|assert\(/i", $str)){
		write_attack_log("EXEC");
	}
	if(preg_match("/flag/i", $str)){
		write_attack_log("GETFLAG");
	}

}

/*
简单将易出现问题的字符替换成中文
*/
function filter_dangerous_words($str){
	$str = str_replace("'", "‘", $str);
	$str = str_replace("\"", "“", $str);
	$str = str_replace("<", "《", $str);
	$str = str_replace(">", "》", $str);
	return $str;
}

/*
获取http的请求包，意义在于获取别人的攻击payload
*/
function get_http_raw() { 
	$raw = ''; 

	$raw .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\r\n"; 
	 
	foreach($_SERVER as $key => $value) { 
		if(substr($key, 0, 5) === 'HTTP_') { 
			$key = substr($key, 5); 
			$key = str_replace('_', '-', $key); 
			$raw .= $key.': '.$value."\r\n"; 
		} 
	} 
	$raw .= "\r\n"; 
	$raw .= file_get_contents('php://input'); 
	return $raw; 
}

/*
这里拦截并记录攻击payload
*/
function write_attack_log($alert){
	$data = date("Y/m/d H:i:s")." -- [".$alert."]"."\r\n".get_http_raw()."\r\n\r\n";
	$ffff = fopen('log_is_a_secret_file.txt', 'a'); //日志路径 
	fwrite($ffff, $data);  
	fclose($ffff);
	if($alert == 'GETFLAG'){
		echo "HCTF{aaaa}"; //如果请求带有flag关键字，显示假的flag。（2333333）
	}else{
		sleep(15); //拦截前延时15秒
	}
	exit(0);
}

?>
