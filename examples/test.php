<?php
require_once __DIR__ . "/shared.php";
use Waljqiang\OpenWechat\OpenWechat;
use Waljqiang\Wechat\Decryption\Decrypt;
try{
	
	$timestamp = "1413192605";
	$nonce = "123456";
	$openWechat = new OpenWechat($redis,$logger,[
		"appid" => $openwechatConfig["appId"],
		"appSecret" => $openwechatConfig["appSecret"],
		"encodingAesKey" => $openwechatConfig["encodingAesKey"],
		"token" => $openwechatConfig["token"]
	]);
	//$openWechat->init($openwechatConfig["appId"],$openwechatConfig["appSecret"],$openwechatConfig["encodingAesKey"],$openwechatConfig["token"]);
	//生成推送过来的加密消息
	/*$message = "<xml>
	<AppId>wxb11529c136998cb6</AppId>
	<CreateTime>1413192605</CreateTime>
	<InfoType>component_verify_ticket</InfoType>
	<ComponentVerifyTicket>some_verify_ticket</ComponentVerifyTicket>
	</xml>";

	$openWechat = new OpenWechat($redis,$logger,[
		"appid" => $openwechatConfig["appId"],
		"appSecret" => $openwechatConfig["appSecret"],
		"encodingAesKey" => $openwechatConfig["encodingAesKey"],
		"token" => $openwechatConfig["token"]
	]);
	$encryptMsg = $openWechat->getDecrypt()->encryptMsg($message,$timestamp,$nonce);
	echo "<pre>";
	print_r($encryptMsg);
	echo "</pre>";*/
	//启用ticket推送服务
	//$openWechat->enableTicketPush();
	/*$message = "<xml><Encrypt><![CDATA[swrSUo9DukaMjWP5TfwaHBoghU3GEU3I0unz7UCEMHQOVtcWZe3CSMmvWcz5Jg63G3sKioCDrpQp9r22yY+PZz/b1SIvRyGP28URUCgXN5XxJfug+w4OhzGQyovQdLMCWWQbkeJOFUosr76Lw3xa8XLBSX1SJswXClAJuzHWKQhqQ8hQMzh2biIZnWkKyE8A4nMr3xz2VXME732av4npekGSXEWN2njJf+/6PBERvflfuMTqL2kXMb19KACceTi39ymbmaLL+mtdzKWDGykG16vaRQjcrf0Ogw0tFmU0jNJv1NfGEsDnBxo1tEPNeAKUZn4bt10MTt9u0rEYxx+dXQ==]]></Encrypt><MsgSignature><![CDATA[ddefa6f5bd215eacc036baa3ac5fa1a30cb89a4a]]></MsgSignature><TimeStamp>1413192605</TimeStamp><Nonce><![CDATA[123456]]></Nonce></xml>";
	$data = $openWechat->getXmlParser()->extract($message,["MsgSignature"]);
	$signature = $data["MsgSignature"];

	//处理推送过来的ticket
	$ticket = $openWechat->handleTicket($message,$signature,$timestamp,$nonce);
	var_dump($ticket);
	exit;*/
	//获取令牌
	/*$res = $openWechat->getComponentToken();
	var_dump($res);
	exit;*/
	//获取预授权码
	/*$res = $openWechat->getPreAuthCode();
	var_dump($res);
	exit;*/
	//生成PC端授权二维码
	/*$url = $openWechat->getAuthorizationCode("http://xxx.xx/authCallBack");
	var_dump($url);
	exit;*/
	//初始化授权信息
	/*$res = $openWechat->initAuthorization("1","Cx_Dk6qiBE0Dmx4EmlT3oRfArPvwSQ-oa3NL_fwHM7VI08r52wazoZX2Rhpz1dEw",function($authorizationInfo){
		var_dump($authorizationInfo);
	});
	var_dump($res);
	exit;*/
	//刷新authorization_access_token
	/*$res = $openWechat->refreshAuthorizationAccessToken(1);
	var_dump($res);
	exit;*/
	/*//获取授权账号的基本信息
	$res = $openWechat->authorizerInfo(1);
	var_dump($res);
	exit;*/
	//获取认证token
	/*$res = $openWechat->getAuthorizerAccessToken(1);
	var_dump($res);
	exit;*/

	//代公众号实现业务
	/*$options = [
		"button" => [
			[
				"type" => "view",
				"name" => "我要下单",
				"url" => "http://www.baidu.com"
			],
			[
				"type" => "click",
				"name" => "个人中心",
				"key" => "V0001_PERSONAL"
			],
			[
				"type" => "click",
				"name" => "关于我们",
				"key" => "V0002_ABOUT"
			]
		]
	];
	$res = $openWechat->initWechat("1")->setMenu($options);
	var_dump($res);
	exit;*/
}catch(\Exception $e){
	var_dump($e);
}