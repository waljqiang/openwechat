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
	$encryptMsg = $openWechat->getDecrypt()->encryptMsg($message,$timestamp,$nonce);
	echo "<pre>";
	print_r($encryptMsg);
	echo "</pre>";*/
	//启用ticket推送服务
	//$openWechat->enableTicketPush();
	/*$message = "<xml><Encrypt><![CDATA[swrSUo9DukaMjWP5TfwaHBoghU3GEU3I0unz7UCEMHQOVtcWZe3CSMmvWcz5Jg63G3sKioCDrpQp9r22yY+PZz/b1SIvRyGP28URUCgXN5XxJfug+w4OhzGQyovQdLMCWWQbkeJOFUosr76Lw3xa8XLBSX1SJswXClAJuzHWKQhqQ8hQMzh2biIZnWkKyE8A4nMr3xz2VXME732av4npekGSXEWN2njJf+/6PBERvflfuMTqL2kXMb19KACceTi39ymbmaLL+mtdzKWDGykG16vaRQjcrf0Ogw0tFmU0jNJv1NfGEsDnBxo1tEPNeAKUZn4bt10MTt9u0rEYxx+dXQ==]]></Encrypt><MsgSignature><![CDATA[ddefa6f5bd215eacc036baa3ac5fa1a30cb89a4a]]></MsgSignature><TimeStamp>1413192605</TimeStamp><Nonce><![CDATA[123456]]></Nonce></xml>";
	$signature = "ddefa6f5bd215eacc036baa3ac5fa1a30cb89a4a";

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
	//授权变更处理
	/*$message = "<xml><AppId>第三方平台appid</AppId><CreateTime>1413192760</CreateTime><InfoType>authorized</InfoType><AuthorizerAppid>公众号appid</AuthorizerAppid><AuthorizationCode>授权码</AuthorizationCode><AuthorizationCodeExpiredTime>过期时间</AuthorizationCodeExpiredTime><PreAuthCode>预授权码</PreAuthCode></xml>";
	$encryptMsg = $openWechat->getDecrypt()->encryptMsg($message,$timestamp,$nonce);
	echo "<pre>";
	print_r($encryptMsg);
	echo "</pre>";*/

	/*$encryptMsg = "<xml><Encrypt><![CDATA[qApXUGI0dKxkenKHskRCfR1L7khmpioaJloiSE9FcoC0fOEDswlrctDLHQhFx7PJhaT5Q7wRhO0N9QGgVRlkmU9YNuclRZzbHfmYNckfktJ1YskmdBYljeZFi6yWQX05bTqnkiUgOkPqgY9tOki9bsEnqprJ02sLbApS8KGvuaR3OONFtX4fc6DOjN7SfXBlsirEX9FQj7dJViHdsxlqdpEA2884PmTN6EnVKyR9hW1OyNuwodjNSrZvUKMJEA/RT/zmFZjIauqiwefqLEhN0++Y2pe0anyVlZ1clv3q4O9X+AuJC0yTJwB/X9/p2HE6aDeBigIFxii7/BdJXdn+2qR/TF4BzGoDlONVPW15OZIB2wjl3IMgLsu6wthj3ylIT+2Kbd1Ljm18hJ08eEigOyt7ZWcmJEu8QvOy7gksEL7iNrRLu2UqE3E98xB17gG67ou8j5jc/aJ3OVBrqD8s6KdbIZGHH2d84QyLKBWAvVrW44/vYyjSEJKFcCPhI0QX]]></Encrypt><MsgSignature><![CDATA[45c3fffa43a8b057a629391a6f2d5d52a2c25dc9]]></MsgSignature><TimeStamp>1413192605</TimeStamp><Nonce><![CDATA[123456]]></Nonce></xml>";
	$signature = "45c3fffa43a8b057a629391a6f2d5d52a2c25dc9";
	$openWechat->authorizationCallBack($encryptMsg,$signature,$timestamp,$nonce,function($authorizationInfo){
		var_dump($authorizationInfo);
	});
	exit;*/
	//待公众号实现网页授权
	//获取网页授权CODE
	/*$url = $openWechat->getCODE(1,"http://www.xxx.com/wxAuthCallBack","snsapi_base","asdfds");
	var_dump($url);
	//header("Location:".$url);
	exit;*/
	//通过CODE获取access_token
	/*$res = $openWechat->getAccessTokenByCODE("1","abcD");
	var_dump($res);
	exit;*/
	//刷新access_token
	$res = $openWechat->refreshAccessToken("1","sdfsfdsffdfsdsfd");

}catch(\Exception $e){
	var_dump($e);
}