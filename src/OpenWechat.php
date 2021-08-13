<?php
namespace Waljqiang\OpenWechat;

use Waljqiang\Wechat\Redis;
use Waljqiang\Wechat\Logger;
use GuzzleHttp\Client;
use Waljqiang\Wechat\Decryption\Decrypt;
use Waljqiang\Wechat\Decryption\XmlParse;
use Waljqiang\OpenWechat\Exceptions\OpenWechatException;
use Waljqiang\OpenWechat\Wechat;

class OpenWechat{
	/**
	 * ticket缓存key
	 */
	const VERIFYTICKET = "owechat:component:verify:ticket:";
	/**
	* 开放平台令牌的key
	*/
	const COMPONENTTOKEN = "owechat:component:token:";
	/**
	* 开放平台预授权码的key
	*/
	const PREAUTHCODE = "owechat:pre:auth:code:";
	/**
	* 授权公共号appid
	*/
	const AUTHORIZERAPPID = "owechat:authorizer:appid:";
	/**
	* 授权公共号令牌key
	*/
	const AUTHORIZERACCESSTOKEN = "owechat:authorizer:accesstoken:";
	/**
	 * 授权公众号刷新令牌key
	 */
	const AUTHORIZERREFRESHTOKEN = "owechat:authorizer:refresh:accesstoken:";

	private $api = [
		"ticket_enabled" => "https://api.weixin.qq.com/cgi-bin/component/api_start_push_ticket",//启用ticket推送
		"component_token" => "https://api.weixin.qq.com/cgi-bin/component/api_component_token",//获取component_token
		"pre_auth_code" => "https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode?component_access_token=%s",//预授权码
		"wechat_authorization" => "https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid=%s&pre_auth_code=%s&redirect_uri=%s",//生成PC端公众号授权二维码
		"api_query_auth" => "https://api.weixin.qq.com/cgi-bin/component/api_query_auth?component_access_token=%s",//获取授权信息
		"refresh_authorization_token" => "https://api.weixin.qq.com/cgi-bin/component/api_authorizer_token?component_access_token=%s",//刷新authorization_access_token
		"authorizer_info" => "https://api.weixin.qq.com/cgi-bin/component/api_get_authorizer_info?component_access_token=%s",//获取授权账号基本信息
	];
	/**
	 * ticket过期时间
	 */
	public $ticket_expire_in = 43200;
	/**
	 * 缓存提前过期时间
	 */
	public static $pre_expire_in = 600;
	/**
	 * 公共缓存时间
	 */
	public static $common_expire_in = 2592000;

	/**
	 * 消息是否加密
	 */
	public $encoded = TRUE;
	/**
	 * 全网发布测试账号
	 */
	public $publish_account = "gh_3c884a361561";

	/**
	 * [微信开放平台appid]
	 */
	private $appid;
	/**
	 * 微信开放平台appSecret
	 */
	private $appSecret;
	/**
	 * 微信开放平台encodingAesKey
	 */
	private $encodingAesKey;
	/**
	 * 微信开放平台token
	 */
	private $token;
	/**
	* 开放平台令牌
	*/
	private $component_token='';

	/**
	 * Predis\Client
	 */
	private $redis;
	/**
	 * Monolog\Logger
	 */
	private $logger;
	/**
	 * GuzzleHttp\Client
	 */
	private $httpClient;
	/**
	 * Waljqiang\Wechat\Decryption\Decrypt
	 */
	private $decrypt;

	/**
	 * Waljqiang\Wechat\Decryption\XmlParse
	 */
	private $xmlParse;

	/**
	 * 微信公众平台类
	 */
	private $wechat;

	/**
	 * 功能描述
	 *
	 * @param Waljqiang\Wechat\Redis  $redis
	 * @param Waljqiang\Wechat\Logger $logger
	 * @param array $config [
			"appId" => "wxb11529c136998cb6",
			"appSecret" => "",
			"encodingAesKey" => "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",//消息加解密key
			"token" => "pamtest"//消息校验token
		];
	 */
	public function __construct(Redis $redis,Logger $logger,$config){
		if(!empty(array_diff(["appid","appSecret","encodingAesKey","token"],array_keys($config)))){
			throw new OpenWechatException("Missing required attribute",OpenWechatException::ATTRIBUTEMISS);
		}
		foreach ($config as $key => $value) {
			if(property_exists($this,$key)){
				$this->{$key} = $value;
			}
		}
		$this->redis = $redis;
		$this->logger = $logger;
		$this->httpClient = new Client;
		$this->decrypt = new Decrypt($this->token,$this->encodingAesKey,$this->appid);
		$this->xmlParser = new XmlParse;
		//此时wechat没有appid跟appSecret;在使用wechat前必须对wechat进行初始化工作
		$this->wechat = new Wechat($this->redis,$this->logger,[
			"appid" => $this->appid,
			"appSecret" => "",
			"encodingAesKey" => $this->encodingAesKey,
			"token" => $this->token
		]);
	}

	public function init($appid,$appSecret,$encodingAesKey,$token){
    	$this->appid = $appid;
        $this->appSecret = $appSecret;
        $this->encodingAesKey = $encodingAesKey;
        $this->token = $token;
        $this->decrypt->init($this->token,$this->encodingAesKey,$this->appid);
        return $this;
    }

    //启用ticket推送服务
    public function enableTicketPush(){
    	$url = $this->api["ticket_enabled"];
		$res = $this->request($url,"POST",[
			"json" => [
				"component_appid" => $this->appid,
				"component_secret" => $this->appSecret
			]
		]);
		return true;
    }

    /**
     * 开放平台component_verify_ticket处理
     *
     * @param  [string] $encryptMsg [微信服务器推送过来的消息]
     * @param  [string] $signature  [消息签名]
     * @param  [timestamp] $timestamp  [时间戳]
     * @param  [string] $nonce      [随机字符]
     * @return 
     */
    public function handleTicket($encryptMsg,$signature,$timestamp,$nonce){
        $fromXml = $this->xmlParser->extract($encryptMsg);
        $formatXml = $this->xmlParser->generate([
            "ToUserName" => "<![CDATA[toUser]]>",
            "Encrypt" => "<![CDATA[" . $fromXml["Encrypt"] . "]]>"
        ]);
        $decryptMsg = $this->decrypt->decryptMsg($signature,$timestamp,$nonce,$formatXml);
        $decryptMsgArr = $this->xmlParser->extract($decryptMsg,["ComponentVerifyTicket"]);
        $componentVerifyTicket = $decryptMsgArr["ComponentVerifyTicket"];
       /* $arr = explode('@@@',$componentVerifyTicket);
        return $arr[1];*/
        $this->redis->setValues(self::VERIFYTICKET . $this->appid,$componentVerifyTicket,$this->ticket_expire_in - self::$pre_expire_in);
        return $componentVerifyTicket;
    }

    //获取令牌
    public function getComponentToken(){
    	if(!$this->component_token){
    		if(!($this->component_token = $this->redis->getValues(self::COMPONENTTOKEN . $this->appid))){
    			if(!($ticket = $this->redis->getValues(self::VERIFYTICKET . $this->appid))){
    				throw new OpenWechatException("No ticket",OpenWechatException::NOTICKET);
    			}
    			$url = $this->api["component_token"];
    			$res = $this->request($url,"POST",[
    				"json" => [
    					"component_appid" => $this->appid,
    					"component_appsecret" => $this->appSecret,
    					"component_verify_ticket" => $ticket
    				]
    			]);
    			$this->component_token = $data["component_access_token"];
    			$this->redis->setValues(self::COMPONENTTOKEN . $this->appid,$this->component_token,$data["expires_in"] - self::$pre_expire_in);
    		}
    	}
    	return $this->component_token;
    }

    //获取预授权码
    public function getPreAuthCode(){
    	if(!($preAuthCode = $this->redis->getValues(self::PREAUTHCODE . $this->appid))){
    		$url = sprintf($this->api["pre_auth_code"],$this->getComponentToken());
    		$res = $this->request($url,"POST",[
    			"json" => [
    				"component_appid" => $this->appid
    			]
    		]);
    		$arr = explode("@@@",$res["pre_auth_code"]);
    		$preAuthCode = $arr[1];
    		$this->redis->setValues(self::PREAUTHCODE . $this->appid,$preAuthCode,$res["expires_in"] - self::$pre_expire_in);
    	}
    	return $preAuthCode;
    }

    //生成PC端授权二维码
    /**
     * 功能描述
     *
     * @param  string  $redirectUri 授权成功后回调地址
     * @param  integer $authType    授权账号类型1:仅展示公众号;2:仅展示小程序3:全部展示;当bizAppid有值时$authType无效
     * @param  string  $bizAppid    指定授权唯一的小程序或公众号
     */
    public function getAuthorizationCode($redirectUri,$authType = 3,$bizAppid = ""){
    	$url = sprintf($this->api["wechat_authorization"],$this->appid,$this->getPreAuthCode(),$redirectUri);
    	if(!empty($bizAppid)){
    		$url .= "&biz_appid=" . $bizAppid;
    	}else{
    		$url .= "&auth_type=" . $authType;
    	}
    	return $url;
    }

    /**
     * 初始化授权信息
     *
     * @param  string $identify    标识，用于授权信息缓存标识，一般与用户id相关联
     * @param  string $authCode 授权码，由公众号授权成功后回调地址的GET参数中得到
     * @param \Closure $callBack  回调函数,回调函数入参为认证信息，可在回调函数中对认证信息做其他业务逻辑处理例如授权信息需要落地存储
     * 
     * 该方法一般在授权成功后回调地址处使用,公众号授权整个流程如下:
     * 1.生成PC端授权二维码(前提需要先获取预授权码)
     * 2.用户扫描二维码确认同意授权公众号
     * 3.授权成功后，微信携带pre_auth_code和expires_in参数发送GET请求到公众号授权回调地址
     * 4.授权回调中调用initAuthorization方法进行授权信息初始化
     *
     * $res = [
			"authorization_info" => [
				"authorizer_appid" => "wxb11529c136998cb6",
				"authorizer_access_token" => "QXjUqNqfYVH0yBE1iI_7vuN_9gQbpjfK7hYwJ3P7xOa88a89-Aga5x1NMYJyB8G2yKt1KCl0nPC3W9GJzw0Zzq_dBxc8pxIGUNi_bFes0qM",
				"expires_in" => 7200,
				"authorizer_refresh_token" => "@@@dTo-YCXPL4llX-u1W1pPpnp8Hgm4wpJtlR6iV0doKdY"
			]
		];
     */
    public function initAuthorization($identify,$authCode,$callBack = ""){
    	$url = sprintf($this->api["api_query_auth"],$this->getComponentToken());
    	$res = $this->request($url,"POST",[
    		"json" => [
    			"component_appid" => $this->appid,
    			"authorization_code" => $authCode
    		]
    	]);
    	$authorizer_appid = $res["authorization_info"]["authorizer_appid"];
    	$authorizer_access_token = $res["authorization_info"]["authorizer_access_token"];
    	$authorizer_refresh_token = $res["authorization_info"]["authorizer_refresh_token"];
    	$arr = explode("@@@",$authorizer_refresh_token);
    	$authorizer_refresh_token = $arr[1];
    	$this->redis->pipeline(function($pipe)use($identify,$res,$authorizer_appid,$authorizer_access_token,$authorizer_refresh_token){
    		$pipe->set(self::AUTHORIZERAPPID . $identify,serialize($authorizer_appid));
    		$pipe->setex(self::AUTHORIZERACCESSTOKEN . $authorizer_appid,$res["authorization_info"]["expires_in"] - self::$pre_expire_in,serialize($authorizer_access_token));
    		$pipe->set(self::AUTHORIZERREFRESHTOKEN . $authorizer_appid,serialize($authorizer_refresh_token));
    	});
    	if($callBack instanceof \Closure){
    		call_user_func($callBack,$res);
    	}
    	return true;
    }

    /**
     * 刷新authorization_access_token
     *
     * 当自己对授权信息进行存储时，需要使用$authorizer_appid、$authorizer_refresh_token、$callBack这三个参数做自己业务逻辑
     */
    public function refreshAuthorizationAccessToken($identify,$authorizer_appid = "",$authorizer_refresh_token = "",$callBack = ""){
    	if(empty($authorizer_appid)){
    		$authorizer_appid = $this->getAuthorizerAppid($identify);
    	}
    	if(empty($authorizer_refresh_token)){
    		$authorizer_refresh_token = $this->redis->getValues(self::AUTHORIZERREFRESHTOKEN . $authorizer_appid);
    	}
    	$url = sprintf($this->api["refresh_authorization_token"],$this->getComponentToken());
    	$res = $this->request($url,"POST",[
    		"json" => [
    			"component_appid" => $this->appid,
    			"authorizer_appid" => $authorizer_appid,
    			"authorizer_refresh_token" => $authorizer_refresh_token
    		]
    	]);
    	$authorizer_access_token = $res["authorizer_access_token"];
    	$this->redis->pipeline(function($pipe)use($authorizer_appid,$res,$authorizer_access_token){
    		$pipe->setex(self::AUTHORIZERACCESSTOKEN . $authorizer_appid,$res["expires_in"] - self::$pre_expire_in,serialize($authorizer_access_token));
    		$pipe->set(self::AUTHORIZERREFRESHTOKEN . $authorizer_appid,serialize($res["authorizer_refresh_token"]));
    	});
    	if($callBack instanceof \Closure){
    		call_user_func($callBack,$res);
    	}
		return $authorizer_access_token;  	
    }
    //获取授权方账号的基本信息
    public function authorizerInfo($identify,$authorizer_appid = ""){
    	if(empty($authorizer_appid)){
    		$authorizer_appid = $this->getAuthorizerAppid($identify);
    	}
    	$url = sprintf($this->api["authorizer_info"],$this->getComponentToken());
    	$res = $this->request($url,"POST",[
    		"json" => [
    			"component_appid" => $this->appid,
    			"authorizer_appid" => $authorizer_appid
    		]
    	]);
    	return $res;
    }

    //授权事件通知处理
    public function authorizationCallBack($encryptMsg,$signature,$timestamp,$nonce,$callBack = ""){
        $decryptMsg = $this->decrypt->decryptMsg($signature,$timestamp,$nonce,$encryptMsg);
        $decryptMsgArr = $this->xmlParser->extract($decryptMsg);
       	if($callBack instanceof \Closure){
    		call_user_func($callBack,$decryptMsgArr);
    	}
    }

    public function getAuthorizerAppid($identify,$authorizer_appid = ""){
    	if(empty($authorizer_appid)){
    		$authorizer_appid = $this->redis->getValues(self::AUTHORIZERAPPID . $identify);
    	}
    	return $authorizer_appid;
    }

    public function getAuthorizerAccessToken($identify,$authorizer_appid = "",$authorizer_refresh_token = "",$callBack = ""){
    	$authorizer_appid = $this->getAuthorizerAppid($identify,$authorizer_appid);
    	if(!($authorizer_access_token = $this->redis->getValues(self::AUTHORIZERACCESSTOKEN . $authorizer_appid))){
    		$authorizer_access_token = $this->refreshAuthorizationAccessToken($identify,$authorizer_appid,$authorizer_refresh_token,$callBack);
    	}
    	return $authorizer_access_token;
    }

	public function getAppid(){
		return $this->appid;
	}

	public function getAppSecret(){
		return $this->appSecret;
	}

	public function getRedis(){
		return $this->redis;
	}

	public function getLogger(){
		return $this->logger;
	}

	public function getDecrypt(){
		return $this->decrypt;
	}

	public function getXmlParser(){
		return $this->xmlParser;
	}

	public function getWechat(){
		return $this->wechat;
	}

	/**
	 * 发送http请求
	 *
	 * @param  string $url     http请求地址
	 * @param  string $method  http请求方法
	 * @param  array  $options http请求参数
	 * @return array
	 * @throws Waljqiang\Wechat\Exception,\Exception 
	 */
	public function request($url,$method = "GET",$data = [],$header = []){
		try{
			$body = [];
			if(!empty($header)){
				array_push($body,["headers" => $header]);
			}
			if(!empty($data)){
				$body = array_merge($body,$data);
			}
			$response = $this->httpClient->request($method,$url,$body);
			if($response->getStatusCode() == 200){
				$result = $response->getBody();
				if(!is_null($result = @json_decode($result,true))){
					$this->logger->log("Request " . $url . "with method[" . $method . "]body[" . json_encode($body) . "] response[" . json_encode($result) . "]",\Monolog\Logger::DEBUG);
					if(isset($result["errcode"]) && $result["errcode"] != 0){
						throw new OpenWechatException($result["errmsg"],$result["errcode"]);
					}
					return $result;
				}else{
					throw new OpenWechatException("Explain response failure",OpenWechatException::HTTPRESPONSEEXPLAINFAILURE);
				}
			}else{
				throw new OpenWechatException($e->getMessage(),OpenWechatException::HTTPREQUESTERROR);
			}
		}catch(\Exception $e){
			$this->logger->log("Request " . $url . " Failure, caused:" . $e->getMessage(),\Monolog\Logger::ERROR);
			throw new OpenWechatException($e->getMessage(),OpenWechatException::HTTPREQUESTERROR);
		}
	}

	public function initWechat($identify,$authorizer_appid = ""){
		if(empty($authorizer_appid)){
			$authorizer_appid = $this->getAuthorizerAppid($identify);
		}
		$this->wechat->init($authorizer_appid);
		$this->wechat->setAccessToken($this->getAuthorizerAccessToken($identify,$authorizer_appid));
		return $this->wechat;
	}

}