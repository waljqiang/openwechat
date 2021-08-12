<?php
namespace Waljqiang\OpenWechat;

use Waljqiang\Wechat\Wechat as Base;

class Wechat extends Base{
	private $authorizer_access_token;

	public function setAccessToken($authorizer_access_token){
		$this->authorizer_access_token = $authorizer_access_token;
	}
	/**
	 * 重写获取access_token方法
	 *
	 */
	public function getAccessToken(){
		return $this->authorizer_access_token;
	}

}