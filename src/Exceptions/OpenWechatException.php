<?php
namespace Waljqiang\OpenWechat\Exceptions;

use Waljqiang\Wechat\Exceptions\WechatException;

class OpenWechatException extends WechatException{
	const NOTICKET = 600902100;//没有推送过来的ticket
}