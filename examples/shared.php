<?php
require_once __DIR__ . "/../vendor/autoload.php";
use Waljqiang\Wechat\Redis;
use Waljqiang\Wechat\Logger;
$openwechatConfig = [
	"appId" => "wxb11529c136998cb6",
	"appSecret" => "xcswasdfasfdasfasffd",
	"encodingAesKey" => "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",//消息加解密key
	"token" => "pamtest"//消息校验token
];
$redisConfig = [
	"host" => "192.168.111.201",
	"port" => 6379,
	"database" => 2,
	"prefix" => "waljqiang:",
	"password" => "1f494c4e0df9b837dbcc82eebed35ca3f2ed3fc5f6428d75bb542583fda2170f",
	"enabled" => TRUE,//是否启用
];
$logConfig = [
	"channel" => "wechat",//log文件将以此为前缀命名
	"level" => "DEBUG",
	"path" => __DIR__ . "/../runtime/logs/"
];

$redis = new Redis([
	"host" => $redisConfig["host"],
	"port" => $redisConfig["port"],
	"database" => $redisConfig["database"]
],[
	"prefix" => $redisConfig["prefix"],
	"parameters" => [
		"password" => $redisConfig["password"]
	]
],$redisConfig["enabled"]);


$logger = new Logger($logConfig);