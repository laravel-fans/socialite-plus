<?php

namespace Laravel\Socialite\Two;

class WeChatWebProvider extends WeChatServiceAccountProvider
{
    /**
     * The scopes being requested.
     * @see https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
     *
     * @var array
     */
    protected $scopes = ['snsapi_login'];

    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase('https://open.weixin.qq.com/connect/qrconnect', $state);
    }
}
