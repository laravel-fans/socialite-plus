<?php

namespace Laravel\Socialite\Two;

use GuzzleHttp\RequestOptions;

class WeChatServiceAccountProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * The scopes being requested.
     * snsapi_base: not require confirmation, get only openId, no info.
     * snsapi_userinfo: requires manual consent from the user.
     * unionid: hack for union id when get snsapi_userinfo
     *
     * @see https://developers.weixin.qq.com/doc/service/guide/h5/auth.html
     * @var array
     */
    protected $scopes = ['snsapi_userinfo'];
    private $driver = 'wechat-service-account';

    /**
     * fu*k Tencent: break the standard of get user by token, it needs openid and token
     *
     * @var string
     */
    private $openId;

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase('https://open.weixin.qq.com/connect/oauth2/authorize', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return 'https://api.weixin.qq.com/sns/oauth2/access_token';
    }

    public function getAccessTokenResponse($code)
    {
        $response = parent::getAccessTokenResponse($code);
        $this->setOpenId($response['openid']);
        return $response;
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        // snsapi_base scope have only id, but no info
        if (in_array('snsapi_base', $this->getScopes(), true)) {
            return ['openid' => $this->openId];
        }
        $response = $this->getHttpClient()->get('https://api.weixin.qq.com/sns/userinfo', [
            RequestOptions::QUERY => [
                'access_token' => $token, // HACK: Tencent use token in Query String, not in Header Authorization
                'openid'       => $this->openId, // HACK: Tencent need id, but other platforms don't need
                'lang'         => 'zh_CN',
            ],
        ]);

        return json_decode((string) $response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        $emailDomain = $this->parameters['email_domain'] ?? $this->driver . '.example.com';
        $emailPrefix = 'openid.' . $user['openid'];
        if (in_array('unionid', $this->getScopes()) && !empty($user['unionid'])) {
            $emailPrefix = 'unionid.' . $user['unionid'];
            $emailDomain = $this->parameters['email_domain'] ?? 'wechat.example.com';
        }
        return (new User)->setRaw($user)->map([
            // use openid as user id, unionid maybe not exists, when unionid exists, should not change id
            'id'       => $user['openid'],
            'openid'   => $user['openid'],
            'unionid'   => $user['unionid'] ?? null,
            'nickname' => $user['nickname'] ?? null,
            'name'     => null,
            'email'    => $emailPrefix . '@' . $emailDomain,
            'avatar'   => $user['headimgurl'] ?? null,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return [
            'appid'      => $this->clientId,
            'secret'     => $this->clientSecret,
            'code'       => $code,
            'grant_type' => 'authorization_code',
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getCodeFields($state = null)
    {
        $fields = parent::getCodeFields($state);
        unset($fields['client_id']);
        $fields['appid'] = $this->clientId; // HACK: Tencent use appid, not app_id or client_id

        return $fields;
    }

    /**
     * {@inheritdoc}
     */
    protected function formatScopes(array $scopes, $scopeSeparator)
    {
        // HACK: unionid is a faker scope for user id
        if (in_array('unionid', $scopes, true)) {
            $scopes = array_values(array_diff($scopes, ['unionid']));
        }

        return implode($scopeSeparator, $scopes);
    }

    public function setOpenId($openId)
    {
        $this->openId = $openId;

        return $this;
    }
}
