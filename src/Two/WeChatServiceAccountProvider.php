<?php

namespace Laravel\Socialite\Two;

use Exception;
use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;

class WeChatServiceAccountProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * The scopes being requested.
     * snsapi_base: not require confirmation, get only openId, no info.
     * snsapi_userinfo: requires manual consent from the user.
     * unionid: hack for union id when get snsapi_userinfo
     *
     * @var array
     */
    protected $scopes = ['snsapi_userinfo'];

    /**
     * The scopes being requested.
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

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
         $openId = $this->credentialsResponseBody['openid'] ?? $this->openId;

        // snsapi_base scope havs only id, but no info
        if (in_array('snsapi_base', $this->getScopes(), true)) {
            return ['openid' => $openId];
        }
        $response = $this->getHttpClient()->get('https://api.weixin.qq.com/sns/userinfo', [
            RequestOptions::QUERY => [
                'access_token' => $token, // HACK: Tencent use token in Query String, not in Header Authorization
                'openid'       => $openId, // HACK: Tencent need id, but other platforms don't need
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
        return (new User)->setRaw($user)->map([
            // HACK: use unionid as user id
            'id'       => in_array('unionid', $this->getScopes(), true) ? $user['unionid'] : $user['openid'],
            // HACK: Tencent scope snsapi_base only return openid
            'openid'   => $user['openid'],
            'unionid'   => $user['unionid'] ?? null,
            'nickname' => $user['nickname'] ?? null,
            'name'     => null,
            'email'    => null,
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
            unset($scopes[array_search('unionid', $scopes, true)]);
        }
        // HACK: use scopes() instead of setScopes()
        // docs: https://laravel.com/docs/socialite#access-scopes
        if (in_array('snsapi_base', $scopes, true)) {
            unset($scopes[array_search('snsapi_userinfo', $scopes, true)]);
        }

        return implode($scopeSeparator, $scopes);
    }

    public function setOpenId($openId)
    {
        $this->openId = $openId;

        return $this;
    }
}
