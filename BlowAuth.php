<?php

/**

Copyright (c) 2011, PandaWhale, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 - Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

 - Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

 - Neither the name of PandaWhale, Inc. nor the names of its contributors may be
   used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

class BlowAuth
{
    public $oauth_version = '1.0';
    public $signature_method = 'HMAC-SHA1';

    protected $oauth_base_url;
    protected $api_base_url;

    protected $consumer_key;
    protected $consumer_secret;

    protected $token;
    protected $token_secret;

    protected $curl_timeout_ms = 10000;
    protected $curl_connecttimeout_ms = 10000;

    protected $request_token_url;
    protected $access_token_url;
    protected $authenticate_url;
    protected $authorize_url;

    public function getRequestToken($oauth_callback = null)
    {
        $params = array();
        if (!is_null($oauth_callback)) {
            $params['oauth_callback'] = $oauth_callback;
        }

        $response = $this->makeOAuthRequest($this->request_token_url, 'GET', $params);
        $raw_credentials = explode('&', $response);

        $credentials = array();
        foreach ($raw_credentials as $cred_str) {
            $curr_cred = explode('=', $cred_str);
            $credentials[$curr_cred[0]] = rawurldecode($curr_cred[1]);
        }

        return $credentials;
    }

    public function getAccessToken($oauth_verifier)
    {
        $params = array(
            'oauth_verifier'        => $oauth_verifier,
        );
        $response = $this->makeOAuthRequest($this->access_token_url, 'GET', $params);

        $raw_credentials = explode('&', $response);

        $credentials = array();
        foreach ($raw_credentials as $cred_str) {
            $curr_cred = explode('=', $cred_str);
            $credentials[$curr_cred[0]] = rawurldecode($curr_cred[1]);
        }

        return $credentials;
    }

    public function request($api_method)
    {
        $request_url = "{$this->api_base_url}/{$api_method}";
        return $this->makeOAuthRequest($request_url, 'GET');
    }

    protected function makeOAuthRequest($url, $method, $extra_params = array())
    {
        $base_params = array(
            'oauth_consumer_key'        => $this->consumer_key,
            'oauth_nonce'               => $this->getOAuthNonce(),
            'oauth_signature_method'    => $this->signature_method,
            'oauth_timestamp'           => $this->getOAuthTimestamp(),
            'oauth_version'             => $this->oauth_version,
        );

        $params = array_merge($base_params, $extra_params);

        if (isset($this->token)) {
            $params['oauth_token'] = $this->token;
        }

        $params['oauth_signature'] = $this->getOAuthSignature($method, $url, $params);

        $ci = curl_init();
        $query_str = http_build_query($params);

        switch ($method) {
            case 'GET':
            case 'PUT':
            case 'DELETE':
                $url .= '?' . $query_str;
                break;
            case 'POST':
                curl_setopt($ci, CURLOPT_POST, TRUE);
                curl_setopt($ci, CURLOPT_POSTFIELDS, $query_str);
                break;
            default:
               throw new Exception("Invalid HTTP method $method"); 
        }

        curl_setopt($ci, CURLOPT_URL, $url);
        curl_setopt($ci, CURLOPT_TIMEOUT_MS, $this->curl_timeout_ms);
        curl_setopt($ci, CURLOPT_CONNECTTIMEOUT_MS, $this->curl_connecttimeout_ms);
        curl_setopt($ci, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ci, CURLOPT_HEADER, false);

        $response = curl_exec($ci);
        curl_close ($ci);
        return $response;
    }

    protected function getOAuthNonce()
    {
        $mt = microtime();
        $rand = mt_rand();

        return md5($mt . $rand);
    }

    protected function getOAuthTimestamp()
    {
        return time();
    }

    protected function getOAuthSignature($method, $url, $params)
    {
        ksort($params);

        $base_string = $method . '&'
                       . rawurlencode($url) . '&'
                       . rawurlencode(http_build_query($params));

        $oauth_token_secret = '';
        if (isset($this->token_secret)) {
            $oauth_token_secret = $this->token_secret;
        }

        $key = $this->consumer_secret . '&' . $oauth_token_secret;
        return base64_encode(hash_hmac('sha1', $base_string, $key, true));
    }

    public function getAuthorizeUrl($credentials)
    {
        $query_str = "oauth_token={$credentials['oauth_token']}";
        return $this->authorize_url . "?$query_str";
    }

}

?>
