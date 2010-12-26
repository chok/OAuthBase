<?php
/**
 *
 *
 *
 * Implementation for OAuth version 2
 *
 * @author Maxime Picaud
 * @since 21 août 2010
 */
class sfOAuthWrap extends sfOAuth
{
  /**
   * Constructor - set version to 2
   *
   * @author Maxime Picaud
   * @since 21 août 2010
   */
  public function __construct($key, $secret, $token = null, $config = array())
  {
    $this->version = 1.5;

    parent::__construct($key, $secret, $token, $config);
  }

  /**
   * (non-PHPdoc)
   * @see plugins/sfDoctrineOAuthPlugin/lib/sfOAuth::requestAuth()
   */
  public function requestAuth($parameters = array())
  {
    if($this->getController())
    {
      $this->setAuthParameter('wrap_client_id', $this->getKey());
      $this->setAuthParameter('wrap_callback', $this->getCallback());
      $this->addAuthParameters($parameters);
      $url = $this->getRequestAuthUrl().'?'.http_build_query($this->getAuthParameters());

      if($this->getLogger())
      {
        $this->getLogger()->info(sprintf('{OAuth} "%s" call url "%s" with params "%s"',
                                         $this->getName(),
                                         $this->getRequestAuthUrl(),
                                         var_export($this->getAuthParameters(), true)
                                        )
                                 );
      }

      $this->getController()->redirect($url);
    }
    else
    {
      if($this->getLogger())
      {
        $this->getLogger()->err(sprintf('{OAuth} "%s" no controller to execute the request', $this->getName()));
      }
    }
  }

  /**
   * (non-PHPdoc)
   * @see plugins/sfDoctrineOAuthPlugin/lib/sfOAuth::getAccessToken()
   */
  public function getAccessToken($verifier, $parameters = array())
  {
    $url = $this->getAccessTokenUrl();

    $this->setAccessParameter('wrap_client_id', $this->getKey());
    $this->setAccessParameter('wrap_client_secret', $this->getSecret());
    $this->setAccessParameter('wrap_callback', $this->getCallback());
    $this->setAccessParameter('wrap_verification_code', $verifier);

    $this->addAccessParameters($parameters);

    $params = $this->call($url, $this->getAccessParameters(), null, 'POST');

    $params = OAuthUtil::parse_parameters($params);

    $access_token = isset($params['wrap_access_token'])?$params['wrap_access_token']:null;

    if(is_null($access_token) && $this->getLogger())
    {
      $error = sprintf('{OAuth} access token failed - %s returns %s', $this->getName(), print_r($params, true));
      $this->getLogger()->err($error);
    }
    elseif($this->getLogger())
    {
      $message = sprintf('{OAuth} %s return %s', $this->getName(), print_r($params, true));
      $this->getLogger()->info($message);
    }

    $token = new Token();
    $token->setTokenKey($access_token);
    $token->setName($this->getName());
    $token->setStatus(Token::STATUS_ACCESS);
    $token->setOAuthVersion($this->getVersion());

    unset($params['wrap_access_token']);

    if(count($params) > 0)
    {
      $token->setParams($params);
    }

    $this->setExpire($token);

    $this->setToken($token);

    // get identifier maybe need the access token
    $token->setIdentifier($this->getIdentifier());

    $this->setToken($token);

    return $token;
  }

  protected function prepareCall($action, $aliases = null, $params = array(), $method = 'GET')
  {
    if(is_null($this->getToken()))
    {
      throw new sfException(sprintf('no access token available for "%s"', $this->getName()));
    }

    $this->setCallParameter('access_token', $this->getToken()->getTokenKey());

    if(in_array($method, array('GET', 'POST')))
    {
      $this->addCallParameters($params);
    }

    return $this->formatUrl($action, $aliases);
  }

  /**
   * overriden to support OAuth 2
   *
   * @author Maxime Picaud
   * @since 19 août 2010
   */
  public function get($action, $aliases = null, $params = array(), $method = 'GET')
  {
    $url = $this->prepareCall($action, $aliases, $params, 'GET');
    $response = $this->call($url, $this->getCallParameters(), null, 'GET');

    return $this->formatResult($response);
  }

  public function post($action, $aliases = null, $params = array())
  {
    $url = $this->prepareCall($action, $aliases, $params, 'POST');
    $response = $this->call($url, $this->getCallParameters(), null, 'POST');

    return $this->formatResult($response);
  }

  public function put($action, $aliases = null, $params = null)
  {
    $url = $this->prepareCall($action, $aliases, $params, 'PUT');
    $response = $this->call($url, $this->getCallParameters(), $params, 'PUT');

    return $this->formatResult($response);
  }

  public function delete($action, $aliases = null, $params = array())
  {
    $url = $this->prepareCall($action, $aliases, $params, 'DELETE');
    $response = $this->call($url, $this->getCallParameters(), $params, 'DELETE');

    return $this->formatResult($response);
  }
}
