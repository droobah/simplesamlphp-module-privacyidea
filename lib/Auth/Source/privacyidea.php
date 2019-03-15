<?php

/**
 * privacyidea authentication module.
 * 2018-03-16 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Replace [] with array()
 * 2017-08-17 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Change POST params to array and
 *            only add REALM if necessary
 * 2017-02-13 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Forward the client IP to privacyIDEA
 * 2016-12-30 Andreas Böhler <dev@rnb-consulting.at>
 *            Add support for passing additional attributes to SAML
 * 2015-11-21 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Add support for U2F authentication requests
 * 2015-11-19 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Add authenticate method to call our own template.
 *            Add handleLogin method to be able to handle challenge response.
 * 2015-11-05 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Revert the authentication logic to avoid false logins
 * 2015-09-23 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Adapt for better usability with
 *            Univention Corporate Server
 *            Change Auth Request to POST
 * 2015-04-11 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            minor changes by code climate
 * 2014-09-29 Cornelius Kölbel, cornelius@privacyidea.org
 *
 * This is forked from simplesamlphp-linotp,
 * (https://github.com/lsexperts/simplesamlphp-linotp)
 * which is based on Radius.php
 *
 */
class sspmod_privacyidea_Auth_Source_privacyidea extends sspmod_core_Auth_UserPassBase
{
	/**
	 * The serverconfig is listed in this array
	 * @var array
	 */
	private $serverconfig;

    /**
     * the otp_extra, default to 0
     */
    private $otp_extra = 0;

    /**
     * the enablepinchange, default to 0
     */
    private $enablepinchange = 0;

    /**
     * The attribute map. It is an array
     */

    private $attributemap = array();

	/**
	 * The detail map. It is an array
	 */

	private $detailmap = array();

	/**
	 * The concatenation map. It is an array
	 */

	private $concatenationmap = array();

    public function getOtpExtra()
    {
        return $this->otp_extra;
    }

    /**
     * Constructor for this authentication source.
     *
     * @param array $info Information about this authentication source.
     * @param array $config Configuration.
     */
    public function __construct($info, $config)
    {
        assert('is_array($info)');
        assert('is_array($config)');

        /* Call the parent constructor first, as required by the interface. */
        parent::__construct($info, $config);

        if (array_key_exists('privacyideaserver', $config)) {
            $this->serverconfig['privacyideaserver'] = $config['privacyideaserver'];
        }
        if (array_key_exists('realm', $config)) {
            $this->serverconfig['realm'] = $config['realm'];
        }
        if (array_key_exists('sslverifyhost', $config)) {
            $this->serverconfig['sslverifyhost'] = $config['sslverifyhost'];
        }
        if (array_key_exists('sslverifypeer', $config)) {
            $this->serverconfig['sslverifypeer'] = $config['sslverifypeer'];
        }
        if (array_key_exists('attributemap', $config)) {
            $this->attributemap = $config['attributemap'];
        }
	    if (array_key_exists('detailmap', $config)) {
		    $this->detailmap = $config['detailmap'];
	    }
	    if (array_key_exists('concatenationmap', $config)) {
	    	$this->concatenationmap = $config['concatenationmap'];
	    }
        if (array_key_exists('otpextra', $config)) {
            $this->otp_extra = $config['otpextra'];
        }
        if (array_key_exists('enablepinchange', $config)) {
            $this->enablepinchange = $config['enablepinchange'];
        }
    }


    /**
     * Attempt to log in using the given username and password.
     *
     * @param string $username The username the user wrote.
     * @param string $password The password the user wrote.
     * @return array  Associative array with the users attributes.
     * Each attribute needs to contain a list:
     * {"uid" => {0 => "Administrator},
     *  "givenName" => {0 => "Hans",
     *                  1 => "Dampf"}
     * }
     */
    protected function login($username, $password)
    {
    }

    private function set_pin($auth_token, $token_serial, $pin) {
        SimpleSAML_Logger::debug("privacyidea updating pin: " . $token_serial);
        $params = array(
                        "serial" => $token_serial,
                        "otppin" => $pin,
                        );
        $headers = array("Authorization: $auth_token");
        $pbody = sspmod_privacyidea_Auth_utils::curl($params, $headers, $this->serverconfig, "/token/setpin", "POST");
    }

    private function load_user_attributes($auth_token, $username, $realm) {
        $headers = array("Authorization: $auth_token");
        $params = array();
        $ubody = sspmod_privacyidea_Auth_utils::curl($params, $headers, $this->serverconfig, "/user/?realm=$realm&username=$username", "GET");
        $uresult = $ubody->result;
        SimpleSAML_Logger::debug("privacyidea user result:" . print_r($uresult->value, True));

        $result = (object) ['value' => (object) [ 'attributes' => (object)[] ] ];
        $result->value->attributes->realm = $realm;

        if ($uresult->value) {
            foreach ($uresult->value[0] as $k => $v) {
                $result->value->attributes->$k = $v;
            }
        }
        return $result;
    }

    protected function login_chal_resp($state, $username, $password, $transaction_id, $signaturedata, $clientdata)
    {
        assert('is_string($username)');
        assert('is_string($password)');
        assert('is_string($transaction_id)');

        // The parameters in an array do get get urlencoded!
        // But we encode the log data to avoid log execution
        $params = array(
            "user" => $username,
            "username" => $username,
            "pass" => $password,
            "password" => $password,
            );
        if (strlen($this->serverconfig['realm']) > 0) {
            $params["realm"] = $this->serverconfig['realm'];
        }

        if ($transaction_id) {
            SimpleSAML_Logger::debug("Authenticating with transaction_id: " . $transaction_id);
            $params["transaction_id"] = $transaction_id;
        }
        if ($signaturedata) {
            SimpleSAML_Logger::debug("Authenticating with signaturedata: " . urlencode($signaturedata));
            $params["signaturedata"] = $signaturedata;
        }
        if ($clientdata) {
            SimpleSAML_Logger::debug("Authenticating with clientdata: " . urlencode($clientdata));
            $params["clientdata"] = $clientdata;
        }
        // determine the client IP
        $headers = $_SERVER;
        foreach(array("X-Forwarded-For", "HTTP_X_FORWARDED_FOR", "REMOTE_ADDR") as $clientkey) {
            if (array_key_exists($clientkey, $headers)) {
                $client_ip = $headers[$clientkey];
                SimpleSAML_Logger::debug("Using IP from " . $clientkey . ": " . $client_ip);
                $params["client"] = $client_ip;
                break;
            }
        }

        // Add some debug so we know what we are doing.
        SimpleSAML_Logger::debug("privacyidea URL:" . $this->serverconfig['privacyideaserver']);
        SimpleSAML_Logger::debug("user          : " . urlencode($username));
        SimpleSAML_Logger::debug("transaction_id: " . $transaction_id);

        $send_server_request = true;
        if ($this->enablepinchange) {
            //check to see if we already have a PIN response
            if (isset($state['privacyidea:privacyidea:pinChange'])) {
                if (!is_numeric($password) || strlen($password) < 4) {
                    //retry the PIN set as data sent was invalid
                    $url = SimpleSAML_Module::getModuleURL('privacyidea/otpform.php');
                    SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));
                    return true;
                }

                $auth_token = $state['privacyidea:privacyidea:pinChange']['token'];
                $token_serial = $state['privacyidea:privacyidea:pinChange']['serial'];
                $this->set_pin($auth_token, $token_serial, $password);
            } else {
                $body = sspmod_privacyidea_Auth_utils::curl($params, null, $this->serverconfig, "/auth", "POST");
            }
        } else {
            $body = sspmod_privacyidea_Auth_utils::curl($params, null, $this->serverconfig, "/validate/samlcheck", "POST");
        }

        $status = True;
        $value = False;
        $realm = NULL;
        $auth_token = NULL;
        $multi_challenge = NULL;
        $transaction_id = NULL;

        if (isset($state['privacyidea:privacyidea:pinChange'])) {
            //authentication was already successful and PIN is now set
            $status = true;
            $value = true;

            $realm = $state['privacyidea:privacyidea:pinChange']['realm'];
            $auth_token = $state['privacyidea:privacyidea:pinChange']['token'];
            $token_serial = $state['privacyidea:privacyidea:pinChange']['serial'];
        } else {
            try {
                $result = $body->result;
                $detailAttributes = $body->detail;
                SimpleSAML_Logger::debug("privacyidea result:" . print_r($result, True));
                $status = $result->status;
                $value = $result->value->auth;

                if ($this->enablepinchange) {
                    // check for 4031 as a 'Wrong Credentials' should be allowed to process further
                    if ($result->error->code === 4031) {
                        $status = True;
                    }
                    // if an auth token exists, the authentication was successful
                    // send a PIN change with the saved and confirmed PIN
                    if (property_exists($result->value, "token")) {
                        $value = True;
                        $auth_token = $result->value->token;
                        SimpleSAML_Logger::debug("privacyidea auth token:" . $auth_token);

                        //if a PIN change is required, update the state to display a PIN change prompt
                        if (property_exists($body->detail, "serial")) {
                            $token_serial = $body->detail->serial;
                            $realm = $result->value->realm;
                            $expired_pins = $state['privacyidea:privacyidea:checkTokenType']['expired_pins'];
                            if (in_array($token_serial, $expired_pins, true)) {
                                $state['privacyidea:privacyidea:pinChange'] = array(
                                    "token" => $auth_token,
                                    "serial" => $token_serial,
                                    "realm" => $realm,
                                );

                                $id  = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea:init');
                                $url = SimpleSAML_Module::getModuleURL('privacyidea/otpform.php');
                                SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));
                                return true;
                            }
                        }
                    }
                }
            } catch (Exception $e) {
                throw new SimpleSAML_Error_BadRequest("We were not able to read the response from the privacyidea server.");
            }
        }

        if ($status !== True) {
            /* We got a valid JSON response, but the STATUS is false */
            throw new SimpleSAML_Error_BadRequest("Valid JSON response, but some internal error occured in privacyidea server.");
        } else {
            /* The STATUS is true, so we need to check the value */
            if ($value !== True) {
                SimpleSAML_Logger::debug("Throwing WRONGUSERPASS");
                $detail = $body->detail;

                if (property_exists($detail, "multi_challenge")) {

                	$state = sspmod_privacyidea_Auth_utils::checkTokenType($state, $body);
					$state['privacyidea:privacyidea']['username'] = $username;
					$state['forcedUsername'] = true;
					$id  = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea:init');
					$url = SimpleSAML_Module::getModuleURL('privacyidea/otpform.php');
					SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));
					return true;
                } else {
					throw new SimpleSAML_Error_Error("WRONGUSERPASS");
				}
            } else {
                if ($this->enablepinchange) {
                    $result = $this->load_user_attributes($auth_token, $token_serial, $realm);
                }
            }
        }

        $user_attributes = $result->value->attributes;
        if (!array_key_exists("username", $user_attributes)) {
            // We have the old response, where the attributes are located directly in the value
            $user_attributes = $result->value;
        }
        SimpleSAML_Logger::debug("privacyidea returned user attributes: " . print_r($user_attributes, True));
        /* status and value are true
         * We can go on and fill attributes
         */

        /* If we get this far, we have a valid login. */
        $attributes = array();
        $arr = array("username", "surname", "email", "givenname", "mobile", "phone", "realm", "resolver");
        // Add all additional attributes defined in the array map to the search array
        $arr = array_merge(array_keys($this->attributemap), $arr);
        reset($arr);
        foreach ($arr as $key) {
            SimpleSAML_Logger::debug("privacyidea        key: " . $key);
            if (array_key_exists($key, $this->attributemap)) {
                // We have a key mapping
                $mapped_key = $this->attributemap[$key];
                SimpleSAML_Logger::debug("privacyidea mapped key: " . $mapped_key);
                $attribute_value = $user_attributes->$key;                
                if ($attribute_value) {
                    SimpleSAML_Logger::debug("privacyidea Mapped key in response");
                    if(is_array($attribute_value)){
                        $attributes[$mapped_key] = $attribute_value;
                    }
                    else{
                        // If attribute is a string, we create an array
                        $attributes[$mapped_key] = array($attribute_value);
                    }
                    SimpleSAML_Logger::debug("privacyidea      value: " . print_r($attributes[$mapped_key], TRUE));
                }
            } else {
                // We have no keymapping and just transfer the attribute
                SimpleSAML_Logger::debug("privacyidea unmapped key: " . $key);
                if ($user_attributes->$key) {
                    $attribute_value = $user_attributes->$key;
                    if(is_array($attribute_value)){
                        $attributes[$key] = $attribute_value;
                    }
                    else{
                        $attributes[$key] = array($attribute_value);
                    }
                    SimpleSAML_Logger::debug("privacyidea        value: " . print_r($attributes[$key], TRUE));
                }
            }
        }
        $detailarr = array_keys($this->detailmap);
        reset($detailarr);
        foreach ($detailarr as $key) {
	        SimpleSAML_Logger::debug("privacyidea        key: " . print_r($key, TRUE));
        	$mapped_key = $this->detailmap[$key];
	        SimpleSAML_Logger::debug("privacyidea mapped key: " . print_r($mapped_key, TRUE));
        	$attribute_value = $detailAttributes->$key;
	        if(is_array($attribute_value)){
		        $attributes[$mapped_key] = $attribute_value;
	        }
	        else{
		        // If attribute is a string, we create an array
		        $attributes[$mapped_key] = array($attribute_value);
	        }

        }

        $concatenation = array_keys($this->concatenationmap);
        reset($concatenation);
        foreach ($concatenation as $key) {
        	SimpleSAML_Logger::debug("privacyidea        key: " . print_r($key, TRUE));
        	$mapped_key = $this->concatenationmap[$key];
        	SimpleSAML_Logger::debug("privacyidea mapped key: " . print_r($mapped_key, TRUE));
        	$concatenationArr = explode(",", $key);
        	$concatenationValues = array();
        	foreach ($concatenationArr as $item) {
        		$concatenationValues[] = $user_attributes->$item;
	        }
			$concatenationString = implode(" ", $concatenationValues);
			$attributes[$mapped_key] = array($concatenationString);
        }

        SimpleSAML_Logger::debug("privacyidea Array returned: " . print_r($attributes, True));
        return $attributes;
    }


    /**
     * Initialize login.
     *
     * This function saves the information about the login, and redirects to a
     * login page.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(&$state)
    {
        assert('is_array($state)');

        /* We are going to need the authId in order to retrieve this authentication source later. */
        $state[self::AUTHID] = $this->authId;
        $state['privacyidea:privacyidea:authenticationMethod'] = "authsource";
        SimpleSAML_Logger::debug("privacyIDEA authId: " . $this->authId);

        $id = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea:init');

        $url = SimpleSAML_Module::getModuleURL('privacyidea/otpform.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));
    }

    /**
     * Handle login request.
     *
     * This function is used by the login form (core/www/loginuserpass.php) when the user
     * enters a username and password. On success, it will not return. On wrong
     * username/password failure, and other errors, it will throw an exception.
     *
     * @param string $authStateId The identifier of the authentication state.
     * @param string $username The username the user wrote.
     * @param string $password The password the user wrote.
     * @param $transaction_id
     * @param $signaturedata
     * @param $clientdata
     * @throws Exception
     */
    public static function handleLogin($authStateId, $username, $password, $transaction_id = NULL, $signaturedata = NULL, $clientdata = NULL)
    {
        assert('is_string($authStateId)');
        assert('is_string($username)');
        assert('is_string($password)');
        assert('is_string($transaction_id)');

        SimpleSAML_Logger::debug("calling privacyIDEA handleLogin with authState: " . $authStateId . " for user " . $username);
        if (array_key_exists("OTP", $_REQUEST)) {
            $otp = $_REQUEST["OTP"];
            $password = $password . $otp;
            SimpleSAML_Logger::stats('Found OTP in Auth request. Concatenating passwords.');
        }

        // sanitize the input
        $sid = SimpleSAML_Utilities::parseStateID($authStateId);
        if (!is_null($sid['url'])) {
            SimpleSAML_Utilities::checkURLAllowed($sid['url']);
        }

        /* Here we retrieve the state array we saved in the authenticate-function. */
        $state = SimpleSAML_Auth_State::loadState($authStateId, "privacyidea:privacyidea:init");

        /* Retrieve the authentication source we are executing. */
        assert('array_key_exists(self::AUTHID, $state)');
        $source = SimpleSAML_Auth_Source::getById($state[self::AUTHID]);
        if ($source === NULL) {
            throw new Exception('Could not find authentication source with id ' . $state[self::AUTHID]);
        }

        /*
         * $source now contains the authentication source on which authenticate()
         * was called. We should call login() on the same authentication source.
         */

        /* Attempt to log in. */
        try {
            $attributes = $source->login_chal_resp($state, $username, $password, $transaction_id, $signaturedata, $clientdata);
        } catch (Exception $e) {
            SimpleSAML_Logger::stats('Unsuccessful login attempt from ' . $_SERVER['REMOTE_ADDR'] . '.');
            throw $e;
        }

        SimpleSAML_Logger::stats('User \'' . $username . '\' has been successfully authenticated.');

        /* Save the attributes we received from the login-function in the $state-array. */
        assert('is_array($attributes)');
        $state['Attributes'] = $attributes;

        /* Return control to simpleSAMLphp after successful authentication. */
        SimpleSAML_Auth_Source::completeAuth($state);
    }


}
