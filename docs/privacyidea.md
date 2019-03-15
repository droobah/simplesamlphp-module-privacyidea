privacyidea module
==================

This module provides an authentication module for simpleSAMLphp to talk
to the privacyIDEA authentication server.

`privacyidea:privacyidea`
: Authenticate a user against a privacyidea server.

The module contacts the privacyIDEA server via the API

  https://privacyidea/validate/samlcheck
 
and authenticates the user according to the token assigned to the user.

The response can also contain some attributes.

To enable this module, create a file 'enable' in the
directorpy 'modules/privacyidea/'.


You can use this plugin in two different ways
Method 1) authenticate against privacyIDEA only
Method 2) authenticate the 1st factor against your authsource and the 2nd factor against privacyIDEA



Method 1
========


You need to add the authentication source 'privacyidea:privacyidea' to
'config/authsources.php'. Do it like this:

```PHP
'example-privacyidea' => array(
    'privacyidea:privacyidea',

    /* 
     * The URI (including protocol and port) of the privacyidea server
     * Required.
     */
    'privacyideaserver' => 'https://your.server.com',

    /*
     * Check if the hostname matches the name in the certificate
     * Optional.
     */
    'sslverifyhost' => False,

    /*
     * Check if the certificate is valid, signed by a trusted CA
     * Optional.
     */
    'sslverifypeer' => False,
        
    /*
     * The realm where the user is located in.
     * Optional.
     */
    'realm' => '',

    /*
     * OTP Extra
     * 0: (default) one password field for PIN and OTP
     * 1: Password field for password and extra field for OTP
     */
    'otpextra' => 1,
        
    /*
     * Enable Pin Change
     * 0: (default) user will not be notified to change their PIN
     * 1: User will be prompted to change an expired PIN
     */
    'enablepinchange' => 1,
     
    /*
     * This is the translation from privacyIDEA attribute names to 
     * SAML attribute names.
     * Optional.
     */
    'attributemap' => array(
        'username' => 'samlLoginName',
        'surname' => 'surName',
        'givenname' => 'givenName',
        'email' => 'emailAddress',
        'phone' => 'telePhone',
        'mobile' => 'mobilePhone'
    ),

    /*
     * You are able to concatenate attributes like the given and surname.
     * Optional.
     */
    'concatenationmap' => array(
        'givenname,surname' => 'fullName',
    ),

    /*
     * Here the detail attributes can be edited.
     * If they should not be listed, just remove them.
     * Optional.
     */
    'detailmap' => array(
        'message' => 'message',
        'type' => 'otpType',
        'serial' => 'otpSerial',
        'otplen' => 'otpLength'
    ),
),
```


User attributes
---------------
At the moment privacyIDEA will know and return the following attributes by default, 
that can be mapped to SAML attributes:

username:	The login name
surname:	The real world name of the user as it is retrieved from the user source
givenname:	The real world name of the user as it is retrieved from the user source
mobile:		The mobile phone number of the user as it is retrieved from the user source
phone:		The phone number of the user as it is retrieved from the user source
email:		The email address of the user as it is retrieved from the user source                                
                                
The list can be extended by including custom attributes in the attributemap. If the 
privacyIDEA server returns an attribute 'groups', you can map that to 'groups' if
you include it in the attributemap. Otherwise, it is discarded.




Method 2
========


If you want to use privacyIDEA as an auth proc filter, change the metadata.
Use the following example:

```PHP
'authproc' => array(

    /**
     *  The first authproc filter conatins the configuration for the privacyIDEA server.
     */
    20 => array(
        'class'             => 'privacyidea:serverconfig',

        /**
         *  Enter the URL to your privacyIDEA instance
         */
        'privacyideaserver' => 'https://your.privacyidea.server',
        
        /**
         *  Enter the realm, where your users are stored (remove it or set it to '' to use default)
         */
        'realm'             => 'realm1',

        /**
         *  The uidKey is the username's attribute key.
         *  You can choose a single one or multiple ones. The first set will be used.
         */
        'uidKey'            => 'uid',
        //  'uidKey'        => array('uid', 'userName', 'uName'),

        /**
         *  Check if the hostname matches the name in the certificate (set to true or false)
         */
        'sslverifyhost'     => true,

        /**
         *  Check if the certificate is valid, signed by a trusted CA
         */
        'sslverifypeer'     => true,

        /**
         *  Here you need to enter the username of your service account
         */
        'serviceAccount'    => 'service',

        /**
         *  Enter here the password for your service account
         */
        'servicePass'       => 'service',

        /**
         *  You can enable or disable trigger challenge
         */
        'doTriggerChallenge' => true,
        
        /**
         *  Other authproc filters can disable 2FA if you want to.
         *  If privacyIDEA should listen to the setting, you have to enter the state's path and key.
         *  The value of this key will be set by a previous auth proc filger.
         *  privacyIDEA will only be disabled, if the value of the key is set to false,
         *  in any other situation (e.g. the key is not set or does not exist), privacyIDEA will be enabled.
         */
        'enabledPath'       => '',
        'enabledKey'        => '',

        /**
         *  If you want to use passOnNoToken or passOnNoUser, you can decide, if this module should send a password to
         *  privacyIDEA. If passOnNoToken is activated and the user does not have a token, he will be passed by privacyIDEA.
         *  NOTE: Do not use it with privacyidea:tokenEnrollment.
         */

        'tryFirstAuthentication' => true,

        /**
         *  You can decide, which password should be used for tryFirstAuthentication
         */

         'tryFirstAuthPass' => 'simpleSAMLphp',
    ),

    /**
     *  This filter is optional, if you want to disable clients by ip, you should enable it.
     */
    21 => array(
        'class'             => 'privacyidea:checkClientIP',

        /**
         *  You can exclude clients with specified ip addresses.
         *  Enter a range like "10.0.0.0-10.2.0.0" or a single ip like "192.168.178.2"
         *  The selected ip addresses do not need 2FA
         */
        'excludeClientIPs'  => array("10.0.0.0-10.2.0.0", "192.168.178.2"),
    ),

    /**
     *  This filter is optional. You can enable it, if you want to enroll tokens for users, who do not have one yet.
     */
    24 => array(
        'class'             => 'privacyidea:tokenEnrollment',

        /**
         *  You can select a time based otp (totp), an event based otp (hotp) or a u2f (u2f)
         */
        'tokenType'         => 'totp',

        /**
         *  If it is needed, you can overwrite the configuration here.
         *  You have to use the same name as it is in privacyidea:serverconfig
         *  For example:
         *  'serviceAccount' => 'service',
         *  'servicePass' => 'service',
         */
    ),

    /**
     *  This filter triggers the authentication against privacyIDEA. If this is not enabled, you will not be able to use 2FA
     */
    25 => array(
        'class'             => 'privacyidea:privacyidea',
        
        /**
         *  If it is needed, you can overwrite the configuration here.
         *  You have to use the same name as it is in privacyidea:serverconfig
         *  For example:
         *  'serviceAccount' => 'service',
         *  'servicePass' => 'service',
         */
),
```
