<?php
session_start();
require_once("../LinkedInOAuth.php");

define('LINKEDIN_CONSUMER_KEY', 'YOUR CONSUMER KEY');
define('LINKEDIN_CONSUMER_SECRET', 'YOUR CONSUMER SECRET');


$oauth = new LinkedInOAuth(LINKEDIN_CONSUMER_KEY, LINKEDIN_CONSUMER_SECRET); 
// your url to linkedin-callback.php
$callback = "http://example.com/linkedin-callback.php";
// after being directed to the provider's website, the user will be redirected
// to the callback url
$credentials = $oauth->getRequestToken($callback);

// you don't necessary have to use sessions, but it's one way
$_SESSION['linkedin_oauth_credentials'] = serialize($credentials);

$authorize_url = $oauth->getAuthorizeURL($credentials);

header("Location: $authorize_url");

?>
