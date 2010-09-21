=====================
Haskell OAuth Library
=====================

A Haskell library that implements oauth authentication protocol as
defined in http://tools.ietf.org/html/draft-hammer-oauth- 10.

Example
-------

The following code should perform a 3 legged oauth request using Yahoo
as the service provider::

  reqUrl   = fromJust $ parseURL "https://api.login.yahoo.com/oauth/v2/get_request_token"
  accUrl   = fromJust $ parseURL "https://api.login.yahoo.com/oauth/v2/get_token"
  srvUrl   = fromJust $ parseURL "http://query.yahooapis.com/v1/yql?q=select%20%2A%20from%20social.profile%20where%20guid%3Dme"
  authUrl  = head . find (=="xoauth_request_auth_url") . oauthParams
  app      = Application "<consumer key>" "<consumer secret>" OOB
  response = runOAuthM_ $ do { ignite app
                             ; signRq2 PLAINTEXT Nothing reqUrl >>= oauthRequest CurlClient
                             ; cliAskAuthorization authUrl
                             ; signRq2 PLAINTEXT Nothing accUrl >>= oauthRequest CurlClient
                             ; signRq2 HMACSHA1 (Just $ Realm "yahooapis.com") srvUrl >>= serviceRequest CurlClient
  
                             }

Another example, this time using Twitter as the service provider::

  reqUrl   = fromJust $ parseURL "http://twitter.com/oauth/request_token"
  accUrl   = fromJust $ parseURL "http://twitter.com/oauth/access_token"
  srvUrl   = fromJust $ parseURL "http://api.twitter.com/1/statuses/home_timeline.xml"
  authUrl  = ("http://twitter.com/oauth/authorize?oauth_token="++) . findWithDefault ("oauth_token","") . oauthParams
  app      = Application "<consumer key>" "<consumer secret>" OOB
  response = runOAuthM_ $ do { ignite app
                             ; signRq2 HMACSHA1 Nothing reqUrl >>= oauthRequest CurlClient
                             ; cliAskAuthorization authUrl
                             ; signRq2 HMACSHA1 Nothing accUrl >>= oauthRequest CurlClient
                             ; signRq2 HMACSHA1 Nothing srvUrl >>= serviceRequest CurlClient
                             }

References
----------

* ./src/test/haskell/test_hoauth.hs
* http://oauth.net/

Changelog
---------

::

  v0_3_0

* Consumer: OAuthMonad is now OAuthMonadT. Major change is that users may now provide custom error handler instead of fail
* HttpClient: completely rewritten with better error handling support
* HttpClient: Extracting curl instance into its own module
* CurlHttpClient: ignoring SSL certificate errors
* CurlHttpClient: defining a timeout of 30s

::

  v0_2_5

* bugfix: freezing when doing PUT or POST requests

::

  v0_2_4

* Adding completeRequest function
* Using fail instead of Either type in oauthRequest to signal failures

::

  v0_2_3

* Exporting OAuthToken to the world

::

  v0_2_2

* Adding unlift function to HttpClient class
* Minor improvements on the documentation
* Word8 is now instance of PercentEncoding

::

  V0_2_1
  v0_2_0

* API is now capable of performing HTTP requests, thus fully capable of dealing with the OAuth protocol;
* Temporally dropped RSA signature support;

::

  V0_1_9
  v0_1_8
  v0_1_7
  V0_1_6
  v0_1_5

* minor change: another attempt to fix haddock errors on hackage

::

  v0_1_4
  V0_1_3

* minor change: adding nonce_and_timestamp function

::

  V0_1_2

* minor change: using Control.Monad in Consumer#response function
* minor change: removing useless apply function in Request
* minor change: changing append_param function interface

::

  v0_1_1

* fixing compiler warnings
* fixing haddock errors/warnings

::

  v0_1_0

* implementing RSA-SHA1 signature method

::

  v0_0_4

* Changing the license to BSD3

::

  v0_0_3

* Adding/Implementing a few utility functions

::

  v0_0_1

* First release
