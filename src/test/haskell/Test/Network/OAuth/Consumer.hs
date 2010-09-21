-- Copyright (c) 2009, Diego Souza
-- All rights reserved.
-- 
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions are met:
-- 
--   * Redistributions of source code must retain the above copyright notice,
--     this list of conditions and the following disclaimer.
--   * Redistributions in binary form must reproduce the above copyright notice,
--     this list of conditions and the following disclaimer in the documentation
--     and/or other materials provided with the distribution.
--   * Neither the name of the <ORGANIZATION> nor the names of its contributors
--     may be used to endorse or promote products derived from this software
--     without specific prior written permission.
-- 
-- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-- ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-- WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-- DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
-- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
-- SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
-- CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
-- OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
-- OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

module Test.Network.OAuth.Consumer where

import qualified Test.HUnit as T
import Control.Monad.Fix
import Control.Monad.Trans
import Data.Maybe
import Data.List
import Data.Char (ord,chr)
import Network.OAuth.Consumer
import Network.OAuth.Http.Request
import Network.OAuth.Http.Response
import Network.OAuth.Http.CurlHttpClient
import Network.OAuth.Http.PercentEncoding
import qualified Data.ByteString.Lazy as B
import qualified Data.Binary as Bi
import qualified Codec.Crypto.RSA as R

ftest0 = T.TestCase $ do
  let token     = fromApplication $ Application "dpf43f3p2l4k3l03" "kd94hf93k423kf44" (URL "http://printer.example.com/request_token_ready")
      nonce     = Nonce "hsu94j3884jdopsl" 
      timestamp = Timestamp "1191242090" 
      assert    = "OAuth "
                  ++ "oauth_signature=\"kd94hf93k423kf44%26\""
                  ++ ",oauth_consumer_key=\"dpf43f3p2l4k3l03\""
                  ++ ",oauth_nonce=\"hsu94j3884jdopsl\""
                  ++ ",oauth_timestamp=\"1191242090\""
                  ++ ",oauth_signature_method=\"PLAINTEXT\""
                  ++ ",oauth_version=\"1.0\""
                  ++ ",oauth_callback=\""++ encode "http://printer.example.com/request_token_ready" ++"\""
      Just request  = parseURL "https://photos.example.net:443/request_token"
  T.assertEqual
    "test request method signs correctly using oauth (REQUEST,PLAINTEXT)"
    (assert)
    (authorization PLAINTEXT Nothing nonce timestamp token request)

ftest1 = T.TestCase $ do
  let fakeResp  = RspHttp 200 
                          "HTTP/1.1 200 OK" 
                          (fromList [("content-type","application/x-www-form-urlencoded")]) 
                          (B.pack . map (fromIntegral.ord) $ "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true")
      Right token = fromResponse fakeResp (fromApplication $ Application "dpf43f3p2l4k3l03" "kd94hf93k423kf44" OOB)
      nonce     = Nonce "hsu94j3884jdopsl"
      timestamp = Timestamp "1191242090"
      verifier  = "hfdp7dh39dks9884"
      assert    = "OAuth "
                  ++ "oauth_signature=\"kd94hf93k423kf44%26hdhd0244k9j7ao03\""
                  ++ ",oauth_consumer_key=\"dpf43f3p2l4k3l03\""
                  ++ ",oauth_nonce=\"hsu94j3884jdopsl\""
                  ++ ",oauth_timestamp=\"1191242090\""
                  ++ ",oauth_signature_method=\"PLAINTEXT\""
                  ++ ",oauth_version=\"1.0\""
                  ++ ",oauth_verifier=\"hfdp7dh39dks9884\""
                  ++ ",oauth_token=\"hh5s93j4hdidpola\""
      Just request = parseURL "https://photos.example.net:443/access_token"

  T.assertEqual
    "test request method signs correctly using oauth (ACCESS,PLAINTEXT)"
    (assert)
    (authorization PLAINTEXT Nothing nonce timestamp (injectOAuthVerifier "hfdp7dh39dks9884" token) request)

ftest2 = T.TestCase $ do
  let app         = Application "foo" "bar" OOB
      payload     = B.pack . map (fromIntegral.ord) $ "oauth_token_secret=foobar&oauth_callback_confirmed=true"
      message     = "missing required keys"
      errorMsg    = "Missing at least one required oauth parameter [expecting=[\"oauth_token\",\"oauth_token_secret\",\"oauth_callback_confirmed\"], response=status: 200, reason: missing required keys]"
      Left result = fromResponse (RspHttp 200 message empty payload) (fromApplication app)

  T.assertEqual
    "test response without oauth_token do nothing"
    errorMsg
    result
  
ftest3 = T.TestCase $ do
  let app         = Application "foo" "bar" OOB
      payload     = B.pack . map (fromIntegral.ord) $ "oauth_token=foobar&oauth_callback_confirmed=true"
      message     = "missing required keys"
      errorMsg    = "Missing at least one required oauth parameter [expecting=[\"oauth_token\",\"oauth_token_secret\",\"oauth_callback_confirmed\"], response=status: 200, reason: missing required keys]"
      Left result = fromResponse (RspHttp 200 message empty payload) (fromApplication app)

  T.assertEqual
    "test response without oauth_token_secret do nothing"
    errorMsg
    result

ftest4 = T.TestCase $ do
  let app         = Application "foo" "bar" OOB
      payload     = B.pack . map (fromIntegral.ord) $ "oauth_token=foobar&oauth_token_secret=true"
      message     = "missing required keys"
      errorMsg    = "Missing at least one required oauth parameter [expecting=[\"oauth_token\",\"oauth_token_secret\",\"oauth_callback_confirmed\"], response=status: 200, reason: missing required keys]"
      Left result = fromResponse (RspHttp 200 message empty payload) (fromApplication app)

  T.assertEqual
    "test response without oauth_callback_confirmed do nothing"
    errorMsg
    result

ftest5 = T.TestCase $ do
  let app      = Application "foo" "bar" OOB
      payload  = B.pack . map (fromIntegral.ord)
      noToken  = fromApplication app
      Right reqToken = fromResponse (RspHttp 200 "" empty (payload "oauth_token=foobar&oauth_token_secret=foobar&oauth_callback_confirmed=true")) noToken
      Right accToken = fromResponse (RspHttp 200 "" empty (payload "oauth_token=foobar&oauth_token_secret=foobar")) reqToken
  
  T.assertBool
    "test initial token is not 2-legged neither 3-legged"
    (twoLegged noToken)

  T.assertBool
    "test valid reponse produces a 2-legged token"
    (not (twoLegged reqToken) && not (threeLegged reqToken))

  T.assertBool
    "test valid response produces a 3-legged token"
    (threeLegged accToken)

ftest6 = T.TestCase $ do
  let app      = Application "foo" "bar" OOB
      payload  = B.pack . map (fromIntegral.ord)
      noToken  = fromApplication app
      Right reqToken = fromResponse (RspHttp 200 "" empty (payload "oauth_token=foobar&oauth_token_secret=foobar&oauth_callback_confirmed=true&foo=bar&bar=foo")) noToken
  
  T.assertBool
    "test fromResponse captures extra parameters"
    ((findWithDefault ("foo","") (oauthParams reqToken)) == "bar")

  T.assertBool
    "test fromResponse captures extra parameters"
    ((findWithDefault ("bar","") (oauthParams reqToken)) == "foo")

ftest7 = T.TestCase $ do
  let app       = Application "dpf43f3p2l4k3l03" "kd94hf93k423kf44" OOB
      payload   = B.pack . map (fromIntegral.ord)
      noToken   = fromApplication app 
      Right reqToken = fromResponse (RspHttp 200 "" empty (payload "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00&oauth_callback_confirmed=true")) noToken
      nonce          = Nonce "kllo9940pd9333jh"
      timestamp      = Timestamp "1191242096"
      Just request   = parseURL "http://photos.example.net/photos?file=vacation.jpg&size=original"
      expected  = "OAuth "
                  ++ "oauth_signature=\"" ++ encode "tR3+Ty81lMeYAr/Fid0kMTYa/WM=" ++"\""
                  ++ ",oauth_consumer_key=\"dpf43f3p2l4k3l03\""
                  ++ ",oauth_nonce=\"kllo9940pd9333jh\""
                  ++ ",oauth_timestamp=\"1191242096\""
                  ++ ",oauth_signature_method=\"HMAC-SHA1\""
                  ++ ",oauth_version=\"1.0\""
                  ++ ",oauth_token=\"nnch734d00sl2jdk\""

  T.assertEqual
    "test request method signs correctly using oauth (REQUEST,HMAC-SHA1)"
    (expected)
    (authorization HMACSHA1 Nothing nonce timestamp reqToken request)

ftest8 = T.TestCase $ do
  let app       = Application "dpf43f3p2l4k3l03" "kd94hf93k423kf44" OOB
      payload   = B.pack . map (fromIntegral.ord)
      noToken   = fromApplication app 
      Right reqToken = fromResponse (RspHttp 200 "" empty (payload "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00&oauth_callback_confirmed=true")) noToken
      Right accToken = fromResponse (RspHttp 200 "" empty (payload "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00")) reqToken
      nonce          = Nonce "kllo9940pd9333jh"
      timestamp      = Timestamp "1191242096"
      Just request   = parseURL "http://photos.example.net/photos?file=vacation.jpg&size=original"
      expected  = "OAuth "
                  ++ "oauth_signature=\"" ++ encode "tR3+Ty81lMeYAr/Fid0kMTYa/WM=" ++"\""
                  ++ ",oauth_consumer_key=\"dpf43f3p2l4k3l03\""
                  ++ ",oauth_nonce=\"kllo9940pd9333jh\""
                  ++ ",oauth_timestamp=\"1191242096\""
                  ++ ",oauth_signature_method=\"HMAC-SHA1\""
                  ++ ",oauth_version=\"1.0\""
                  ++ ",oauth_token=\"nnch734d00sl2jdk\""

  T.assertEqual
    "test request method signs correctly using oauth (ACCESS,HMAC-SHA1)"
    (expected)
    (authorization HMACSHA1 Nothing nonce timestamp accToken request)

ftest9 = T.TestCase $ do
  let app      = Application "" "" OOB
      payload  = B.pack . map (fromIntegral.ord)
      notoken  = fromApplication app
      Right reqToken = fromResponse (RspHttp 200 "" empty (payload "oauth_token=&oauth_token_secret=&oauth_callback_confirmed=true")) notoken
      Right accToken = fromResponse (RspHttp 200 "" empty (payload "oauth_token=&oauth_token_secret=")) reqToken
  
  T.assertEqual
    "test injectOAuthVerifier is `id' when token is a 2legged token"
    ""
    (findWithDefault ("oauth_verifier","") (oauthParams $ injectOAuthVerifier "foobar" notoken))

  T.assertEqual
    "test injectOAuthVerifier works for request tokens"
    "foobar"
    (findWithDefault ("oauth_verifier","") (oauthParams $ injectOAuthVerifier "foobar" reqToken))

  T.assertEqual
    "test injectOAuthVerifier is `id` when token is an access token"
    ""
    (findWithDefault ("oauth_verifier","") (oauthParams $ injectOAuthVerifier "foobar" accToken))

ftest10 = T.TestCase $ do
  let app     = Application "consumerKey" "consumerSec" OOB
      payload = B.pack . map (fromIntegral.ord)
      notoken = fromApplication app
      Right reqToken = fromResponse (RspHttp 200 "" empty (payload "oauth_token=&oauth_token_secret=&oauth_callback_confirmed=true")) notoken
      Right accToken = fromResponse (RspHttp 200 "" empty (payload "oauth_token=&oauth_token_secret=")) reqToken

  T.assertBool
    "test decode . encode = id (Binary) [TwoLegged]"
    (notoken == (Bi.decode . Bi.encode $ notoken))

  T.assertBool
    "test decode . encode = id (Binary) [ReqToken]"
    (reqToken ==  (Bi.decode . Bi.encode $ reqToken))

  T.assertBool
    "test decode . encode = id (Binary) [AccessToken]"
    (accToken == (Bi.decode . Bi.encode $ accToken))

ftest11 = T.TestCase $ do
  let app0 = Application "consumerKey" "consumerSec" OOB
      app1 = Application "consumerKey" "consumerSec" (URL "url")

  T.assertBool
    "test decode . encode = id (Binary) [Application]"
    (app0 == (Bi.decode . Bi.encode $ app0))

  T.assertBool
    "test decode . encode = id (Binary) [Application]"
    (app1 == (Bi.decode . Bi.encode $ app1))

-- to generate the test data to the following tests:
-- $ openssl genrsa -out rsa -in 1024 
-- $ openssl rsa -text -in rsa # copy modulus and privateExponent
-- $ echo -n 'GET&http%3A%2F%2Ffoo.bar%3A8080%2Ffoobar&bar%3Dfoo%26foo%3Dbar' | openssl dgst -sign rsa -sha1 | base64 -w 64
-- rsa key:
-- -----BEGIN RSA PRIVATE KEY-----
-- MIICXAIBAAKBgQDOP+avZbhdd0SihyaPCupP14MAW2MG81Pp5JqVg/fU68eHCmX8
-- MMzdXOeoS41ak1bwauPQBZnlyL2jtUP0MxzPBP2THhCNdeSr6pwSD0b+c1E4wxNE
-- 5LdKF4jt8WHZwqxvjMmTkn/KtO+Va3FQJ42u0NLWMEE6WtVmWAJqO8s87QIDAQAB
-- AoGAF+VNa9rkLmgIGrB/5ijElvWIJv1vjrmYakvjIRmGGDQtDNdGk55vzeHasSP3
-- v5u8geRQeqR7fSTx28q/kcZuOtSQYFvMNqhWi84n3J0VhNw+RDSZ+BncCp0rAjP1
-- rm2KuENRIcgR/8elSRcYR50kbVLycXLlkD9mgUQxGG7GB+ECQQD6HxnUX90Qd6/N
-- TfbFTd3VTeVAb+JGTkR0Pn57vCyZG6cnqedZwweSLGat+6F6CWPNWu9dBXodHLbF
-- h5ZfYdl1AkEA0xjWZ05+rmmTIpwQZpfLFvID4Ro911m7qNUx5YSwmAMERadw15xv
-- Ml7SNmrnPN9o32agSAXNOQJ3T8dft2BumQJAcolpb5pShib4x2ArX+Cvc+1OzPov
-- ORjAOicgDpN2LMq/+ebQ/YbU4bgZcRSotlS0ciZxNDy81bX/cGcNkjIhvQJBAMjZ
-- Ae4q5idmNeMhIA2s8UN0ozJC+IH0U7OwnRfmpusLO75WMOxEYBxJ0bKLBlaJrkuY
-- ZnoAYyGR8hlK9gwQyUkCQCkk+FG2ziItInzwwLJfUeHaSMa3o8W39l8hVbFOyLRE
-- IEhf7DCGXGJril4U3uyoP7kCzsqIKE2WZ9SRlLwccDs=
-- -----END RSA PRIVATE KEY-----
ftest12 = T.TestCase $ do
  let modulus  = 0x00ce3fe6af65b85d7744a287268f0aea4fd783005b6306f353e9e49a9583f7d4ebc7870a65fc30ccdd5ce7a84b8d5a9356f06ae3d00599e5c8bda3b543f4331ccf04fd931e108d75e4abea9c120f46fe735138c31344e4b74a1788edf161d9c2ac6f8cc993927fcab4ef956b7150278daed0d2d630413a5ad56658026a3bcb3ced
      expoent  = 0x17e54d6bdae42e68081ab07fe628c496f58826fd6f8eb9986a4be321198618342d0cd746939e6fcde1dab123f7bf9bbc81e4507aa47b7d24f1dbcabf91c66e3ad490605bcc36a8568bce27dc9d1584dc3e443499f819dc0a9d2b0233f5ae6d8ab8435121c811ffc7a5491718479d246d52f27172e5903f66814431186ec607e1
      numbytes = 128
      key      = R.PrivateKey numbytes modulus expoent
      Just req = parseURL "http://foo.bar:8080/foobar?foo=bar&bar=foo"
  T.assertEqual
    "test sign_request (RSA-SHA1)"
    ("JUIS4p4Qgcw7r/6HdplUSZSx2YHLfB/Va6736VbBQSBdk/F1NK0YvQtaRoY67aXvyXrwZGajC4BdHSe53HB7cIBhqdwKmnFqZZw9Bc2yMeoINZqDOctUIXgP0qpc3vflACW1SFQARKUTTKxvmWNPApWPsS44eRZOedjIr25waF0=")
    (signature (RSASHA1 key) NoToken req)

ftest13 = T.TestCase $ do
  let modulus   = 0x00ce3fe6af65b85d7744a287268f0aea4fd783005b6306f353e9e49a9583f7d4ebc7870a65fc30ccdd5ce7a84b8d5a9356f06ae3d00599e5c8bda3b543f4331ccf04fd931e108d75e4abea9c120f46fe735138c31344e4b74a1788edf161d9c2ac6f8cc993927fcab4ef956b7150278daed0d2d630413a5ad56658026a3bcb3ced
      expoent   = 0x17e54d6bdae42e68081ab07fe628c496f58826fd6f8eb9986a4be321198618342d0cd746939e6fcde1dab123f7bf9bbc81e4507aa47b7d24f1dbcabf91c66e3ad490605bcc36a8568bce27dc9d1584dc3e443499f819dc0a9d2b0233f5ae6d8ab8435121c811ffc7a5491718479d246d52f27172e5903f66814431186ec607e1
      numbytes  = 128
      key       = R.PrivateKey numbytes modulus expoent
      Just req0 = parseURL "http://foo.bar:80/foobar?foo=bar&bar=foo"
      Just req1 = parseURL "https://foo.bar:443/foobar?foo=bar&bar=foo"
  T.assertEqual
    "test sign_request (RSA-SHA1) ignores default port (http,80)"
    ("wspZGQBp1Gv0guYxVYTVllAtasGa9AaSAGcraB15Chgv0MXs4lSt/PPY41WGdQzT3K3D8l2veBeJEqEka63vSJNnDyMPb38oTJrRyn1TvaZzXq4Oyp2y6lgmxL9x4xOrLLGBIMQ8T2gWL+eQJ7FeqTL83MdMqUulyJfxc9PeObA=") -- msg:PUT&http%3A%2F%2Ffoo.bar%2Ffoobar&bar%3Dfoo%26foo%3Dbar
    (signature (RSASHA1 key) NoToken (req0 { method = PUT }))

  T.assertEqual
    "test sign_request (RSA-SHA1) ignores default port (https,443)"
    ("AjwVGN2wkvDjb/bGDqMtAzwn9hhx3nCH2GIR+puXim4qMk1Qy7aJCDrDyBNPgzET/4lr3bwPSK0UaBO4iyp5e4Zv5BGp0VWkP7clQZaqR56/zKpcgvKav9Ge7tM02dR0XoODfSBk94ckyotTp1F4cmF4bEe1mHlsabWbJXQq29k=") -- msg:DELETE&https%3A%2F%2Ffoo.bar%2Ffoobar&bar%3Dfoo%26foo%3Dbar
    (signature (RSASHA1 key) NoToken (req1 { method = DELETE }))

stest0 = T.TestCase $ do
  let app          = Application "dj0yJmk9WjN6WTBncG5BMTlOJmQ9WVdrOVdWcE1WRTAwTldrbWNHbzlOakUxT1RJM01UUTMmcz1jb25zdW1lcnNlY3JldCZ4PWY4" "02a8b7e40e348a0f2025dd1d3c627f7a1e60e844" OOB
      Just yqlUrl  = parseURL "http://query.yahooapis.com/v1/yql?q=select%20%2A%20from%20yahoo.identity%20where%20yid%3D%22yahoo%22%3B"
      ioresp       = runOAuthM_ $ do { ignite app
                                     ; signRq2 HMACSHA1 (Just $ Realm "yahooapis.com") yqlUrl >>= serviceRequest CurlClient
                                     }

  response <- ioresp
  T.assertEqual
    ("test 2legged authentication works with yql ("++ (reason response) ++")")
    (200)
    (status response)

fast_tests = [ftest0,ftest1,ftest2,ftest3,ftest4,ftest5,ftest6,ftest7,ftest8,ftest9,ftest10,ftest11,ftest12,ftest13]
slow_tests = [stest0]

