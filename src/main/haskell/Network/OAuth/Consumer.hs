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

-- | A Haskell library that implements oauth authentication protocol as defined in <http://tools.ietf.org/html/draft-hammer-oauth-10>.
--  
-- According to the RFC [1]:
--   OAuth provides a method for clients to access server resources on behalf
--   of a resource owner (such as a different client or an end- user).  It also
--   provides a process for end-users to authorize third- party access to their
--   server resources without sharing their credentials (typically, a username and
--   password pair), using user- agent redirections.
-- 
-- The following code should perform a request using 3 legged oauth, provided the parameters are defined correctly:
-- 
-- >  reqUrl   = fromJust . parseURL $ "https://service.provider/request_token"
-- >  accUrl   = fromJust . parseURL $ "https://service.provider/access_token"
-- >  srvUrl   = fromJust . parseURL $ "http://service/path/to/resource/"
-- >  authUrl  = ("http://service.provider/authorize?oauth_token="++) . findWithDefault ("oauth_token","") . oauthParams
-- >  app      = Application "consumerKey" "consumerSec" OOB
-- >  response = runOAuth $ do ignite app
-- >                           oauthRequest PLAINTEXT Nothing reqUrl
-- >                           cliAskAuthorization authUrl
-- >                           oauthRequest PLAINTEXT Nothing accUrl
-- >                           serviceRequest HMACSHA1 (Just "realm") srvUrl
--
module Network.OAuth.Consumer (
                     -- * Types
                      Token(..)
                     ,Application(..)
                     ,OAuthCallback(..)
                     ,SigMethod(..)
                     ,Realm
                     ,Nonce
                     ,Timestamp
                     ,OAuthMonad
                     -- * OAuthMonad related functions
                     ,runOAuth
                     ,oauthRequest
                     ,completeRequest
                     ,serviceRequest
                     ,cliAskAuthorization
                     ,ignite
                     ,getToken
                     ,putToken
                     -- * Token related functions
                     ,twoLegged
                     ,threeLegged
                     ,signature
                     ,injectOAuthVerifier
                     ,fromApplication
                     ,fromResponse
                     ,authorization
                     ) where

import Network.OAuth.Http.HttpClient
import Network.OAuth.Http.Request
import Network.OAuth.Http.Response
import Network.OAuth.Http.PercentEncoding
import Control.Monad.State
import System.Random (randomRIO)
import Data.Time (getCurrentTime,formatTime)
import System.Locale (defaultTimeLocale)
import Data.Char (chr,ord)
import Data.List (intercalate,sort)
import System.IO
import qualified Data.Binary as Bi
import Data.Word (Word8)
import qualified Data.Digest.Pure.SHA as S
import qualified Codec.Binary.Base64 as B64
import qualified Data.ByteString.Lazy as B

-- | Random string that is unique amongst requests. Refer to <http://oauth.net/core/1.0/#nonce> for more information.
type Nonce = String

-- | Unix timestamp (seconds since epoch). Refer to <http://oauth.net/core/1.0/#nonce> for more information.
type Timestamp = String

-- | The optional authentication realm. Refer to <http://oauth.net/core/1.0/#auth_header_authorization> for more information.
type Realm = String

-- | Callback used in oauth authorization
data OAuthCallback =   URL String
                     | OOB
  deriving (Eq)

-- | Identifies the application.
data Application = Application { consKey  :: String 
                               , consSec  :: String
                               , callback :: OAuthCallback
                               }
  deriving (Eq)

-- | The OAuth Token.
data Token =   
  {-| There is no valid token present, all requests go unauthenticated.
   -}
    TwoLegg {application :: Application 
            ,oauthParams :: FieldList
            }
  {-| The service provider has granted you the request token but the user has
      not yet authorized your application. If you use this token it will goes
      as 2 legged OAuth.
   -}
  | ReqToken {application :: Application
             ,oauthParams :: FieldList
             }
  {-| This is a proper 3 legged OAuth. The difference between this and ReqToken
      is that user has authorized your application and you can perform requests
      on behalf of that user.
   -}
  | AccessToken {application :: Application
                ,oauthParams :: FieldList
                }
  deriving (Eq)

-- | Available signature methods.
data SigMethod =   
    {-| The 'PLAINTEXT' /consumer_key/ /token_secret/ method does not provide
        any security protection and SHOULD only be used over a secure channel
        such as /HTTPS/. It does not use the Signature Base String.
    -}
    PLAINTEXT
    {-| The 'HMAC_SHA1' /consumer_key/ /token_secret/ signature method uses the
        /HMAC-SHA1/ signature algorithm as defined in
        <http://tools.ietf.org/html/rfc2104> where the Signature Base String is
        the text and the key is the concatenated values (each first encoded per
        Parameter Encoding) of the Consumer Secret and Token Secret, separated
        by an /&/ character (ASCII code 38) even if empty.
    -}
  | HMACSHA1

-- | The OAuth monad.
type OAuthMonad m a = StateT Token m a

-- | Signs a request using a given signature method. This expects the request
--   to be a valid request already (for instance, none and timestamp are not set).
signature :: SigMethod -> Token -> Request -> String
signature m token req = case m
                        of PLAINTEXT -> key
                           HMACSHA1  -> b64encode $ S.bytestringDigest (S.hmacSha1 (bsencode key) (bsencode text))
  where bsencode  = B.pack . map (fromIntegral.ord)
        b64encode = B64.encode . B.unpack

        key  = encode (consSec (application token)) 
               ++"&"++ 
               encode (findWithDefault ("oauth_token_secret","") (oauthParams token))

        text = intercalate "&" $ map encode [show (method req)
                                            ,showURL (req {qString = empty})
                                            ,intercalate "&" . map (\(k,v) -> k++"="++v)
                                                             . sort
                                                             . map (\(k,v) -> (encode k,encode v)) 
                                                             . toList 
                                                             $ params
                                            ]

        params = if (ifindWithDefault ("content-type","") (reqHeaders req) == "application/x-www-form-urlencoded")
                 then (qString req) `unionAll` (parseQString . map (chr.fromIntegral) 
                                                             . B.unpack 
                                                             . reqPayload $ req)
                 else qString req

-- | Returns true if the token is able to perform 2-legged oauth requests.
twoLegged :: Token -> Bool
twoLegged (TwoLegg _ _)  = True
twoLegged _              = False

-- | Tests whether or not the current token is able to perform 3-legged requests.
threeLegged :: Token -> Bool
threeLegged (AccessToken _ _) = True
threeLegged _                 = False

-- | Transforms an application into a token.
ignite :: (MonadIO m) => Application -> OAuthMonad m ()
ignite = put . fromApplication

-- | Transforms an application into a token
fromApplication :: Application -> Token
fromApplication app = TwoLegg app empty

-- | Execute the oauth monad and returns the value it produced.
runOAuth :: (MonadIO m,HttpClient m) => OAuthMonad m a -> m a
runOAuth = flip evalStateT (TwoLegg (Application "" "" OOB) empty)

-- | Executes an oauth request which is intended to upgrade/refresh the current
--   token. Use this combinator to get either a request token or an access
--   token.
oauthRequest :: (MonadIO m,HttpClient m) => SigMethod -> Maybe Realm -> Request -> OAuthMonad m Token
oauthRequest sigm realm req = do response <- serviceRequest sigm realm req
                                 token    <- get
                                 case (fromResponse response token)
                                   of (Right token') -> do put token'
                                                           return token'
                                      (Left err)     -> fail err

-- | Simply complete the request with the required information to perform the oauth request.
completeRequest :: (MonadIO m) => SigMethod -> Token -> Maybe Realm -> Request -> m Request
completeRequest sigm token realm req = do nonce     <- _nonce
                                          timestamp <- _timestamp
                                          let authValue = authorization sigm realm nonce timestamp token req
                                          return (req {reqHeaders = insert ("Authorization",authValue) (reqHeaders req)})

-- | Performs a signed request with the available token.
serviceRequest :: (MonadIO m,HttpClient m) => SigMethod -> Maybe Realm -> Request -> OAuthMonad m Response
serviceRequest sigm realm req0 = do token <- get
                                    req   <- completeRequest sigm token realm req0
                                    lift (request req)

-- | Extracts the token from the OAuthMonad.
getToken :: (Monad m) => OAuthMonad m Token
getToken = get

-- | Alias to the put function.
putToken :: (Monad m) => Token -> OAuthMonad m ()
putToken = put

-- | Injects the oauth_verifier into the token. Usually this means the user has
-- authorized the app to access his data.
injectOAuthVerifier :: String -> Token -> Token
injectOAuthVerifier value (ReqToken app params) = ReqToken app (replace ("oauth_verifier",value) params)
injectOAuthVerifier _ token                     = token

-- | Probably this is just useful for testing. It asks the user (stdout/stdin)
-- to authorize the application and provide the oauth_verifier.
cliAskAuthorization :: (MonadIO m) => (Token -> String) -> OAuthMonad m ()
cliAskAuthorization getUrl = do token  <- get
                                answer <- liftIO $ do hSetBuffering stdout NoBuffering
                                                      putStrLn ("open " ++ (getUrl token))
                                                      putStr "oauth_verifier: "
                                                      getLine
                                put (injectOAuthVerifier answer token)

-- | Receives a response possibly from a service provider and updates the
-- token. As a matter effect, assumes the content-type is
-- application/x-www-form-urlencoded (because some service providers send it as
-- text/plain) and if the status is [200..300) updates the token accordingly.
fromResponse :: Response -> Token -> Either String Token
fromResponse rsp token | validRsp =  case (token)
                                     of (TwoLegg app params)     -> Right $ ReqToken app (payload `union` params)
                                        (ReqToken app params)    -> Right $ AccessToken app (payload `union` params)
                                        (AccessToken app params) -> Right $ AccessToken app (payload `union` params)
                       | otherwise = Left (statusLine rsp)
  where payload = parseQString . map (chr.fromIntegral) . B.unpack . rspPayload $ rsp

        validRsp = statusOk && paramsOk

        statusOk = status rsp `elem` [200..299]

        paramsOk = not $ null (zipWithM ($) (map (find . (==)) requiredKeys) (repeat payload))

        requiredKeys = case token
                       of (TwoLegg _ _) -> ["oauth_token"
                                           ,"oauth_token_secret"
                                           ,"oauth_callback_confirmed"
                                           ]
                          _             -> ["oauth_token"
                                           ,"oauth_token_secret"
                                           ]

-- | Computes the authorization header and updates the request.
authorization :: SigMethod -> Maybe Realm -> Nonce -> Timestamp -> Token -> Request -> String
authorization m realm nonce time token req = oauthPrefix ++ enquote (("oauth_signature",oauthSignature):oauthFields)
  where oauthFields = [("oauth_consumer_key",consKey.application $ token)
                      ,("oauth_nonce",nonce)
                      ,("oauth_timestamp",time)
                      ,("oauth_signature_method",show m)
                      ,("oauth_version","1.0")
                      ] ++ extra

        oauthPrefix = case realm
                      of Nothing -> "OAuth "
                         Just v  -> "OAuth realm=\""++encode v++"\","

        extra = case token
                of (TwoLegg app _)        -> [("oauth_callback",show.callback $ app)]
                   (ReqToken _ params)    -> filter (not.null.snd) [("oauth_verifier",findWithDefault ("oauth_verifier","") params)
                                                                   ,("oauth_token",findWithDefault ("oauth_token","") params)]
                   (AccessToken _ params) -> filter (not.null.snd) [("oauth_token",findWithDefault ("oauth_token","") params)
                                                                   ,("oauth_session_handle",findWithDefault ("oauth_session_handle","") params)
                                                                   ]

        oauthSignature = signature m token (req {qString = (qString req) `union` (fromList oauthFields)})

        enquote = intercalate "," . map (\(k,v) -> encode k ++"=\""++ encode v ++"\"")

_nonce :: (MonadIO m) => m Nonce
_nonce = do rand <- liftIO (randomRIO (0,maxBound::Int))
            return (show rand)

_timestamp :: (MonadIO m) => m Timestamp
_timestamp = do clock <- liftIO getCurrentTime
                return (formatTime defaultTimeLocale "%s" clock)

instance Show SigMethod where
  showsPrec _ PLAINTEXT = showString "PLAINTEXT"
  showsPrec _ HMACSHA1 = showString "HMAC-SHA1"

instance Show OAuthCallback where
  showsPrec _ OOB     = showString "oob"
  showsPrec _ (URL u) = showString u

instance Bi.Binary OAuthCallback where
  put OOB       = Bi.put (0 :: Word8)
  put (URL url) = do Bi.put (1 :: Word8) 
                     Bi.put url
  
  get = do t <- Bi.get :: Bi.Get Word8
           case t
            of 0 -> return OOB
               1 -> fmap URL Bi.get
               _ -> fail "Consumer: parse error"

instance Bi.Binary Application where
  put app = do Bi.put (consKey app)
               Bi.put (consSec app)
               Bi.put (callback app)
  
  get = do ckey      <- Bi.get
           csec      <- Bi.get
           callback_ <- Bi.get
           return (Application ckey csec callback_)

instance Bi.Binary Token where
  put (TwoLegg app params) = do Bi.put (0 :: Word8)
                                Bi.put app
                                Bi.put params
  put (ReqToken app params) = do Bi.put (1 :: Word8)
                                 Bi.put app
                                 Bi.put params
  put (AccessToken app params) = do Bi.put (2 :: Word8)
                                    Bi.put app
                                    Bi.put params
  get = do t <- Bi.get :: Bi.Get Word8
           case t 
            of 0 -> do app    <- Bi.get
                       params <- Bi.get
                       return (TwoLegg app params)
               1 -> do app    <- Bi.get
                       params <- Bi.get
                       return (ReqToken app params)
               2 -> do app    <- Bi.get
                       params <- Bi.get
                       return (AccessToken app params)
               _ -> fail "Consumer: parse error"

-- vim:sts=2:sw=2:ts=2:et
