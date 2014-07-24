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
-- >  reqUrl    = fromJust . parseURL $ "https://service.provider/request_token"
-- >  accUrl    = fromJust . parseURL $ "https://service.provider/access_token"
-- >  srvUrl    = fromJust . parseURL $ "http://service/path/to/resource/"
-- >  authUrl   = ("http://service.provider/authorize?oauth_token="++) . findWithDefault ("oauth_token","ERROR") . oauthParams
-- >  app       = Application "consumerKey" "consumerSec" OOB
-- >  response  = runOAuthM (fromApplication app) $ do { signRq2 PLAINTEXT Nothing reqUrl >>= oauthRequest CurlHttpClient
-- >                                                   ; cliAskAuthorization authUrl
-- >                                                   ; signRq2 PLAINTEXT Nothing accUrl >>= oauthRequest CurlHttpClient
-- >                                                   ; signRq2 HMACSHA1 (Just $ Realm "realm") srvUrl >>= serviceRequest CurlHttpClient
-- >                                                   }
-- 
module Network.OAuth.Consumer 
       ( -- * Types
         OAuthMonadT()
       , OAuthRequest(unpackRq)
       , Token(..)
       , Application(..)
       , OAuthCallback(..)
       , SigMethod(..)
       , Realm(..)
       , Nonce(..)
       , Timestamp(..)

         -- * OAuthMonadT related functions
       , runOAuth
       , runOAuthM
       , oauthRequest
       , packRq
       , signRq
       , signRq2
       , serviceRequest
       , cliAskAuthorization
       , ignite
       , getToken
       , putToken

         -- * Token related functions
       , twoLegged
       , threeLegged
       , signature
       , injectOAuthVerifier
       , fromApplication
       , fromResponse
       , authorization
       ) where

import Network.OAuth.Http.HttpClient
import Network.OAuth.Http.Request
import Network.OAuth.Http.Response
import Network.OAuth.Http.PercentEncoding
import Control.Monad
import Control.Monad.Trans
import System.IO
import System.Entropy (getEntropy)
import System.Locale (defaultTimeLocale)
import Data.Time (getCurrentTime,formatTime)
import Data.Char (chr,ord)
import Data.List (intercalate,sort)
import Data.Word (Word8)
import qualified Data.Binary as Bi
import qualified Data.Digest.Pure.SHA as S
import qualified Codec.Binary.Base64 as B64
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as B
import qualified Codec.Crypto.RSA        as R
import qualified Crypto.Types.PubKey.RSA as R

-- | A request that is ready to be performed, i.e., that contains authorization headers.
newtype OAuthRequest = OAuthRequest { unpackRq :: Request }
                     deriving (Show)

-- | Random string that is unique amongst requests. Refer to <http://oauth.net/core/1.0/#nonce> for more information.
newtype Nonce = Nonce { unNonce :: String }
              deriving (Eq)

-- | Unix timestamp (seconds since epoch). Refer to <http://oauth.net/core/1.0/#nonce> for more information.
newtype Timestamp = Timestamp { unTimestamp :: String }
                  deriving (Eq,Ord)

-- | The optional authentication realm. Refer to <http://oauth.net/core/1.0/#auth_header_authorization> for more information.
newtype Realm = Realm { unRealm :: String }
              deriving (Eq)

-- | Callback used in oauth authorization
data OAuthCallback = URL String
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
  {-| This token is used to perform 2 legged OAuth requests. -}
  TwoLegg { application :: Application 
          , oauthParams :: FieldList
          }
  {-| The service provider has granted you the request token but the
      user has not yet authorized your application. You need to
      exchange this token by a proper AccessToken, but this may only
      happen after user has granted you permission to do so.
   -}
  | ReqToken { application :: Application
             , oauthParams :: FieldList
             }
  {-| This is a proper 3 legged OAuth. The difference between this and ReqToken
      is that user has authorized your application and you can perform requests
      on behalf of that user.
   -}
  | AccessToken { application :: Application
                , oauthParams :: FieldList
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
  {-| The "RSA-SHA1" signature method uses the RSASSA-PKCS1-v1_5 signature
      algorithm as defined in [RFC3447], Section 8.2 (also known as
      PKCS#1), using SHA-1 as the hash function for EMSA-PKCS1-v1_5.  To
      use this method, the client MUST have established client credentials
      with the server that included its RSA public key (in a manner that is
      beyond the scope of this specification).
  -}
  | RSASHA1 R.PrivateKey

data OAuthMonadT m a = OAuthMonadT (Token -> m (Either String (Token,a)))

-- | Signs a request using a given signature method. This expects the request
--   to be a valid request already (for instance, none and timestamp are not set).
signature :: SigMethod -> Token -> Request -> String
signature m token req = case m
                        of PLAINTEXT -> key
                           HMACSHA1  -> b64encode $ S.bytestringDigest (S.hmacSha1 (bsencode key) (bsencode text))
                           RSASHA1 k -> b64encode $ R.rsassa_pkcs1_v1_5_sign R.hashSHA1 k (bsencode text)

  where bsencode  = B.pack . map (fromIntegral.ord)
        b64encode = B64.encode . B.unpack

        key  = encode (consSec (application token)) 
               ++"&"++ 
               encode (findWithDefault ("oauth_token_secret","") (oauthParams token))

        text = intercalate "&" $ map encode [ show (method req)
                                            , showURL (req {qString = empty})
                                            , intercalate "&" . map (\(k,v) -> k++"="++v)
                                                              . sort
                                                              . map (\(k,v) -> (encode k,encode v)) 
                                                              . toList 
                                                              $ params
                                            ]

        params = if (ifindWithDefault ("content-type","") (reqHeaders req) == "application/x-www-form-urlencoded")

                 -- e.g., in the case of most Twitter API calls
                 then (qString req) `unionAll` (parseQString . map (chr.fromIntegral) 
                                                             . B.unpack 
                                                             . reqPayload $ req)

                 -- e.g., in the case of a "multipart/form-data" image upload, however, the payload isn't signed
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
ignite :: (MonadIO m) => Application -> OAuthMonadT m ()
ignite = putToken . fromApplication

-- | Creates a TwoLegg token from an application
fromApplication :: Application -> Token
fromApplication app = TwoLegg app empty

-- | Execute the oauth monad using a given error handler
runOAuth :: (Monad m) => (String -> m a) -> Token -> OAuthMonadT m a -> m a
runOAuth h t (OAuthMonadT f) = do { v <- f t
                                  ; case v 
                                    of Right (_,a) -> return a
                                       Left err    -> h err
                                  }

-- | Execute the oauth monad and returns the value it produced using
-- `fail` as the error handler.
runOAuthM :: (Monad m) => Token -> OAuthMonadT m a -> m a
runOAuthM = runOAuth fail

-- | Executes an oauth request which is intended to upgrade/refresh the current
--   token.
oauthRequest :: (HttpClient c, MonadIO m) => c -> OAuthRequest -> OAuthMonadT m Token
oauthRequest c req = do { response <- serviceRequest c req
                        ; token    <- getToken
                        ; case (fromResponse response token)
                          of Right token' -> do { putToken token'
                                                ; return token'
                                                }
                             Left err     -> fail err
                        }

-- | Performs a signed request with the available token.
serviceRequest :: (HttpClient c,MonadIO m) => c -> OAuthRequest -> OAuthMonadT m Response
serviceRequest c req = do { result <- lift $ runClient c (unpackRq req)
                          ; case (result)
                            of Right rsp -> return rsp
                               Left err  -> fail $ "Failure performing the request. [reason=" ++ err ++"]"
                          }

-- | Complete the request with authorization headers.
signRq2 :: (MonadIO m) => SigMethod -> Maybe Realm -> Request -> OAuthMonadT m OAuthRequest
signRq2 sigm realm req = getToken >>= \t -> lift $ signRq t sigm realm req

-- | Simply create the OAuthRequest but adds no Authorization header.
packRq :: Request -> OAuthRequest
packRq = OAuthRequest

-- | Complete the request with authorization headers.
signRq :: (MonadIO m) => Token -> SigMethod -> Maybe Realm -> Request -> m OAuthRequest
signRq token sigm realm req0 = do { nonce     <- _nonce
                                  ; timestamp <- _timestamp
                                  ; let authValue = authorization sigm realm nonce timestamp token req0
                                        req       = req0 { reqHeaders = insert ("Authorization", authValue) (reqHeaders req0) }
                                  ; return (OAuthRequest req)
                                  }

-- | Extracts the token from the OAuthMonadT.
getToken :: (Monad m) => OAuthMonadT m Token
getToken = OAuthMonadT $ \t -> return $ Right (t,t)

-- | Alias to the put function.
putToken :: (Monad m) => Token -> OAuthMonadT m ()
putToken t = OAuthMonadT $ const (return $ Right (t,()))

-- | Injects the oauth_verifier into the token. Usually this means the user has
-- authorized the app to access his data.
injectOAuthVerifier :: String -> Token -> Token
injectOAuthVerifier value (ReqToken app params) = ReqToken app (replace ("oauth_verifier", value) params)
injectOAuthVerifier _ token                     = token

-- | Probably this is just useful for testing. It asks the user (stdout/stdin)
-- to authorize the application and provide the oauth_verifier.
cliAskAuthorization :: (MonadIO m) => (Token -> String) -> OAuthMonadT m ()
cliAskAuthorization getUrl = do { token  <- getToken
                                ; answer <- liftIO $ do { hSetBuffering stdout NoBuffering
                                                        ; putStrLn ("open " ++ (getUrl token))
                                                        ; putStr "oauth_verifier: "
                                                        ; getLine
                                                        }
                                ; putToken (injectOAuthVerifier answer token)
                                }

-- | Receives a response possibly from a service provider and updates the
-- token. As a matter effect, assumes the content-type is
-- application/x-www-form-urlencoded (because some service providers send it as
-- text/plain) and if the status is [200..300) updates the token accordingly.
fromResponse :: Response -> Token -> Either String Token
fromResponse rsp token | validRsp =  case (token)
                                     of TwoLegg app params     -> Right $ ReqToken app (payload `union` params)
                                        ReqToken app params    -> Right $ AccessToken app (payload `union` params)
                                        AccessToken app params -> Right $ AccessToken app (payload `union` params)
                       | otherwise = Left errorMessage
  where payload = parseQString . map (chr.fromIntegral) . B.unpack . rspPayload $ rsp

        validRsp = statusOk && paramsOk

        statusOk = status rsp `elem` [200..299]

        paramsOk = not $ null (zipWithM ($) (map (find . (==)) requiredKeys) (repeat payload))

        requiredKeys 
          | twoLegged token = [ "oauth_token"
                              , "oauth_token_secret"
                              , "oauth_callback_confirmed"
                              ]
          | otherwise       = [ "oauth_token"
                              , "oauth_token_secret"
                              ]

        errorMessage 
          | not statusOk = "Bad status code. [response=" ++ debug ++ "]"
          | not paramsOk = "Missing at least one required oauth parameter [expecting="++ show requiredKeys ++", response="++ debug ++"]"
          | otherwise    = error "Consumer#fromResponse: not an error!"
            where debug = concat [ "status: " ++ show (status rsp)
                                 , ", reason: " ++ reason rsp
                                 ]

-- | Computes the authorization header and updates the request.
authorization :: SigMethod -> Maybe Realm -> Nonce -> Timestamp -> Token -> Request -> String
authorization m realm nonce time token req = oauthPrefix ++ enquote (("oauth_signature",oauthSignature):oauthFields)
  where oauthFields = [ ("oauth_consumer_key", consKey.application $ token)
                      , ("oauth_nonce", unNonce nonce)
                      , ("oauth_timestamp", unTimestamp time)
                      , ("oauth_signature_method", showMethod m)
                      , ("oauth_version", "1.0")
                      ] ++ extra
        
        showMethod HMACSHA1    = "HMAC-SHA1"
        showMethod (RSASHA1 _) = "RSA-SHA1"
        showMethod PLAINTEXT   = "PLAINTEXT"

        oauthPrefix = case realm
                      of Nothing -> "OAuth "
                         Just v  -> "OAuth realm=\"" ++ encode (unRealm v) ++ "\","

        extra = case token
                of TwoLegg app _        -> [ ("oauth_callback", show.callback $ app) ]
                   ReqToken _ params    -> filter (not.null.snd) [ ("oauth_verifier", findWithDefault ("oauth_verifier","") params)
                                                                 , ("oauth_token", findWithDefault ("oauth_token","") params)
                                                                 ]
                   AccessToken _ params -> filter (not.null.snd) [ ("oauth_token", findWithDefault ("oauth_token","") params)
                                                                 , ("oauth_session_handle", findWithDefault ("oauth_session_handle","") params)
                                                                 ]

        oauthSignature = signature m token (req {qString = (qString req) `union` (fromList oauthFields)})

        enquote = intercalate "," . map (\(k,v) -> encode k ++"=\""++ encode v ++"\"")

_nonce :: (MonadIO m) => m Nonce
_nonce = liftIO $ liftM (Nonce . B64.encode . BS.unpack) (getEntropy 32)

_timestamp :: (MonadIO m) => m Timestamp
_timestamp = do { clock <- liftIO getCurrentTime
                ; return (Timestamp $ formatTime defaultTimeLocale "%s" clock)
                }

instance (Monad m) => Monad (OAuthMonadT m) where
  return a = OAuthMonadT $ \t -> return $ Right (t,a)
  fail err = OAuthMonadT $ \_ -> return $ Left err

  (OAuthMonadT ma) >>= f = OAuthMonadT $ \t0 -> ma t0 >>= either left right
    where left = return . Left
          right (t1,a) = let OAuthMonadT mb = f a
                         in mb t1

instance MonadTrans OAuthMonadT where
  lift ma = OAuthMonadT $ \t -> do { a <- ma
                                   ; return $ Right (t,a)
                                   }

instance (MonadIO m) => MonadIO (OAuthMonadT m) where
  liftIO ma = OAuthMonadT $ \t -> do { a <- liftIO ma
                                     ; return $ Right (t,a)
                                     }

instance (Monad m,Functor m) => Functor (OAuthMonadT m) where
  fmap f (OAuthMonadT ma) = OAuthMonadT $ \t0 -> ma t0 >>= either left right
    where left = return . Left
          right (t1,a) = return (Right (t1, f a))

instance Show OAuthCallback where
  showsPrec _ OOB     = showString "oob"
  showsPrec _ (URL u) = showString u

instance Bi.Binary OAuthCallback where
  put OOB       = Bi.put (0 :: Word8)
  put (URL url) = do { Bi.put (1 :: Word8) 
                     ; Bi.put url
                     }
  
  get = do { t <- Bi.get :: Bi.Get Word8
           ; case t
             of 0 -> return OOB
                1 -> fmap URL Bi.get
                _ -> fail "Consumer#get: parse error"
           }

instance Bi.Binary Application where
  put app = do { Bi.put (consKey app)
               ; Bi.put (consSec app)
               ; Bi.put (callback app)
               }
  
  get = do { ckey      <- Bi.get
           ; csec      <- Bi.get
           ; callback_ <- Bi.get
           ; return (Application ckey csec callback_)
           }

instance Bi.Binary Token where
  put (TwoLegg app params) = do { Bi.put (0 :: Word8)
                                ; Bi.put app
                                ; Bi.put params
                                }
  put (ReqToken app params) = do { Bi.put (1 :: Word8)
                                 ; Bi.put app
                                 ; Bi.put params
                                 }
  put (AccessToken app params) = do { Bi.put (2 :: Word8)
                                    ; Bi.put app
                                    ; Bi.put params
                                    }
  get = do { t <- Bi.get :: Bi.Get Word8
           ; case t 
             of 0 -> do { app    <- Bi.get
                        ; params <- Bi.get
                        ; return (TwoLegg app params)
                        }
                1 -> do { app    <- Bi.get
                        ; params <- Bi.get
                        ; return (ReqToken app params)
                        }
                2 -> do { app    <- Bi.get
                        ; params <- Bi.get
                        ; return (AccessToken app params)
                        }
                _ -> fail "Consumer#get: parse error"
           }

