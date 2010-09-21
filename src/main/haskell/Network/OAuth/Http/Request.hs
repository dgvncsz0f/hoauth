{-# LANGUAGE GeneralizedNewtypeDeriving #-}

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

-- | The request currently is only able to represent an HTTP request.
module Network.OAuth.Http.Request 
       ( -- * Types
         Request(..)
       , FieldList()
       , Version(..)
       , Method(..)
         -- * FieldList related functions
       , fromList
       , singleton
       , empty
       , toList
       , parseQString
       , find
       , findWithDefault
       , ifindWithDefault
       , change
       , insert
       , replace
       , replaces
       , union
       , unionAll
         -- * Request related functions
       , showURL
       , showQString
       , showProtocol
       , showAuthority
       , showPath
       , parseURL
       ) where

import Control.Monad.State
import Network.OAuth.Http.PercentEncoding
import Network.OAuth.Http.Util
import Data.List (intercalate,isPrefixOf)
import Data.Monoid
import Data.Char (toLower)
import qualified Data.ByteString.Lazy as B
import qualified Data.Binary as Bi

-- | All known HTTP methods
data Method =   GET
              | POST
              | PUT
              | DELETE
              | TRACE
              | CONNECT
              | HEAD
  deriving (Eq)

-- | Supported HTTP versions
data Version =   Http10
               | Http11
  deriving (Eq)

-- | Key-value list.
newtype FieldList = FieldList { unFieldList :: [(String,String)] }
  deriving (Eq,Ord)

data Request = ReqHttp { version    :: Version      -- ^ Protocol version
                       , ssl        :: Bool         -- ^ Wheter or not to use ssl
                       , host       :: String       -- ^ The hostname to connect to
                       , port       :: Int          -- ^ The port to connect to
                       , method     :: Method       -- ^ The HTTP method of the request.
                       , reqHeaders :: FieldList    -- ^ Request headers
                       , pathComps  :: [String]     -- ^ The path split into components 
                       , qString    :: FieldList    -- ^ The query string, usually set for GET requests
                       , reqPayload :: B.ByteString -- ^ The message body
                       }
  deriving (Eq,Show)

-- | Show the protocol in use (currently either https or http)
showProtocol :: Request -> String
showProtocol req 
  | ssl req   = "https"
  | otherwise = "http"

-- | Show the host+port path of the request. May return only the host when
--   (ssl=False && port==80) or (ssl=True && port==443).
showAuthority :: Request -> String
showAuthority req 
  | ssl req && (port req)==443      = host req
  | not (ssl req) && (port req)==80 = host req
  | otherwise                       = host req ++":"++ show (port req)

-- | Show the path component of the URL.
showPath :: Request -> String
showPath = intercalate "/" . map encode . pathComps

-- | Show the querty string of the URL.
showQString :: Request -> String
showQString = show . qString

-- | Show the URL.
showURL :: Request -> String
showURL =   concat 
          . zipWith ($) [showProtocol,const "://",showAuthority,showPath,showQString'] 
          . repeat
  where showQString' :: Request -> String
        showQString' req 
          | null (unFieldList (qString req)) = ""
          | otherwise                        = '?' : showQString req

-- | Parse a URL and creates an request type.
parseURL :: String -> Maybe Request
parseURL tape = evalState parser (tape,Just initial)
  where parser = do { _parseProtocol
                    ; _parseSymbol (':',True)
                    ; _parseSymbol ('/',True)
                    ; _parseSymbol ('/',True)
                    ; _parseHost
                    ; _parseSymbol (':',False)
                    ; _parsePort
                    ; _parseSymbol ('/',True)
                    ; _parsePath
                    ; _parseSymbol ('?',False)
                    ; _parseQString
                    ; fmap snd get
                    }
        initial = ReqHttp { version    = Http11
                          , ssl        = False
                          , method     = GET
                          , host       = "127.0.0.1"
                          , port       = 80
                          , reqHeaders = fromList []
                          , pathComps  = []
                          , qString    = fromList []
                          , reqPayload = B.empty
                          }

-- | Parse a query string.
parseQString :: String -> FieldList
parseQString tape = evalState parser (tape,Just initial)
  where parser = do { _parseQString
                    ; fmap (qstring . snd) get
                    }

        qstring Nothing  = fromList []
        qstring (Just r) = qString r

        initial = ReqHttp { version    = Http11
                          , ssl        = False
                          , method     = GET
                          , host       = "127.0.0.1"
                          , port       = 80
                          , reqHeaders = fromList []
                          , pathComps  = []
                          , qString    = fromList []
                          , reqPayload = B.empty
                          }

-- | Creates a FieldList type from a list.
fromList :: [(String,String)] -> FieldList
fromList = FieldList

-- | Transforms a fieldlist into a list type.
toList :: FieldList -> [(String,String)]
toList = unFieldList

-- | Creates a FieldList out from a single element.
singleton :: (String,String) -> FieldList
singleton = fromList . (:[])

-- | Returns an empty fieldlist.
empty :: FieldList
empty = fromList []

-- | Updates all occurrences of a given key with a new value. Does nothing if
--   the values does not exist.
change :: (String,String) -> FieldList -> FieldList
change kv (FieldList list) = FieldList (change' kv list)
  where change' (k,v) ((k0,v0):fs) 
          | k0==k     = (k0,v) : change' (k,v) fs
          | otherwise = (k0,v0) : change' (k,v) fs
        change' _ []  = []

-- | Inserts a new value into a fieldlist.
insert :: (String,String) -> FieldList -> FieldList
insert kv = mappend (FieldList [kv])

-- | Inserts or updates occurrences of a given key.
replace :: (String,String) -> FieldList -> FieldList
replace (k,v) fs 
  | null $ find (==k) fs = insert (k,v) fs
  | otherwise            = change (k,v) fs

-- | Same as /replace/ but work on a list type
replaces :: [(String,String)] -> FieldList -> FieldList
replaces fs field = foldr (replace) field fs

-- | Find keys that satisfy a given predicate.
find :: (String -> Bool) -> FieldList -> [String]
find p (FieldList list) = map snd (filter (p.fst) list)

-- | Combines two fieldsets, but prefere items of the first list.
union :: FieldList -> FieldList -> FieldList
union (FieldList as) bs = foldr replace bs as

-- | Combines two fieldsets keeping duplicates.
unionAll :: FieldList -> FieldList -> FieldList
unionAll (FieldList as) bs = foldr insert bs as

-- | Finds a the value defined in a fieldlist or returns a default value. In
-- the event there are multiple values under the same key the first one is
-- returned.
findWithDefault :: (String,String) -> FieldList -> String
findWithDefault (key,def) fields 
  | null values = def
  | otherwise   = head values
    where values = find (==key) fields

-- | Same as <findWithDefault> but the match is case-insenstiive.
ifindWithDefault :: (String,String) -> FieldList -> String
ifindWithDefault (key,def) fields 
  | null values = def
  | otherwise   = head values
    where values = find (\k -> lower k == lower key) fields
          lower  = map toLower

_parseProtocol :: State (String,Maybe Request) ()
_parseProtocol = do { (tape,req) <- get
                    ; if ("https" `isPrefixOf` tape)
                      then put (drop 5 tape,liftM (\r -> r {ssl=True,port=443}) req)
                      else if ("http" `isPrefixOf` tape) 
                           then put (drop 4 tape,liftM (\r -> r {ssl=False,port=80}) req)
                           else put ("",Nothing)
                    }

_parseHost :: State (String,Maybe Request) ()
_parseHost = do { (tape,req) <- get
                ; let (value,tape') = break (`elem` ":/") tape
                ; put (tape',liftM (\r -> r {host = value}) req)
                }

_parsePort :: State (String,Maybe Request) ()
_parsePort = do { (tape,req) <- get
                ; let (value,tape') = break (=='/') tape
                ; case (reads value)
                  of [(value',"")] -> put (tape',liftM (\r -> r {port = value'}) req)
                     _             -> put (tape',req)
                }

_parsePath :: State (String,Maybe Request) ()
_parsePath = do { (tape,req) <- get
                ; let (value,tape') = break (=='?') tape
                      value'        = "" : map (decodeWithDefault "") (splitBy (=='/') value)
                ; put (tape',liftM (\r -> r {pathComps=value'}) req)
                }

_parseQString :: State (String,Maybe Request) ()
_parseQString = do { (tape,req) <- get
                   ; let (value,tape') = break (=='#') tape
                         fields        = fromList $ filter (/=("","")) (map parseField (splitBy (=='&') value))
                   ; put (tape',liftM (\r -> r {qString=fields}) req)
                   }
  where parseField tape = let (k,v) = break (=='=') tape
                          in case (v)
                             of ('=':v') -> (decodeWithDefault "" k,decodeWithDefault "" v')
                                _        -> (decodeWithDefault "" k,"")

_parseSymbol :: (Char,Bool) -> State (String,Maybe Request) ()
_parseSymbol (c,required) = do { (tape,req) <- get
                               ; if ([c] `isPrefixOf` tape)
                                 then put (drop 1 tape,req)
                                 else if (required) 
                                      then put ("",Nothing)
                                      else put (tape,req)
                               }

instance Show Method where
  showsPrec _ m = case m 
                  of GET     -> showString "GET"
                     POST    -> showString "POST"
                     DELETE  -> showString "DELETE"
                     CONNECT -> showString "CONNECT"
                     HEAD    -> showString "HEAD"
                     TRACE   -> showString "TRACE"
                     PUT     -> showString "PUT"

instance Read Method where
  readsPrec _ "GET"     = [(GET,"")]
  readsPrec _ "POST"    = [(POST,"")]
  readsPrec _ "DELETE"  = [(DELETE,"")]
  readsPrec _ "CONNECT" = [(CONNECT,"")]
  readsPrec _ "HEAD"    = [(HEAD,"")]
  readsPrec _ "TRACE"   = [(TRACE,"")]
  readsPrec _ "PUT"     = [(PUT,"")]
  readsPrec _ _         = []

instance Read Version where
  readsPrec _ "HTTP/1.0" = [(Http10,"")]
  readsPrec _ "HTTP/1.1" = [(Http11,"")]
  readsPrec _ _          = []

instance Show Version where
  showsPrec _ v = case v 
                  of Http10 -> showString "HTTP/1.0"
                     Http11 -> showString "HTTP/1.1"

instance Show FieldList where
  showsPrec _ = showString . intercalate "&" . map showField . unFieldList
    where showField (k,v) = encode k ++"="++ encode v

instance Monoid FieldList where
  mempty  = FieldList []
  mappend (FieldList as) (FieldList bs) = FieldList (as `mappend` bs)

instance Bi.Binary FieldList where
  put = Bi.put . unFieldList
  get = fmap FieldList Bi.get

