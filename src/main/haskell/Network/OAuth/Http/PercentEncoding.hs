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

-- | Percent encoding <http://tools.ietf.org/html/rfc3986#page-12> functions,
-- with the exception that all encoding/decoding is in UTF-8.
module Network.OAuth.Http.PercentEncoding (PercentEncoding(..)
                                          ,decodeWithDefault
                                          ) where

import Data.Monoid (mappend)
import Data.List (splitAt)
import qualified Codec.Binary.UTF8.String as U
import Data.Char (intToDigit,digitToInt,toUpper,ord)
import Data.Bits

class PercentEncoding a where
  -- | Encodes a type into its percent encoding representation.
  encode :: a -> String

  -- | Decodes a percent-encoded type to its native type.
  decode :: String -> Maybe (a,String)

-- | Encodes Char types using UTF\-8 charset.
instance PercentEncoding Char where
  encode c | c `elem` whitelist = [c]
           | otherwise          = concatMap (run.fromIntegral) (U.encode [c])
    where whitelist =    ['a'..'z'] 
                      ++ ['A'..'Z']
                      ++ ['0'..'9']
                      ++ "-._~"
          run b = '%' : map (toUpper.intToDigit) [shiftR (b .&. 0xF0) 4,b .&. 0x0F]

  decode xs = case (U.decode . tobytes $ xs)
              of []     -> Nothing
                 (y:_)  -> let sizeof = if ("%"==take 1 xs)
                                        then length (encode y)
                                        else 1
                           in Just (y,drop sizeof xs)
    where tobytes (b:bs) = case b 
                           of '%' -> let ([c0,c1],bs') = splitAt 2 bs
                                         b0            = (shiftL (digitToInt c0) 4) .&. 0xF0
                                         b1            = (digitToInt c1) .&. 0x0F
                                         byte          = fromIntegral (b0 .|. b1)
                                     in byte : tobytes bs'
                              _   -> fromIntegral (ord b) : tobytes bs
          tobytes []     = []

-- | Add support for encoding strings
instance (PercentEncoding a) => PercentEncoding [a] where
  encode (x:xs) = encode x ++ encode xs
  encode []     = []
  
  decode xs = do (c,ys) <- (decode xs)
                 cs     <- fmap (fst) (decode ys `mappend` Just ([],""))
                 return (c:cs,"")

-- | Decodes a percent encoded string. In case of failure returns a default value, instead of Nothing.
decodeWithDefault :: (PercentEncoding a) => a -> String -> a
decodeWithDefault def str = case (decode str)
                            of Just (v,"") -> v
                               _           -> def

-- vim:sts=2:sw=2:ts=2:et
