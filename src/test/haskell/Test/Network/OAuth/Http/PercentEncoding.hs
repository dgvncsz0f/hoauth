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

module Test.Network.OAuth.Http.PercentEncoding where

import qualified Test.HUnit as T
import Network.OAuth.Http.PercentEncoding
import Data.Char (isPrint)
import Data.Maybe (fromJust)
import System.Random (randomRIO)
import qualified Data.ByteString.Lazy as B

ftest0 = T.TestCase $ do
  let ascii = ['a'..'z'] ++ ['A'..'Z'] ++ ['0'..'9'] ++ "-._~"
  T.assertEqual
    "test encode preserves ascii characters"
    (ascii)
    (encode ascii)

ftest1 = T.TestCase $ do
  let string = "foo=bar&bar=foo&%foo=%bar& "
  T.assertEqual
    "test encode encodes unsafe chars"
    ("foo%3Dbar%26bar%3Dfoo%26%25foo%3D%25bar%26%20")
    (encode string)

stest0 = T.TestCase $ do
  let string   = filter isPrint [minBound .. maxBound]
  dSize <- randomRIO (0,length string - 1000)
  T.assertEqual
    "test (decode . encode) == id"
    (take 1000 . drop dSize $ string)
    (fst . fromJust . decode . encode . take 1000 . drop dSize $ string)

fast_tests = [ftest0,ftest1]
slow_tests = [stest0]

-- vim:sts=2:sw=2:ts=2:et
