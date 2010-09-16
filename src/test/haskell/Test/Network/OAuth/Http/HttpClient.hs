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

module Test.Network.OAuth.Http.HttpClient where

import qualified Test.HUnit as T
import Network.OAuth.Http.HttpClient
import Network.OAuth.Http.Response
import Network.OAuth.Http.Request
import Data.Maybe (fromJust)

stest0 = T.TestCase $ do
  let CurlM ioresp = request (fromJust $ parseURL "http://github.com/dsouza/hoauth/")

  response <- ioresp
  T.assertEqual
    "Assert status code is set on response"
    (200)
    (status response)

  T.assertEqual
    "Assert statusLine is set on response"
    ("HTTP/1.1 200 OK")
    (statusLine response)

  T.assertEqual
    "Assert headers are set (content-type)"
    (" text/html; charset=utf-8")
    (ifindWithDefault ("content-type","") (rspHeaders response))

  T.assertBool
    "Assert header are set (content-length)"
    (not $ null $ ifindWithDefault ("content-length","") (rspHeaders response))

stest1 = T.TestCase $ do
  let req          = fromJust $ parseURL "http://github.com/dsouza/hoauth/"
      CurlM ioresp = request (req {method = HEAD})

  response <- ioresp
  T.assertEqual
    "Assert status code is set on response"
    (200)
    (status response)

  T.assertEqual
    "Assert statusLine is set on response"
    ("HTTP/1.1 200 OK")
    (statusLine response)

  T.assertEqual
    "Assert headers are set (content-type)"
    (" text/html; charset=utf-8")
    (ifindWithDefault ("content-type","") (rspHeaders response))

fast_tests = []
slow_tests = [stest0,stest1]

