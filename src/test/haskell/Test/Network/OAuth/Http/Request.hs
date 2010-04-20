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

module Test.Network.OAuth.Http.Request where

import qualified Test.HUnit as T
import Network.OAuth.Http.Request
import Data.Maybe (fromJust)
import qualified Data.ByteString.Lazy as B
import qualified Data.Binary as Bi

ftest0 = T.TestCase $ do
  let fields = fromList [("foo","bar"),("bar","foo")]
  T.assertEqual
    "Test find"
    (["bar"])
    (find (=="foo") fields)

  T.assertEqual
    "Test find"
    (["foo"])
    (find (=="bar") fields)

  T.assertEqual
    "Test find"
    (["bar","foo"])
    (find (const True) fields)

ftest1 = T.TestCase $ do
  let list = [("a","b"),("b","c"),("c","d")]

  T.assertEqual
    "Test toList.fromList = id"
    (list)
    (toList.fromList $ list)

ftest2 = T.TestCase $ do
  let list = [("a","b")]

  T.assertEqual
    "Test singleton = fromList (head list)"
    (fromList list)
    (singleton ("a","b"))

ftest3 = T.TestCase $ do
  let list = []

  T.assertEqual
    "Test empty = fromList []"
    (fromList [])
    (empty)

ftest4 = T.TestCase $ do
  T.assertEqual
    "Test findWithDefault returns default value when key is not found"
    ("null")
    (findWithDefault ("foobar","null") empty)

  T.assertEqual
    "Test findWithDefault returns the first occurence of a given key"
    ("#1")
    (findWithDefault ("foobar","") (fromList [("foobar","#1"),("foobar","#2"),("foobar","#3")]))

ftest5 = T.TestCase $ do
  T.assertEqual
    "Test ifindWithDefault returns default value when key is not found"
    ("null")
    (findWithDefault ("foobar","null") empty)

  T.assertEqual
    "Test ifindWithDefault ignores case"
    ("righton")
    (ifindWithDefault ("foobar","") (singleton ("fOoBaR","righton")))

  T.assertEqual
    "Test ifindWithDefault returns the first occurence of a given key"
    ("#1")
    (ifindWithDefault ("fOoBar","") (fromList [("foobar","#1"),("foobar","#2"),("foobar","#3")]))

ftest6 = T.TestCase $ do
  let fields = fromList [("a","#1"),("b","#2"),("c","#3"),("c","#3.1")]

  T.assertEqual
    "Test change does nothing if key is not defined"
    (fields)
    (change ("foobar","") fields)

  T.assertEqual
    "Test change modifies only specified keys"
    (fromList [("a","foobar"),("b","#2"),("c","#3"),("c","#3.1")])
    (change ("a","foobar") fields)

  T.assertEqual
    "Test change modifies all occurences of a given key"
    (fromList [("a","#1"),("b","#2"),("c","foobar"),("c","foobar")])
    (change ("c","foobar") fields)

ftest7 = T.TestCase $ do
  let fields = fromList [("a","#1"),("b","#2"),("c","#3"),("c","#3.1")]

  T.assertEqual
    "Test insert always add a new element"
    ((singleton ("c","#4")) `unionAll` fields)
    (insert ("c","#4") fields)

  T.assertEqual
    "Test insert always add a new element"
    ((singleton ("d","#4")) `union` fields)
    (insert ("d","#4") fields)

ftest8 = T.TestCase $ do
  let fields = fromList [("a","#1"),("b","#2"),("c","#3"),("c","#3.1")]

  T.assertEqual
    "Test replace is insert when key is undefined"
    (insert ("d","#4") fields)
    (replace ("d","#4") fields)

  T.assertEqual
    "Test replace is change when key is defined"
    (change ("c","#4") fields)
    (replace ("c","#4") fields)

ftest9 = T.TestCase $ do
  let fields0 = fromList [("a","#1"),("b","#2")]
      fields1 = fromList [("a","#1.1"),("b","#2.1"),("c","#3.1")]

  T.assertEqual
    "Test union prefer first fieldlist"
    (fromList [("a","#1"),("b","#2"),("c","#3.1")])
    (fields0 `union` fields1)

  T.assertEqual
    "Test unionAll ignores duplicates"
    (fromList (toList fields0 ++ toList fields1))
    (fields0 `unionAll` fields1)

ftest10 = T.TestCase $ do
  T.assertEqual
    "Test showURL do the right thing"
    ("https://foo.bar:9999/%20foo%23/bar?a=%C3%A1&b=10&c=%22test%22")
    (showURL $ ReqHttp Http11 True "foo.bar" 9999 GET empty [""," foo#","bar"] (fromList [("a","á"),("b","10"),("c","\"test\"")]) B.empty)

ftest11 = T.TestCase $ do
  T.assertEqual
    "Test parseURL do the right thing"
    (Just $ ReqHttp Http11 True "foo.bar" 9999 GET empty [""," foo#","bar"] (fromList [("a","á"),("b","10"),("c","\"test\"")]) B.empty)
    (parseURL "https://foo.bar:9999/%20foo%23/bar?a=%C3%A1&b=10&c=%22test%22")

ftest12 = T.TestCase $ do
  let url = "http://search.yahoo.com/search%3B_ylt%3DA0geu9SiXK9LgnEAUf.l87UF%3B_ylc%3DX1MDMjE0MjQ3ODk0OARfcgMyBGZyA3NmcARuX2dwcwMwBG9yaWdpbgNzZWFyY2gueWFob28uY29tBHF1ZXJ5A3lhaG9vBHNhbwMw?p=yahoo&fr=sfp&fr2=&iscqry="
  T.assertEqual
    "Test showURL . parseURL = id"
    (url)
    (showURL . fromJust . parseURL $ url)

  T.assertEqual
    "Test parseURL . showURL = id"
    (ReqHttp Http11 True "foo.bar" 9999 GET empty [""," foo#","bar"] (fromList [("a","á"),("b","10"),("c","\"test\"")]) B.empty)
    (fromJust . parseURL . showURL $ ReqHttp Http11 True "foo.bar" 9999 GET empty [""," foo#","bar"] (fromList [("a","á"),("b","10"),("c","\"test\"")]) B.empty)

ftest13 = T.TestCase $ do
  T.assertEqual
    "Test parseQString do the right thing"
    (fromList [("a","#1"),("b","#2"),("c","#3"),("d","?a=#1&b=#2")])
    (parseQString "a=%231&b=%232&c=%233&d=%3Fa%3D%231%26b%3D%232")

  T.assertEqual 
    "Test show.parseQString = id"
    ("a=%231&b=%232&c=%233&d=%3Fa%3D%231%26b%3D%232")
    (show . parseQString $ "a=%231&b=%232&c=%233&d=%3Fa%3D%231%26b%3D%232")

  T.assertEqual
    "Test parseQString.show = id"
    (fromList [("a","#1"),("b","#2"),("c","#3"),("d","?a=#1&b=#2")])
    (parseQString . show . fromList $ [("a","#1"),("b","#2"),("c","#3"),("d","?a=#1&b=#2")])

ftest14 = T.TestCase $ do
  T.assertEqual 
    "Test showProtocol"
    ("http")
    (showProtocol . fromJust . parseURL $ "http://foobar/")

  T.assertEqual 
    "Test showProtocol"
    ("https")
    (showProtocol . fromJust . parseURL $ "https://foobar/")

ftest15 = T.TestCase $ do
  T.assertEqual
    "Test showAuthority"
    ("foobar")
    (showAuthority . fromJust . parseURL $ "http://foobar/")

  T.assertEqual
    "Test showAuthority"
    ("foobar:8080")
    (showAuthority . fromJust . parseURL $ "http://foobar:8080/")

  T.assertEqual
    "Test showAuthority"
    ("foobar")
    (showAuthority . fromJust . parseURL $ "https://foobar:443/")

  T.assertEqual
    "Test showAuthority"
    ("foobar:9999")
    (showAuthority . fromJust . parseURL $ "https://foobar:9999/")

ftest16 = T.TestCase $ do
  T.assertEqual
    "Test showPath"
    ("/rig.ht.on")
    (showPath . fromJust . parseURL $ "http://foobar/rig.ht.on")

  T.assertEqual
    "Test showPath"
    ("/rig/ht/on")
    (showPath . fromJust . parseURL $ "http://foobar/rig/ht/on")

  T.assertEqual
    "Test showPath"
    ("/%2F")
    (showPath . fromJust . parseURL $ "http://foobar/%2F")

ftest17 = T.TestCase $ do
  let fields = [("foobar","#0"),("righton","#1"),("foobaz","#2")]
  T.assertBool
    "Test encode.decode = id (Binary) [FieldList]"
    (fields == (Bi.decode.Bi.encode $ fields))

  T.assertBool
    "Test encode.decode = id (Binary) [FieldList]"
    (empty == (Bi.decode.Bi.encode $ empty))

  T.assertBool
    "Test encode.decode = id (Binary) [FieldList]"
    (singleton ("foobar","#0") == (Bi.decode.Bi.encode $ singleton ("foobar","#0")))

fast_tests = [ftest0,ftest1,ftest2,ftest3,ftest4,ftest5,ftest6,ftest7,ftest8,ftest9,ftest10,ftest11,ftest12,ftest13,ftest14,ftest15,ftest16,ftest17]
slow_tests = []

-- vim:sts=2:sw=2:ts=2:et
