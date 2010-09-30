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

-- | Minimum definition of a user agent required to implement oauth
-- service calls. This should suffice for most applications.
module Network.OAuth.Http.DebugHttpClient
       ( DebugClient(..)
       , stdDebugClient
       ) where

import Network.OAuth.Http.HttpClient
import Network.OAuth.Http.Request
import Network.OAuth.Http.Response
import Control.Monad.Trans

-- | A client that is able to debug interaction with HTTP servers.
data DebugClient c = DebugClient { backend  :: c
                                 , traceRq  :: Request -> IO ()
                                 , traceRp  :: Response -> IO ()
                                 , traceErr :: String -> IO ()
                                 }

-- | Creates the a instance which prints messages using putStrLn.
stdDebugClient :: (HttpClient c) => c -> DebugClient c
stdDebugClient c = DebugClient { backend  = c
                               , traceRq  = putStrLn . ("Request: " ++) . show
                               , traceRp  = putStrLn . ("Response: " ++) . show
                               , traceErr = putStrLn . ("Error: "++) . show
                               }

instance (HttpClient c) => HttpClient (DebugClient c) where
  runClient debug req = do { liftIO (traceRq debug $ req)
                           ; rsp <- runClient (backend debug) req
                           ; liftIO (either (traceErr debug) (traceRp debug) $ rsp)
                           ; return rsp
                           }
