{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
import Crypto.Pbkdf2
import Criterion.Main

import "cryptonite" Crypto.MAC.HMAC (initialize, update, finalize, Context(), hmacGetDigest)
import Crypto.Hash.Algorithms (SHA512)
import Data.Byteable (toBytes)

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteArray as BA
import qualified Data.ByteString.Lazy.Char8 as C8

sha512 key = let h = (initialize key :: Context SHA512) ; in (\msg -> let h' = update h $ msg in B.pack $ BA.unpack $ hmacGetDigest $ finalize h')

doPbkdf func password salt iter = nf (\(p, s, i) -> LB.take 1000 $ func sha512 p s i) (password, salt, iter)

main = defaultMain [
  bgroup "pbkdf2"
    [ bench "standard" $ doPbkdf pbkdf2 "password" "saltword" 1000,
      bench "iterative" $ doPbkdf pbkdf2_iterative "password" "saltword" 1000],
  bgroup "long-password"
    [ bench "standard" $ doPbkdf pbkdf2 (B.replicate 100000 65) "saltword" 1000,
      bench "iterative" $ doPbkdf pbkdf2_iterative (B.replicate 100000 65) "saltword" 1000],
  bgroup "long-salt"
    [ bench "standard" $ doPbkdf pbkdf2 "password" (B.replicate 100000 65) 1000,
      bench "iterative" $ doPbkdf pbkdf2_iterative "password" (B.replicate 100000 65) 1000],
  bgroup "many-iterations"
    [ bench "standard" $ doPbkdf pbkdf2 "password" "saltword" 10000,
      bench "iterative" $ doPbkdf pbkdf2_iterative "password" "saltword" 10000]]

