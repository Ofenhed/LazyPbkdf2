module Crypto.Pbkdf2 (pbkdf2, hmacSha512Pbkdf2) where

import Data.Digest.Pure.SHA (hmacSha512, bytestringDigest)
import Data.Bits (shiftR)
import Data.ByteString.Lazy as B
import Data.Binary as Bin
import Data.Bits(xor)

octetsBE :: Word32 -> [Word8]
octetsBE w = 
    [ fromIntegral (w `shiftR` 24)
    , fromIntegral (w `shiftR` 16)
    , fromIntegral (w `shiftR` 8)
    , fromIntegral w
    ]

xorByteStrings x y
  | B.length x == B.length y = B.pack $ B.zipWith xor x y
  | otherwise = error "xor bytestrings are not of equal length"

pbkdf2 :: (ByteString -> ByteString -> ByteString)
           -- ^ @PRF@, the PRF function to be used for PBKDF2. The first
           -- argument is secret, the second argument is not.
       -> ByteString -- ^ @Password@, the secret to use in the PBKDF2 computations.
       -> ByteString -- ^ @Salt@, the not neccesarily secret data to use in the PBKDF2 computations.
       -> Integer -- ^ @c@, number of iterations for the the PBKDF2 computations.
       -> ByteString -- ^ @DK@, the output data in the format of an unlimited lazy ByteString.
pbkdf2 prf password salt iterations = B.concat $ pbkdf2' 1 True
  where
    hash' = prf password
    pbkdf2' :: Word32 -> Bool -> [ByteString]
    pbkdf2' 1 False = error "Hashing algorithm looped, stopping to maintain security of data" -- Paranoia, but that's useful when doing crypto
    pbkdf2' i _ = (pbkdf2'' (hash' $ B.concat [salt, B.pack $ octetsBE i])):(pbkdf2' (i + 1) False)
    pbkdf2'' hash = pbkdf2''' hash hash 1
    pbkdf2''' prev_hash prev_result i
      | i == iterations = prev_result
      | i > iterations = error "Count must be at least 1"
      | otherwise = pbkdf2''' current_hash result (i + 1)
        where
          current_hash = (hash' prev_hash)
          result = xorByteStrings current_hash prev_result

-- |Example of the pbkdf2 function using SHA512. See `pbkdf2` for usage.
hmacSha512Pbkdf2 :: ByteString -- ^ @Password@
                 -> ByteString -- ^ @Salt@
                 -> Integer -- ^ @c@
                 -> ByteString -- ^ @DK@
hmacSha512Pbkdf2 = pbkdf2 hash
  where
    hash password salt = bytestringDigest $ hmacSha512 password salt
