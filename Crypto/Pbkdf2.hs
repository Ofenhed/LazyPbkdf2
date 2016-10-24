module Crypto.Pbkdf2 (pbkdf2, pbkdf2_iterative) where

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

-- | This is a non standard variation of PBKDF2 which recursively uses the
-- last generated value to improve the salt. In difference to pbkdf2 the
-- salt can not be precalculated (with a simple append of 4 bytes), but has
-- to be calculated for every single iteration. This also creates
-- a function where you cannot jump in the stream without calculating
-- everything before it. Compared to the standard this function only
-- changes the salt for the initial PBKDF2 value to include a salt iterated
-- from earlier parts of the PBKDF2 stream. This can be verified by
-- removing the i from (hash' $ B.concat [i, salt, B.pack $ octetsBE c]).
pbkdf2_iterative :: (ByteString -> ByteString -> ByteString)
                     -- ^ @PRF@, the PRF function to be used for the
                     -- iterative PBKDF2. The first argument is secret, the
                     -- second argument is not.
                 -> ByteString -- ^ @Password@, the secret to use in the PBKDF2 computations.
                 -> ByteString -- ^ @Salt@, the not neccesarily secret data to use in the PBKDF2 computations.
                 -> Integer -- ^ @c@, number of iterations for the the PBKDF2 computations.
                 -> ByteString -- ^ @DK@, the output data in the format of an unlimited lazy ByteString.
pbkdf2_iterative prf password salt iterations = B.concat $ pbkdf2' (B.pack []) 1
  where
    hash' = prf password
    pbkdf2' :: ByteString -> Word32 -> [ByteString]
    pbkdf2' i c = let prev = (pbkdf2'' (hash' $ B.concat [i, salt, B.pack $ octetsBE c])) in prev:(pbkdf2' (prf prev i) (c + 1))
    pbkdf2'' hash = pbkdf2''' hash hash 1
    pbkdf2''' prev_hash prev_result i
      | i == iterations = prev_result
      | i > iterations = error "Count must be at least 1"
      | otherwise = pbkdf2''' current_hash result (i + 1)
        where
          current_hash = (hash' prev_hash)
          result = xorByteStrings current_hash prev_result

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
