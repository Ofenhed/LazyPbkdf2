module Crypto.Pbkdf2 (pbkdf2, pbkdf2_iterative) where

import Data.Bits (shiftR)
import Data.Bits(xor)

import qualified Data.ByteString.Lazy as B
import qualified Data.Binary as Bin

octetsBE :: Bin.Word32 -> [Bin.Word8]
octetsBE w = 
    [ fromIntegral (w `shiftR` 24)
    , fromIntegral (w `shiftR` 16)
    , fromIntegral (w `shiftR` 8)
    , fromIntegral w
    ]

xorByteStrings x y
  | B.length x == B.length y = B.pack $ B.zipWith xor x y
  | otherwise = error "xor bytestrings are not of equal length"

pbkdf2_internal createBlock prf password salt iterations = B.concat $ createBlock hash' first_iteration 1
  where
    hash' = prf password
    first_iteration hash = additional_iterations hash hash 1
    additional_iterations prev_hash prev_result i
      | i == iterations = prev_result
      | i > iterations = error "Count must be at least 1"
      | otherwise = additional_iterations current_hash result (i + 1)
        where
          current_hash = (hash' prev_hash)
          result = xorByteStrings current_hash prev_result

-- | This is a non standard variation of PBKDF2 which recursively uses the
-- last generated value to improve the salt. In difference to pbkdf2 the
-- salt can not be precalculated for every iteration (with a simple append
-- of 4 bytes), but has to be calculated for every single iteration. This
-- also creates a function where you cannot jump in the stream without
-- calculating everything before it.  Compared to the standard this
-- function only changes the salt for the initial PBKDF2 value of each
-- iteration to include a salt iterated from earlier parts of the PBKDF2
-- stream. This can be verified by removing the i from (hash' $ B.concat
-- [i, salt, B.pack $ octetsBE c]).
--
-- The added salt for the first iteration will be "", and all following
-- will be calculated as (PRF output input), where output is the output of
-- the previous block and input is the added salt for the previous block.
-- Notice that the output from the previous block is put in the password
-- filed of the PRF.
pbkdf2_iterative :: (B.ByteString -> B.ByteString -> B.ByteString)
                     -- ^ @PRF@, the PRF function to be used for the
                     -- iterative PBKDF2. The first argument is secret, the
                     -- second argument is not.
                 -> B.ByteString -- ^ @Password@, the secret to use in the PBKDF2 computations.
                 -> B.ByteString -- ^ @Salt@, the not neccesarily secret data to use in the PBKDF2 computations.
                 -> Integer -- ^ @c@, number of iterations for the the PBKDF2 computations.
                 -> B.ByteString -- ^ @DK@, the output data in the format of an unlimited lazy ByteString.
pbkdf2_iterative prf password salt iterations = pbkdf2_internal (createBlocks $ B.pack []) prf password salt iterations
  where
    createBlocks :: B.ByteString -> (B.ByteString -> B.ByteString) -> (B.ByteString -> B.ByteString) -> Bin.Word32 -> [B.ByteString]
    createBlocks i hash iterate c = let prev = (iterate (hash $ B.concat [i, salt, B.pack $ octetsBE c]))
                                      in prev:(createBlocks (prf prev i) hash iterate $ c + 1)

pbkdf2 :: (B.ByteString -> B.ByteString -> B.ByteString)
           -- ^ @PRF@, the PRF function to be used for PBKDF2. The first
           -- argument is secret, the second argument is not.
       -> B.ByteString -- ^ @Password@, the secret to use in the PBKDF2 computations.
       -> B.ByteString -- ^ @Salt@, the not neccesarily secret data to use in the PBKDF2 computations.
       -> Integer -- ^ @c@, number of iterations for the the PBKDF2 computations.
       -> B.ByteString -- ^ @DK@, the output data in the format of an unlimited lazy ByteString.
pbkdf2 prf password salt iterations = pbkdf2_internal (createBlocks True) prf password salt iterations
  where
    createBlocks :: Bool -> (B.ByteString -> B.ByteString) -> (B.ByteString -> B.ByteString) -> Bin.Word32 -> [B.ByteString]
    createBlocks False _ _ 1 = error "Hashing algorithm looped, stopping to maintain security of data" -- Paranoia, but that's useful when doing crypto
    createBlocks _ hash iterate i = (iterate (hash $ B.concat [salt, B.pack $ octetsBE i])):(createBlocks False hash iterate $ i + 1)
