{-# LANGUAGE Safe #-}
module Crypto.Pbkdf2 (pbkdf2, pbkdf2_blocks, pbkdf2_iterative, pbkdf2_iterative_blocks) where

import Data.Bits (shiftR)
import Data.Bits (xor)
import Data.Word (Word8, Word32)

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB

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

pbkdf2_internal createBlocks prf password salt iterations = createBlocks $ first_iteration . hash'
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

-- | This is a non standard variation of PBKDF2 which recursively uses the last
-- generated value to improve the salt. In difference to pbkdf2 the salt can
-- not be precalculated for every iteration (with a simple append of 4 bytes),
-- but has to be calculated for every single iteration. This also creates a
-- function where you cannot jump in the stream without calculating everything
-- before it.  Compared to the standard this function only changes the salt for
-- the initial PBKDF2 value of each iteration to include a salt iterated from
-- earlier parts of the PBKDF2 stream. This can be verified by removing the
-- blockSalt from (hash $ B.concat [blockSalt, salt, B.pack $ octetsBE c]).
--
-- The added salt for the first iteration will be "", and all following will be
-- calculated as (PRF output input), where output is the output of the previous
-- block and input is the added salt for the previous block.  Notice that the
-- output from the previous block is put in the secrets field of the PRF.
pbkdf2_iterative_blocks :: (B.ByteString -> B.ByteString -> B.ByteString)
                            -- ^ @PRF@, the PRF function to be used for the
                            -- iterative PBKDF2. The first argument is secret, the
                            -- second argument is not.
                        -> B.ByteString -- ^ @Password@, the secret to use in the PBKDF2 computations.
                        -> B.ByteString -- ^ @Salt@, the not neccesarily secret data to use in the PBKDF2 computations.
                        -> Integer -- ^ @c@, number of iterations for the the PBKDF2 computations.
                        -> [B.ByteString] -- ^ @DK@, the output data in the
                            -- format of an unlimited lazy list of strict
                            -- ByteStrings, each of which is a block from
                            -- @PRF@. This can be useful for precalculations of
                            -- the next block, but by the design of this
                            -- algorithm it cannot be used to compute blocks in
                            -- parallel.
pbkdf2_iterative_blocks prf password salt iterations = pbkdf2_internal (createBlocks (B.pack []) 1) prf password salt iterations
  where
    createBlocks :: B.ByteString -> Word32 -> (B.ByteString -> B.ByteString) -> [B.ByteString]
    createBlocks blockSalt i hash = let prev = (hash $ B.concat [blockSalt, salt, B.pack $ octetsBE i])
                                     in prev:(createBlocks (prf prev blockSalt) (i + 1) hash)

-- | This is the same as 'pbkdf2_iterative_blocks', except that it returns a lazy bytestring instead.
pbkdf2_iterative :: (B.ByteString -> B.ByteString -> B.ByteString)
                     -- ^ @PRF@, the PRF function to be used for the
                     -- iterative PBKDF2. The first argument is secret, the
                     -- second argument is not.
                 -> B.ByteString -- ^ @Password@, the secret to use in the PBKDF2 computations.
                 -> B.ByteString -- ^ @Salt@, the not neccesarily secret data to use in the PBKDF2 computations.
                 -> Integer -- ^ @c@, number of iterations for the the PBKDF2 computations.
                 -> LB.ByteString -- ^ @DK@, the output data in the format of an unlimited lazy ByteString.
pbkdf2_iterative prf password salt iterations = LB.concat $ map LB.fromStrict $ pbkdf2_iterative_blocks prf password salt iterations

-- | This is the standard PBKDF2 algorithm.
pbkdf2_blocks :: (B.ByteString -> B.ByteString -> B.ByteString)
           -- ^ @PRF@, the PRF function to be used for PBKDF2. The first
           -- argument is secret, the second argument is not.
       -> B.ByteString -- ^ @Password@, the secret to use in the PBKDF2 computations.
       -> B.ByteString -- ^ @Salt@, the not neccesarily secret data to use in the PBKDF2 computations.
       -> Integer -- ^ @c@, number of iterations for the the PBKDF2 computations.
       -> [B.ByteString] -- ^ @DK@, the output data in the
           -- format of an unlimited lazy list of strict
           -- ByteStrings, each of which is a block from
           -- @PRF@. These can be calculated in parallel.
pbkdf2_blocks prf password salt iterations = pbkdf2_internal (createBlocks True 1) prf password salt iterations
  where
    createBlocks :: Bool -> Word32 -> (B.ByteString -> B.ByteString) -> [B.ByteString]
    createBlocks False 1 _ = error "Hashing algorithm looped, stopping to maintain security of data" -- Paranoia, but that's useful when doing crypto
    createBlocks _ i hash = (hash $ B.concat [salt, B.pack $ octetsBE i]):(createBlocks False (i + 1) hash)

-- | This is the same as 'pbkdf2_blocks', except that it returns a lazy bytestring instead.
pbkdf2 :: (B.ByteString -> B.ByteString -> B.ByteString)
           -- ^ @PRF@, the PRF function to be used for PBKDF2. The first
           -- argument is secret, the second argument is not.
       -> B.ByteString -- ^ @Password@, the secret to use in the PBKDF2 computations.
       -> B.ByteString -- ^ @Salt@, the not neccesarily secret data to use in the PBKDF2 computations.
       -> Integer -- ^ @c@, number of iterations for the the PBKDF2 computations.
       -> LB.ByteString -- ^ @DK@, the output data in the format of an unlimited lazy ByteString.
pbkdf2 prf password salt iterations = LB.concat $ map LB.fromStrict $ pbkdf2_blocks prf password salt iterations
