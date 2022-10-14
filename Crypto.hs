module Crypto where

import Data.Char

import Prelude hiding (gcd)

{-
The advantage of symmetric encryption schemes like AES is that they are efficient
and we can encrypt data of arbitrary size. The problem is how to share the key.
The flaw of the RSA is that it is slow and we can only encrypt data of size lower
than the RSA modulus n, usually around 1024 bits (64 bits for this exercise!).

We usually encrypt messages with a private encryption scheme like AES-256 with
a symmetric key k. The key k of fixed size 256 bits for example is then exchanged
via the aymmetric RSA.
-}

------------------------------------------------------------------------------
-- PART 1 : asymmetric encryption

-- This function is called gcd, which is short for "greatest common divisor"
-- It returns the greatest common divisor after taking two ints m, n as an input
gcd :: Int -> Int -> Int
gcd m n
  | n == 0    = m
  | m == 0    = n
  | otherwise = gcd n (m `mod` n)


-- The phi function finds the number of ints that coprime with an input int m in the range 1 - m inclusive
phi :: Int -> Int
phi m = length [n | n <- [1..m], gcd m n == 1] 

-- The computeCoeffs function calculates (u, v, d) the gcd (d) and Bezout coefficients (u and v)
-- such that au + bv = d
-- It takes in two ints a b as its input, and returns a tuple consisting variables q, r, u, v
computeCoeffs :: Int -> Int -> (Int, Int)
computeCoeffs a b
  | b == 0    = (1, 0) 
  | otherwise = (v, u - q * v)
  where
      (q, r) = quotRem a b 
      (u, v) = computeCoeffs b r 

-- Inverse of a modulo m
-- This function takes in two ints a and m and returns an inverse (also an int) of a modulo m
inverse :: Int -> Int -> Int
inverse a m
  | gcd a m == 1 = fst (computeCoeffs a m) `mod` m
  | otherwise    = error "Inverse Error"

-- Here's a code for Inverse that I find very handy if we define modPow first: inverse a m = modPow a (phi m - 1) m.
-- It is an alternative way of doing inverse without computeCoeffs


-- The modPow function takes in three ints a (base), k (power) and m (modulo) and returns another int of value (a^k mod m)
modPow :: Int -> Int -> Int -> Int
modPow a k m
    | k == 0    = mod 1 m
    | k == 1    = mod a m
    | even k    = modPow c (div k 2) m
    | otherwise = mod (a * modPow c (div k 2) m) m
    where
        c = mod a m ^ 2 `mod` m  -- using modPov incurrs a stack overflow (reasons explained by Wojtek through teams)

-- Returns the smallest integer that is coprime with phi
checkPrime :: Int -> Int -> Int
checkPrime r s
  | gcd r s == 1 = s
  | otherwise    = checkPrime r (s + 1)

smallestCoPrimeOf :: Int -> Int
smallestCoPrimeOf phi = checkPrime phi 2


-- Generates keys pairs (public, private) = ((e, n), (d, n))
-- given two "large" distinct primes, p and q
genKeys :: Int -> Int -> ((Int, Int), (Int, Int))
genKeys p q
  = ((e, n), (d, n))
  where
      n = p * q
      x = (p - 1) * (q - 1)
      e = smallestCoPrimeOf x
      d = inverse e x


-- RSA encryption/decryption
rsaEncrypt :: Int -> (Int, Int) -> Int
rsaEncrypt x (e, n)
  = modPow x e n

rsaDecrypt :: Int -> (Int, Int) -> Int
rsaDecrypt c (d, n)
  = modPow c d n

-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

-- Returns position of a letter in the alphabet
-- We are saying that a is the 0th letter
toInt :: Char -> Int
toInt c
  | ord c >= ord 'a' && ord c <= ord 'z' = ord c - ord 'a'
  | ord c >= ord 'A' && ord c <= ord 'Z' = ord c - ord 'A'
  | otherwise                            = error "Non-alphabetic Input"

-- Returns the n^th letter (case insensitive)
toChar :: Int -> Char
toChar x
  = chr(ord 'a' + mod x z)
  where
    z = toInt 'z' + 1


-- "adds" two letters
add :: Char -> Char -> Char 
add p q
   = toChar (toInt p + toInt q)

-- "substracts" two letters p q
substract :: Char -> Char -> Char
substract p q
  = toChar (toInt p - toInt q)


-- the next functions present
-- 2 modes of operation for block ciphers : ECB and CBC
-- based on a symmetric encryption function e/d such as "add"

-- ecb (electronic codebook) with block size of a letter
ecbEncrypt :: Char -> String -> String
ecbEncrypt k m
    | m == ""     = ""
    | otherwise   = add k m' : ecbEncrypt k ms
    where
        (m' : ms) = m

-- Alternative method of writing ecbEncrypt        
{-
ecbEncrypt k m
  = map (add k) m
-}

ecbDecrypt :: Char -> String -> String
ecbDecrypt k' u                                        
    | u == ""     = ""
    | otherwise   = substract u' k' : ecbDecrypt k' us
    where                                               
        (u' : us) = u

-- cbc (cipherblock chaining) encryption with block size of a letter
-- initialisation vector iv is a letter
-- last argument is message m as a string

cbcEncrypt :: Char -> Char -> String -> String
cbcEncrypt k v x
  | x == ""   = ""
  | otherwise = m : cbcEncrypt k m xs
  where
    (x' : xs) = x
    i = add x' v
    m = add i k

cbcDecrypt :: Char -> Char -> String -> String
cbcDecrypt k' v c
  | c == ""   = ""
  | otherwise = substract t v : cbcDecrypt k' c' cs
  where
    (c' : cs) = c
    t = substract c' k'