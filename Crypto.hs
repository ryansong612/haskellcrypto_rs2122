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

-------------------------------------------------------------------------------
-- PART 1 : asymmetric encryption

-- This function is called gcd, which is short for "greatest common divisor"
-- It returns the greatest common divisor after taking two ints m, n as an input
gcd :: Int -> Int -> Int
gcd m n
  | n == 0    = m  -- if one of the inputs is 0, then return the other input, and this also accounts for the case where m and n are both 0 (gcd 0 0 = 0)
  | m == 0    = n  -- same as above
  | otherwise = gcd n (m `mod` n)


-- The phi function finds the number of ints that coprime with an input int m in the range 1 - m inclusive
phi :: Int -> Int
phi m = length [n | n <- [1..m], gcd m n == 1]   -- Using list comprehension, we generate a list of all ints that coprime with m in the range 1 - m using the gcd function (they corpime when the greatest common divisor between them is 1)
                                                 -- Then we simply take the length of it

-- The computeCoeffs function calculates (u, v, d) the gcd (d) and Bezout coefficients (u and v)
-- such that au + bv = d
-- It takes in two ints a b as its input, and returns a tuple consisting variables q, r, u, v
computeCoeffs :: Int -> Int -> (Int, Int)
computeCoeffs a b
  | b == 0    = (1, 0) 
  | otherwise = (v, u - q * v)
  where
      (q, r) = quotRem a b               -- According to the specification, q and r are the quotient and remainders when we divide a by b
      (u, v) = computeCoeffs b r         -- Then we simply apply recursion of computeCoeffs to the known relationship bu + rv = gcd(b, r) to find out the precise values of u, v and return them as a tuple 

-- Inverse of a modulo m
-- This function takes in two ints a and m and returns an inverse (also an int) of a modulo m
inverse :: Int -> Int -> Int
inverse a m
  | gcd a m == 1 = fst (computeCoeffs a m) `mod` m   -- This line uses the premises of implementing RSA mentioned in the specification "multiplicative inverse"
  | otherwise    = error "Inverse Error"               -- An int a has an inverse modulo m if and only if gcd(a, m) = 1, hence we code the otherwise situation as an error exit

-- Here's a code for Inverse that I find very handy if we define modPow first: inverse a m = modPow a (phi m - 1) m.
-- It is an alternative way of doing inverse without computeCoeffs


-- The modPow function takes in three ints a (base), k (power) and m (modulo) and returns another int of value (a^k mod m)
modPow :: Int -> Int -> Int -> Int
modPow a k m
    | k == 0    = mod 1 m                          -- base case #1 when the power is 0, R ^ 0 = 1, hence we return 1 mod m
    | k == 1    = mod a m                          -- base case #2 when the power is 1, R ^ 1 = R, hence we return a mod m
    | even k    = modPow c (div k 2) m             -- simply writing the formula in specification using code
    | otherwise = mod (a * modPow c (div k 2) m) m -- simply writing the second formula using code
    where
        c = mod a m ^ 2 `mod` m                -- using modPov incurrs a stack overflow (reasons explained by Wojtek through teams)

-- Returns the smallest integer that is coprime with phi
-- I did not discuss cases where input s is 0 because the smallestCoPrime premise is when r is a positive integer
checkPrime :: Int -> Int -> Int      -- The checkPrime function acts as a checkpoint for us whenever we increment s by 1 after we've found gcd(r, s) != 1
checkPrime r s                       -- like gcd, it takes two ints r and s as its inputs
  | gcd r s == 1 = s                 -- If the gcd function returns a one, then we have already found our smallest Coprime, we will then simply return it. This includes the case where r = 0 (see gcd code where gcd 0 n = n)
  | otherwise = checkPrime r (s + 1) -- Otherwise we increment s by 1 and keep checking whether it is the smallest Coprime that we are looking for

smallestCoPrimeOf :: Int -> Int      -- the smallestCoPrime takes in only one input phi, we then checkPrime for phi and 2 and it will yield us with a desired result. This is what the specification asked us for.
smallestCoPrimeOf phi = checkPrime phi 2

  
-- Here is a more brutal way of writing smallestCoPrimeOf using list comprehension (I put it here as an alternative method)
-- smallestCoPrimeOf :: Int -> Int
-- smallestCoPrimeOf phi = head [n | n <- [2..(phi+1)], gcd n phi == 1]
-- Using list comprehension, we generate a list consisting all elements that coprime with phi (gcd = 1) and take the head of the list since it is in ascending order


-- Generates keys pairs (public, private) = ((e, n), (d, n))
-- given two "large" distinct primes, p and q
genKeys :: Int -> Int -> ((Int, Int), (Int, Int))
genKeys p q
  = ((e, n), (d, n))          -- Notice that in the specification sheet, the actual name of the variable n is its uppercase. However, we cannot use that exact name for that variable in Haskell because uppercase beginners are considered types
  where
      n = p * q               -- Simply plugging in the information we obtained from the specification for each variable
      x = (p - 1) * (q - 1)
      e = smallestCoPrimeOf x
      d = inverse e x


-- RSA encryption/decryption
rsaEncrypt :: Int -> (Int, Int) -> Int
rsaEncrypt x (e, n)           -- This function takes a plain text x, and a tuple of the public pairs generated by genKeys as its input. And encrypts the text using the RSA method.
  = modPow x e n              -- Recognizing that the formula given in the specification sheet is actually just a modPow function

rsaDecrypt :: Int -> (Int, Int) -> Int
rsaDecrypt c (d, n)           -- This function takes a plain text x, and a tuple of the private pairs generated by genKeys as its input. And decrypts the text using the RSA method.
  = modPow c d n              -- We also recognize that the formula for rsaDecrypt is a modPow function

-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

-- Returns position of a letter in the alphabet
-- We are saying that a is the 0th letter
toInt :: Char -> Int            -- The toInt function will take a Char as its input, and return an int that indicates its position in the alphabet list (a - z, or A - Z)
toInt c
  | ord c >= ord 'a' && ord c <= ord 'z' = ord c - ord 'a'     -- returns the position if the input is a lowercase alphabet
  | ord c >= ord 'A' && ord c <= ord 'Z' = ord c - ord 'A'     -- returns the position if the input is an uppercase alphabet
  | otherwise = error "toInt Error"                            -- if the input is not an alphabet, we exit with an error

-- Returns the n^th letter
-- pre: x >= -26 (this is because subtract function's minimum value is -25 when 'a' - 'z')
-- we are saying that a is the 0th letter
-- if the input exceeds 25, then we simply loop all the way back to 'a' and count again
-- if the input is negative (-26 <= x < 0)
toChar :: Int -> Char
toChar x
  | x >= 0 && x <= 25 = chr(ord 'a' + x)                        -- where the input is between 0 and 25 and we simply increment 'a's ASCII value based on the input and return the character
  | x > 25            = chr(x `mod` z - 1 + ord 'a')            -- where the input is out of the range of 0-25, and we need to loop back through the alphabet list and return the character
  | x < 0 && x >= -26 = chr(ord 'z' + x + 1)                    -- where the input is between -1 and -25 and we need to loop through the alphabet list in reverse order and return the character
  | otherwise = error "toChar Error"                            -- the pre condition of the function is that x >= -26, if the input is out of that range then we exit with an error
  where
      z = toInt 'z'

-- Below is a different way of writing toChar (this goes hand in hand in the alternative method to write add)
{-| x >= 0 && x <= 25 = chr (x + ord 'a')
  | otherwise = error "toChar Error"-}
-- "adds" two letters
add :: Char -> Char -> Char        -- this function takes in two inputs, both characters, adds their positions and returns the character that is located at the summed position, simple arithmetics
add p q
   = toChar (toInt p + toInt q)

-- Below is the different way of writing add if we use the alternative program for toChar
   {- add p q
        = toChar t
        where
          m = toInt p + toInt q
          t = mod m 26 -}
-- End of alternative method


-- "substracts" two letters
substract :: Char -> Char -> Char  -- this function also takes in two inputs, both characters, but this time it substracts their positions and return character that is located at the position of difference
substract p q
  = toChar (toInt p - toInt q)

-- Here is a different way of writing substract if we use the alternative program for toChar
  {- substract p q
        = toChar t
        where
          m = toInt p - toInt q + 2600      -- (Inspiration from Jack) What a genius play to add 2600 so that we ensure the difference is a positive int to input into t
          t = mod m 26  -}
-- the next functions present
-- 2 modes of operation for block ciphers : ECB and CBC
-- based on a symmetric encryption function e/d such as "add"

-- ecb (electronic codebook) with block size of a letter
ecbEncrypt :: Char -> String -> String
ecbEncrypt k m                                 -- the ecbEncrypt function takes in k, a character, as its key, and m, a string, as its message to be encrypted, then it returns an encrypted string
    | m == ""   = ""                           -- for the case where the input message is an empty string, then no matter how we encrypt it, it is still an empty string, hence we return it
    | otherwise = add k m' : ecbEncrypt k ms   -- if the input is not empty, then we simply implement the formula mentioned in the specs, and apply recursion to encrypt the message
    where
        (m' : ms) = m                          -- defining variables m' and ms

-- Alternative method of writing ecbEncrypt        
{-
ecbEncrypt k m
  = map (add k) m
-}

ecbDecrypt :: Char -> String -> String
ecbDecrypt k' u                                         -- the ecbDecrypt function takes in k', a character, as its key, and u, an encrypted message/string, then it returns a decrypted string
    | u == ""   = ""                                    -- for the case where the input encrypted message is an empty string, then still, no matter how we try to decrypt it, it is still empty. We return it.
    | otherwise = substract u' k' : ecbDecrypt k' us    -- if the input is not empty, then we still just implement the formula mentioned in the specs, or the reverse of the encryption code (using subtract)
    where                                               -- Note: We also use recursion here, but be aware of the order of input for substract (u - k' != k' - u)
        (u' : us) = u                                   -- defining variables u' and us

-- cbc (cipherblock chaining) encryption with block size of a letter
-- initialisation vector iv is a letter
-- last argument is message m as a string

{- -}

cbcEncrypt :: Char -> Char -> String -> String
cbcEncrypt k v x                         -- the cbcEncrypt function also takes in k as its character key, x as its message string to be encrypted, but it also has an initializing vector v. In this case, it's a Char
  | x == "" = ""                         -- Same as before, if the input string is empty, no need to encrypt it, we return it as an empty string
  | otherwise = m : cbcEncrypt k m xs    -- Implementing the formula into code form, and using the recursion of cbcEncrypt
  where
    (x' : xs) = x                        -- defining variables x', xs, i, and m
    i = add x' v
    m = add i k

cbcDecrypt :: Char -> Char -> String -> String
cbcDecrypt k' v c                                     -- the cbcDecrypt function takes in k' as its character key, c as its ciphered message to decrypt, and an initializing vector v
  | c == "" = ""                                      -- if the input is empty, then return empty string because it will be the same after decryption
  | otherwise = substract t v : cbcDecrypt k' c' cs   -- Implementing the decryption formula into code form and also using the recursion of cbcDecrypt
  where
    (c' : cs) = c                                     -- defining variables c', cs, t
    t = substract c' k'