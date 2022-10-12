module Tests where

import IC.TestSuite

import Crypto
    ( gcd,
      phi,
      computeCoeffs,
      inverse,
      modPow,
      smallestCoPrimeOf,
      genKeys,
      rsaEncrypt,
      rsaDecrypt,
      toInt,
      toChar,
      add,
      substract,
      ecbEncrypt,
      ecbDecrypt,
      cbcEncrypt,
      cbcDecrypt )

-------------------------------------------------------------------------------
-- PART 1 : asymmetric encryption

gcdTestCases
  = [ (0, 0) ==> 0
    , (0, 8) ==> 8
    , (8, 0) ==> 8
    , (3, 3) ==> 3
    , (12, 16) ==> 4
    , (16, 12) ==> 4
    , (65, 40) ==> 5
    , (735, 1239) ==> 21
    , (283756, 8723645) ==> 1
    , (99999999, 88888888) ==> 11111111
    , (983415687456, 7686435) ==> 3
    , (8347, 7234) ==> 1
    , (43426, 73682) ==> 2
    , (2, 3) ==> 1
    , (77, 90) ==> 1
    ]

phiTestCases
  = [ 0 ==> 0
    , 1 ==> 1
    , 2 ==> 1
    , 6 ==> 2
    , 18 ==> 6
    , 17 ==> 16
    , 31 ==> 30
    , 35 ==> 24
    , 77 ==> 60
    , 857 ==> 856
    , 933 ==> 620
    , 721 ==> 612
    , 167 ==> 166
    , 491 ==> 490
    , 937 ==> 936
    , 1171 ==> 1170
    , 2161 ==> 2160
    ]

modPowTestCases
  = [ (0, 0, 1) ==> 0
    , (1, 1, 1) ==> 0
    , (1, 1, 2) ==> 1
    , (13481, 11237, 6) ==> 5
    , (8, 0, 1) ==> 0
    , (8, 0, 5) ==> 1
    , (237, 1, 1000) ==> 237
    , (859237, 1, 1000) ==> 237
    , (33893, 2, 10000) ==> 5449
    , (7433893, 2, 10000) ==> 5449
    , (13481503, 11237126, 46340) ==> 6629
    , (520, 1314, 959) ==> 218
    , (52045, 25047, 848) ==> 741
    , (98345, 8374, 98) ==> 23
    , (87523, 875, 23) ==> 13
    , (937, 984, 124) ==> 101
    , (87, 834, 23) ==> 12
    , (157, 8725, 97) ==> 40
    , (2585, 3578, 35) ==> 25
    , (86279, 65879, 56478) ==> 34217
    ]

computeCoeffsTestCases
  = [ (0, 0) ==> (1, 0)
    , (0, 8) ==> (0, 1)
    , (12, 16) ==> (-1, 1)
    , (16, 12) ==> (1, -1)
    , (65, 40) ==> (-3, 5)
    , (735, 1239) ==> (27, -16)
    , (30, 30) ==> (0, 1)
    , (79, 79) ==> (0, 1)
    , (79, 78) ==> (1, -1)
    , (123, 321) ==> (47, -18)
    , (7982, 91) ==> (3, -263)
    , (2378, 7869234) ==> (-1949108, 589)
    ]

inverseTestCases
  = [ (11, 16) ==> 3
    , (4, 15) ==> 4
    , (18, 35) ==> 2
    , (35, 18) ==> 17
    , (12, 91) ==> 38
    , (34, 91) ==> 83
    , (64, 91) ==> 64
    , (2, 3) ==> 2
    , (9, 8) ==> 1
    , (100, 3) ==> 1
    -- I attempted to compute inverse 100 2, and it returned an error on the screen (which was expected)--
    , (33, 91) ==> 80
    , (198, 89) ==> 49
    ]

smallestCoPrimeOfTestCases
  = [ 1 ==> 2
    , 2 ==> 3
    , 12 ==> 5
    , 13 ==> 2
    , 30 ==> 7
    , 210 ==> 11
    , 15 ==> 2
    , 17 ==> 2
    , 222 ==> 5
    , 234 ==> 5
    , 987124 ==> 3
    , 1247 ==> 2
    ]

genKeysTestCases
  = [ (2, 3) ==> ((3,6),(1,6))
    , (17, 23) ==> ((3,391),(235,391))
    , (101, 83) ==> ((3,8383),(5467,8383))
    , (401, 937) ==> ((7,375737),(213943,375737))
    , (613, 997) ==> ((5,611161),(243821,611161))
    , (26641, 26437) ==> ((7,704308117),(100607863,704308117))
    , (34561, 13145) ==> ((7,454304345),(259575223,454304345))
    , (92842, 123) ==> ((5,11419566),(4530641,11419566))
    , (13, 28) ==> ((5,364),(65,364))
    , (872, 3829) ==> ((5,3338888),(2000513,3338888))
    , (1789, 7637) ==> ((5,13662593),(8191901,13662593))
    , (7, 8) ==> ((5,56),(17,56))
    ]

rsaEncryptTestCases
  = [ (4321, (3,8383)) ==> 3694
    , (324561, (5,611161)) ==> 133487
    , (1234, (5,611161)) ==> 320878
    , (704308111, (7,704308117)) ==> 704028181
    , (12476, (21376,37645)) ==> 36846
    , (456734, (913752, 4673812)) ==> 4001336
    , (5201314, (1314, 520)) ==> 456
    , (1314, (5201314, 520)) ==> 456
    , (520, (1314, 5201314)) ==> 1501712
    , (520, (5201314, 1314)) ==> 502
    ]

rsaDecryptTestCases
  = [ (3694, (5467,8383)) ==> 4321
    , (133487, (243821,611161)) ==> 324561
    , (320878, (243821,611161)) ==> 1234
    , (704028181, (100607863,704308117)) ==> 704308111
    , (98765, (7583241, 2184556)) ==> 1441293
    , (5201314, (1314, 520)) ==> 456
    , (1314, (520, 5201314)) ==> 2430210
    , (594250, (14250, 184250)) ==> 7250
    , (12469, (9872, 2109438547)) ==> 258188610
    , (2, (3, 4)) ==> 0
    ]

-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

toIntTestCases
  = [ 'a' ==> 0
    , 'z' ==> 25
    , 'h' ==> 7
    , 'b' ==> 1
    , 'c' ==> 2
    , 'd' ==> 3
    , 'e' ==> 4
    , 'f' ==> 5
    , 'g' ==> 6
    , 'i' ==> 8
    , 'j' ==> 9
    , 'k' ==> 10
    , 'l' ==> 11
    , 'm' ==> 12
    , 'n' ==> 13
    , 'o' ==> 14
    , 'p' ==> 15
    , 'q' ==> 16
    , 'r' ==> 17
    , 's' ==> 18
    , 't' ==> 19
    , 'u' ==> 20
    , 'v' ==> 21
    , 'w' ==> 22
    , 'x' ==> 23
    , 'y' ==> 24
    ]

toCharTestCases
  = [ 0 ==> 'a'
    , 25 ==> 'z'
    , 7 ==> 'h'
    , 1 ==> 'b'
    , 2 ==> 'c'
    , 3 ==> 'd'
    , 4 ==> 'e'
    , 5 ==> 'f'
    , 6 ==> 'g'
    , 8 ==> 'i'
    , 9 ==> 'j'
    , 10 ==> 'k'
    , 11 ==> 'l'
    , 12 ==> 'm'
    , 13 ==> 'n'
    , 14 ==> 'o'
    , 15 ==> 'p'
    , 16 ==> 'q'
    , 17 ==> 'r'
    , 18 ==> 's'
    , 19 ==> 't'
    , 20 ==> 'u'
    , 21 ==> 'v'
    , 22 ==> 'w'
    , 23 ==> 'x'
    , 24 ==> 'y'
    , 26 ==> 'a'
    , 27 ==> 'b'
    , (-1) ==> 'z'
    , (-3) ==> 'x'
    , (-26) ==> 'a'
    ]

addTestCases
  = [ ('a', 'a') ==> 'a'
    , ('d', 's') ==> 'v'
    , ('w', 't') ==> 'p'
    , ('a', 'b') ==> 'b'
    , ('b', 'c') ==> 'd'
    , ('z', 'b') ==> 'a'
    -- below are examples from the specification
    , ('a', 'c') ==> 'c'
    , ('y', 'e') ==> 'c'
    ]

substractTestCases
  = [ ('a', 'a') ==> 'a'
    , ('v', 's') ==> 'd'
    , ('p', 'w') ==> 't'
    , ('b', 'a') ==> 'b'
    , ('a', 'b') ==> 'z'
    , ('l', 'm') ==> 'z'
    -- below are examples from the specification
    , ('h', 'c') ==> 'f'
    , ('b', 'e') ==> 'x'
    ]

ecbEncryptTestCases
  = [ ('w', "") ==> ""
    , ('d', "w") ==> "z"
    , ('x', "bonjour") ==> "ylkglro"
    , ('k', "hello") ==> "rovvy"
    , ('l', "hola") ==> "szwl"
    , ('p', "nihao") ==> "cxwpd"
    , ('c', "konichiwa") ==> "mqpkejkyc"
    , ('f', "aniasaiyo") ==> "fsnfxfndt"
    ]

ecbDecryptTestCases
  = [ ('w', "") ==> ""
    , ('d', "z") ==> "w"
    , ('x', "ylkglro") ==> "bonjour"
    , ('k', "rovvy") ==> "hello"
    , ('l', "szwl") ==> "hola"
    , ('p', "cxwpd") ==> "nihao"
    , ('c', "mqpkejkyc") ==> "konichiwa"
    , ('f', "fsnfxfndt") ==> "aniasaiyo"
    ]

cbcEncryptTestCases
  = [ ('w', 'i', "") ==> ""
    , ('d', 'i', "w") ==> "h"
    , ('x', 'w', "bonjour") ==> "ufpvgxl"
    , ('k', 'q', "hello") ==> "hvqlj"
    , ('l', 'c', "hola") ==> "utpa"
    , ('p', 't', "nihao") ==> "vsodg"
    , ('c', 'p', "konichiwa") ==> "brgqudnln"
    , ('f', 'l', "aniasaiyo") ==> "qivaxcpsl"
    ]

cbcDecryptTestCases
  = [ ('w', 'i', "") ==> ""
    , ('d', 'i', "h") ==> "w"
    , ('x', 'w', "ufpvgxl") ==> "bonjour"
    , ('k', 'q', "hvqlj") ==> "hello"
    , ('l', 'c', "utpa") ==> "hola"
    , ('p', 't', "vsodg") ==> "nihao"
    , ('c', 'p', "brgqudnln") ==> "konichiwa"
    , ('f', 'l', "qivaxcpsl") ==> "aniasaiyo"
    ]

-- You can add your own test cases above

allTestCases
  = [ TestCase "gcd" (uncurry Crypto.gcd)
                     gcdTestCases
    , TestCase "phi" phi
                     phiTestCases
    , TestCase "modPow" (uncurry3 modPow)
                        modPowTestCases
    , TestCase "computeCoeffs" (uncurry computeCoeffs)
                             computeCoeffsTestCases
    , TestCase "inverse" (uncurry inverse)
                         inverseTestCases
    , TestCase "smallestCoPrimeOf" (smallestCoPrimeOf)
                                   smallestCoPrimeOfTestCases
    , TestCase "genKeys" (uncurry genKeys)
                         genKeysTestCases
    , TestCase "rsaEncrypt" (uncurry rsaEncrypt)
                            rsaEncryptTestCases
    , TestCase "rsaDecrypt" (uncurry rsaDecrypt)
                            rsaDecryptTestCases
    , TestCase "toInt" (toInt)
                       toIntTestCases
    , TestCase "toChar" (toChar)
                       toCharTestCases
    , TestCase "add" (uncurry add)
                     addTestCases
    , TestCase "substract" (uncurry substract)
                           substractTestCases
    , TestCase "ecbEncrypt" (uncurry ecbEncrypt)
                            ecbEncryptTestCases
    , TestCase "ecbDecrypt" (uncurry ecbDecrypt)
                            ecbDecryptTestCases
    , TestCase "cbcEncrypt" (uncurry3 cbcEncrypt)
                            cbcEncryptTestCases
    , TestCase "cbcDecrypt" (uncurry3 cbcDecrypt)
                       cbcDecryptTestCases
    ]


runTests = mapM_ goTest allTestCases

main = runTests
