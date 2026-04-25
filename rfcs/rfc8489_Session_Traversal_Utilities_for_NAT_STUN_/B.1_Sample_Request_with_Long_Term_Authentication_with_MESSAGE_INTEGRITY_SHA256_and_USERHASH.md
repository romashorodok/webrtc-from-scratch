## B.1.  Sample Request with Long-Term Authentication with MESSAGE-
      INTEGRITY-SHA256 and USERHASH

   This request uses the following parameters:

   Username: "<U+30DE><U+30C8><U+30EA><U+30C3><U+30AF><U+30B9>" (without
   quotes) unaffected by OpaqueString [RFC8265] processing

   Password: "The<U+00AD>M<U+00AA>tr<U+2168>" and "TheMatrIX" (without
   quotes) respectively before and after OpaqueString [RFC8265]
   processing

   Nonce: "obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA" (without quotes)

   Realm: "example.org" (without quotes)

        00 01 00 9c      Request type and message length
        21 12 a4 42      Magic cookie
        78 ad 34 33   }
        c6 ad 72 c0   }  Transaction ID
        29 da 41 2e   }
        00 1e 00 20      USERHASH attribute header
        4a 3c f3 8f   }
        ef 69 92 bd   }
        a9 52 c6 78   }
        04 17 da 0f   }  Userhash value (32 bytes)
        24 81 94 15   }
        56 9e 60 b2   }
        05 c4 6e 41   }
        40 7f 17 04   }
        00 15 00 29      NONCE attribute header
        6f 62 4d 61   }
        74 4a 6f 73   }
        32 41 41 41   }
        43 66 2f 2f   }
        34 39 39 6b   }  Nonce value and padding (3 bytes)
        39 35 34 64   }
        36 4f 4c 33   }
        34 6f 4c 39   }
        46 53 54 76   }
        79 36 34 73   }
        41 00 00 00   }
        00 14 00 0b      REALM attribute header
        65 78 61 6d   }
        70 6c 65 2e   }  Realm value (11 bytes) and padding (1 byte)
        6f 72 67 00   }
        00 1c 00 20      MESSAGE-INTEGRITY-SHA256 attribute header
        e4 68 6c 8f   }
        0e de b5 90   }
        13 e0 70 90   }
        01 0a 93 ef   }  HMAC-SHA256 value
        cc bc cc 54   }
        4c 0a 45 d9   }
        f8 30 aa 6d   }
        6f 73 5a 01   }