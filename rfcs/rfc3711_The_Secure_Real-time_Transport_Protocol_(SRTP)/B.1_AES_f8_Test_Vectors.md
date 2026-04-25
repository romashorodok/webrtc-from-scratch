## B.1.  AES-f8 Test Vectors

   SRTP PREFIX LENGTH  :   0

   RTP packet header   :   806e5cba50681de55c621599

   RTP packet payload  :   70736575646f72616e646f6d6e657373
                           20697320746865206e65787420626573
                           74207468696e67

   ROC                 :   d462564a
   key                 :   234829008467be186c3de14aae72d62c
   salt key            :   32f2870d
   key-mask (m)        :   32f2870d555555555555555555555555
   key XOR key-mask    :   11baae0dd132eb4d3968b41ffb278379

   IV                  :   006e5cba50681de55c621599d462564a
   IV'                 :   595b699bbd3bc0df26062093c1ad8f73



   j = 0
   IV' xor j           :   595b699bbd3bc0df26062093c1ad8f73
   S(-1)               :   00000000000000000000000000000000
   IV' xor S(-1) xor j :   595b699bbd3bc0df26062093c1ad8f73
   S(0)                :   71ef82d70a172660240709c7fbb19d8e
   plaintext           :   70736575646f72616e646f6d6e657373
   ciphertext          :   019ce7a26e7854014a6366aa95d4eefd

   j = 1
   IV' xor j           :   595b699bbd3bc0df26062093c1ad8f72
   S(0)                :   71ef82d70a172660240709c7fbb19d8e
   IV' xor S(0) xor j  :   28b4eb4cb72ce6bf020129543a1c12fc
   S(1)                :   3abd640a60919fd43bd289a09649b5fc
   plaintext           :   20697320746865206e65787420626573
   ciphertext          :   1ad4172a14f9faf455b7f1d4b62bd08f

   j = 2
   IV' xor j           :   595b699bbd3bc0df26062093c1ad8f71
   S(1)                :   3abd640a60919fd43bd289a09649b5fc
   IV' xor S(1) xor j  :   63e60d91ddaa5f0b1dd4a93357e43a8d
   S(2)                :   220c7a8715266565b09ecc8a2a62b11b
   plaintext           :   74207468696e67
   ciphertext          :   562c0eef7c4802

