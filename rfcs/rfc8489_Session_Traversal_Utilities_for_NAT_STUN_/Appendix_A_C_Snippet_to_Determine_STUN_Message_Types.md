# Appendix A.  C Snippet to Determine STUN Message Types

   Given a 16-bit STUN message type value in host byte order in msg_type
   parameter, below are C macros to determine the STUN message types:

   <CODE BEGINS>
   #define IS_REQUEST(msg_type)       (((msg_type) & 0x0110) == 0x0000)
   #define IS_INDICATION(msg_type)    (((msg_type) & 0x0110) == 0x0010)
   #define IS_SUCCESS_RESP(msg_type)  (((msg_type) & 0x0110) == 0x0100)
   #define IS_ERR_RESP(msg_type)      (((msg_type) & 0x0110) == 0x0110)
   <CODE ENDS>

   A function to convert method and class into a message type:

   <CODE BEGINS>
   int type(int method, int cls) {
     return (method & 0x1F80) << 2 | (method & 0x0070) << 1
       | (method & 0x000F) | (cls & 0x0002) << 7
       | (cls & 0x0001) << 4;
     }
   <CODE ENDS>

   A function to extract the method from the message type:

   <CODE BEGINS>
   int method(int type) {
     return (type & 0x3E00) >> 2 | (type & 0x00E0) >> 1
       | (type & 0x000F);
     }
   <CODE ENDS>

   A function to extract the class from the message type:

   <CODE BEGINS>
   int cls(int type) {
     return (type & 0x0100) >> 7 | (type & 0x0010) >> 4;
     }
   <CODE ENDS>

