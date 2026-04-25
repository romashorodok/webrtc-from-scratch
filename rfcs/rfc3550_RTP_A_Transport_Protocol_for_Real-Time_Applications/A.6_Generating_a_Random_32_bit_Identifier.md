## A.6 Generating a Random 32-bit Identifier

The following subroutine generates a random 32-bit identifier using
the MD5 routines published in RFC 1321 [32].  The system routines may
not be present on all operating systems, but they should serve as
hints as to what kinds of information may be used.  Other system
calls that may be appropriate include


o  getdomainname(),

o  getwd(), or

o  getrusage().

"Live" video or audio samples are also a good source of random
numbers, but care must be taken to avoid using a turned-off
microphone or blinded camera as a source [17].

Use of this or a similar routine is recommended to generate the
initial seed for the random number generator producing the RTCP
period (as shown in Appendix A.7), to generate the initial values for
the sequence number and timestamp, and to generate SSRC values.
Since this routine is likely to be CPU-intensive, its direct use to
generate RTCP periods is inappropriate because predictability is not
an issue.  Note that this routine produces the same result on
repeated calls until the value of the system clock changes unless
different values are supplied for the type argument.

/*
* Generate a random 32-bit quantity.
*/
#include <sys/types.h>   /* u_long */
#include <sys/time.h>    /* gettimeofday() */
#include <unistd.h>      /* get..() */
#include <stdio.h>       /* printf() */
#include <time.h>        /* clock() */
#include <sys/utsname.h> /* uname() */
#include "global.h"      /* from RFC 1321 */
#include "md5.h"         /* from RFC 1321 */

#define MD_CTX MD5_CTX
#define MDInit MD5Init
#define MDUpdate MD5Update
#define MDFinal MD5Final

static u_long md_32(char *string, int length)
{
    MD_CTX context;
    union {
        char   c[16];
        u_long x[4];
    } digest;
    u_long r;
    int i;

    MDInit (&context);



    MDUpdate (&context, string, length);
    MDFinal ((unsigned char *)&digest, &context);
    r = 0;
    for (i = 0; i < 3; i++) {
        r ^= digest.x[i];
    }
    return r;
}                               /* md_32 */

/*
* Return random unsigned 32-bit quantity.  Use 'type' argument if
* you need to generate several different values in close succession.
*/
u_int32 random32(int type)
{
    struct {
        int     type;
        struct  timeval tv;
        clock_t cpu;
        pid_t   pid;
        u_long  hid;
        uid_t   uid;
        gid_t   gid;
        struct  utsname name;
    } s;

    gettimeofday(&s.tv, 0);
    uname(&s.name);
    s.type = type;
    s.cpu  = clock();
    s.pid  = getpid();
    s.hid  = gethostid();
    s.uid  = getuid();
    s.gid  = getgid();
    /* also: system uptime */

    return md_32((char *)&s, sizeof(s));
}                               /* random32 */

