#ifndef TOMCRYPT_MACROS_H_
#define TOMCRYPT_MACROS_H_

#include "AES_tables.h"
struct sha256_state {
    unsigned long length;
    unsigned int state[8], curlen;
    unsigned char buf[64];
};

typedef union Hash_state {
    char dummy[1];
    struct sha256_state sha256;
    void *data;
} hash_state;
typedef struct Hmac_state {
     hash_state     md;
     int            hash;
     hash_state     hashstate;
     unsigned char  *key;
} hmac_state;


int sha256_init(hash_state * md);
int sha256_process(hash_state * md, unsigned char *in, unsigned long inlen);
int sha256_done(hash_state * md, unsigned char *hash);
int sha256_test(void);

int hmac_init(hmac_state *hmac, int hash, unsigned char *key, unsigned long keylen);
int hmac_process(hmac_state *hmac, unsigned char *in, unsigned long inlen);
int hmac_done(hmac_state *hmac, unsigned char *out, unsigned long *outlen);
int hash_memory(int hash, unsigned char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen);


struct rijndael_key {
   unsigned int eK[60], dK[60];
   int Nr;
};		   
			   
typedef union Symmetric_key {
   struct rijndael_key rijndael;
   void   *data;
} symmetric_key;

typedef struct {
   /** The index of the cipher chosen */
   int                 cipher,
   /** The block size of the given cipher */
                       blocklen;
   /** The current IV */
   unsigned char       IV[16];
   /** The scheduled key */
   symmetric_key       key;
} symmetric_CBC;


int ECB_DEC(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int ECB_ENC(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
int SETUP(const unsigned char *key, unsigned long keylen, int num_rounds, symmetric_key *skey);





/*
struct sha256_state {
    unsigned long length;
    unsigned int state[8], curlen;
    unsigned char buf[64];
};

typedef union Hash_state {
    char dummy[1];
    struct sha256_state sha256;
    void *data;
} hash_state;

typedef struct Hmac_state {
     hash_state     md;
     int            hash;
     hash_state     hashstate;
     unsigned char  *key;
} hmac_state;

int sha256_init(hash_state * md);
int sha256_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int sha256_done(hash_state * md, unsigned char *hash);
int sha256_test(void);

int hmac_init(hmac_state *hmac, int hash, const unsigned char *key, unsigned long keylen);
int hmac_process(hmac_state *hmac, const unsigned char *in, unsigned long inlen);
int hmac_done(hmac_state *hmac, unsigned char *out, unsigned long *outlen);
int hash_memory(int hash, const unsigned char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen);
*/
#define MAXBLOCKSIZE  128
#define XMALLOC  malloc
#define XFREE    free
#define XMEMCPY memcpy
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y))
#define S(x, n)         RORc((x),(n))
#define R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))




#define ENDIAN_NEUTRAL
#ifdef ENDIAN_NEUTRAL

#define STORE32L(x, y)                                                                     \
  do { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD32L(x, y)                            \
  do { x = ((unsigned int)((y)[3] & 255)<<24) | \
           ((unsigned int)((y)[2] & 255)<<16) | \
           ((unsigned int)((y)[1] & 255)<<8)  | \
           ((unsigned int)((y)[0] & 255)); } while(0)

#define STORE64L(x, y)                                                                     \
  do { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);   \
       (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);   \
       (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD64L(x, y)                                                       \
  do { x = (((unsigned long)((y)[7] & 255))<<56)|(((unsigned long)((y)[6] & 255))<<48)| \
           (((unsigned long)((y)[5] & 255))<<40)|(((unsigned long)((y)[4] & 255))<<32)| \
           (((unsigned long)((y)[3] & 255))<<24)|(((unsigned long)((y)[2] & 255))<<16)| \
           (((unsigned long)((y)[1] & 255))<<8)|(((unsigned long)((y)[0] & 255))); } while(0)

#define STORE32H(x, y)                                                                     \
  do { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); } while(0)

#define LOAD32H(x, y)                            \
  do { x = ((unsigned int)((y)[0] & 255)<<24) | \
           ((unsigned int)((y)[1] & 255)<<16) | \
           ((unsigned int)((y)[2] & 255)<<8)  | \
           ((unsigned int)((y)[3] & 255)); } while(0)

#define STORE64H(x, y)                                                                     \
do { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); } while(0)

#define LOAD64H(x, y)                                                      \
do { x = (((unsigned long)((y)[0] & 255))<<56)|(((unsigned long)((y)[1] & 255))<<48) | \
         (((unsigned long)((y)[2] & 255))<<40)|(((unsigned long)((y)[3] & 255))<<32) | \
         (((unsigned long)((y)[4] & 255))<<24)|(((unsigned long)((y)[5] & 255))<<16) | \
         (((unsigned long)((y)[6] & 255))<<8)|(((unsigned long)((y)[7] & 255))); } while(0)

#endif /* ENDIAN_NEUTRAL */

#ifdef ENDIAN_LITTLE

#ifdef LTC_HAVE_BSWAP_BUILTIN

#define STORE32H(x, y)                          \
do { unsigned int __t = __builtin_bswap32 ((x));     \
      XMEMCPY ((y), &__t, 4); } while(0)

#define LOAD32H(x, y)                           \
do { XMEMCPY (&(x), (y), 4);                    \
      (x) = __builtin_bswap32 ((x)); } while(0)

#elif !defined(LTC_NO_BSWAP) && (defined(INTEL_CC) || (defined(__GNUC__) && (defined(__DJGPP__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__i386__) || defined(__x86_64__))))

#define STORE32H(x, y)           \
asm __volatile__ (               \
   "bswapl %0     \n\t"          \
   "movl   %0,(%1)\n\t"          \
   "bswapl %0     \n\t"          \
      ::"r"(x), "r"(y));

#define LOAD32H(x, y)          \
asm __volatile__ (             \
   "movl (%1),%0\n\t"          \
   "bswapl %0\n\t"             \
   :"=r"(x): "r"(y));

#else

#define STORE32H(x, y)                                                                     \
  do { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); } while(0)

#define LOAD32H(x, y)                            \
  do { x = ((unsigned int)((y)[0] & 255)<<24) | \
           ((unsigned int)((y)[1] & 255)<<16) | \
           ((unsigned int)((y)[2] & 255)<<8)  | \
           ((unsigned int)((y)[3] & 255)); } while(0)

#endif

#ifdef LTC_HAVE_BSWAP_BUILTIN

#define STORE64H(x, y)                          \
do { unsigned long __t = __builtin_bswap64 ((x));     \
      XMEMCPY ((y), &__t, 8); } while(0)

#define LOAD64H(x, y)                           \
do { XMEMCPY (&(x), (y), 8);                    \
      (x) = __builtin_bswap64 ((x)); } while(0)

/* x86_64 processor */
#elif !defined(LTC_NO_BSWAP) && (defined(__GNUC__) && defined(__x86_64__))

#define STORE64H(x, y)           \
asm __volatile__ (               \
   "bswapq %0     \n\t"          \
   "movq   %0,(%1)\n\t"          \
   "bswapq %0     \n\t"          \
   ::"r"(x), "r"(y): "memory");

#define LOAD64H(x, y)          \
asm __volatile__ (             \
   "movq (%1),%0\n\t"          \
   "bswapq %0\n\t"             \
   :"=r"(x): "r"(y): "memory");

#else

#define STORE64H(x, y)                                                                     \
do { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); } while(0)

#define LOAD64H(x, y)                                                      \
do { x = (((unsigned long)((y)[0] & 255))<<56)|(((unsigned long)((y)[1] & 255))<<48) | \
         (((unsigned long)((y)[2] & 255))<<40)|(((unsigned long)((y)[3] & 255))<<32) | \
         (((unsigned long)((y)[4] & 255))<<24)|(((unsigned long)((y)[5] & 255))<<16) | \
         (((unsigned long)((y)[6] & 255))<<8)|(((unsigned long)((y)[7] & 255))); } while(0)

#endif

#ifdef ENDIAN_32BITWORD

#define STORE32L(x, y)        \
  do { unsigned int  __t = (x); XMEMCPY(y, &__t, 4); } while(0)

#define LOAD32L(x, y)         \
  do { XMEMCPY(&(x), y, 4); } while(0)

#define STORE64L(x, y)                                                                     \
  do { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);   \
       (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);   \
       (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD64L(x, y)                                                       \
  do { x = (((unsigned long)((y)[7] & 255))<<56)|(((unsigned long)((y)[6] & 255))<<48)| \
           (((unsigned long)((y)[5] & 255))<<40)|(((unsigned long)((y)[4] & 255))<<32)| \
           (((unsigned long)((y)[3] & 255))<<24)|(((unsigned long)((y)[2] & 255))<<16)| \
           (((unsigned long)((y)[1] & 255))<<8)|(((unsigned long)((y)[0] & 255))); } while(0)

#else /* 64-bit words then  */

#define STORE32L(x, y)        \
  do { unsigned int __t = (x); XMEMCPY(y, &__t, 4); } while(0)

#define LOAD32L(x, y)         \
  do { XMEMCPY(&(x), y, 4); x &= 0xFFFFFFFF; } while(0)

#define STORE64L(x, y)        \
  do { unsigned long __t = (x); XMEMCPY(y, &__t, 8); } while(0)

#define LOAD64L(x, y)         \
  do { XMEMCPY(&(x), y, 8); } while(0)

#endif /* ENDIAN_64BITWORD */

#endif /* ENDIAN_LITTLE */

#ifdef ENDIAN_BIG
#define STORE32L(x, y)                                                                     \
  do { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD32L(x, y)                            \
  do { x = ((unsigned int)((y)[3] & 255)<<24) | \
           ((unsigned int)((y)[2] & 255)<<16) | \
           ((unsigned int)((y)[1] & 255)<<8)  | \
           ((unsigned int)((y)[0] & 255)); } while(0)

#define STORE64L(x, y)                                                                     \
do { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);     \
     (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);     \
     (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);     \
     (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD64L(x, y)                                                      \
do { x = (((unsigned long)((y)[7] & 255))<<56)|(((unsigned long)((y)[6] & 255))<<48) | \
         (((unsigned long)((y)[5] & 255))<<40)|(((unsigned long)((y)[4] & 255))<<32) | \
         (((unsigned long)((y)[3] & 255))<<24)|(((unsigned long)((y)[2] & 255))<<16) | \
         (((unsigned long)((y)[1] & 255))<<8)|(((unsigned long)((y)[0] & 255))); } while(0)

#ifdef ENDIAN_32BITWORD

#define STORE32H(x, y)        \
  do { unsigned int __t = (x); XMEMCPY(y, &__t, 4); } while(0)

#define LOAD32H(x, y)         \
  do { XMEMCPY(&(x), y, 4); } while(0)

#define STORE64H(x, y)                                                                     \
  do { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);   \
       (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);   \
       (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);   \
       (y)[6] = (unsigned char)(((x)>>8)&255);  (y)[7] = (unsigned char)((x)&255); } while(0)

#define LOAD64H(x, y)                                                       \
  do { x = (((unsigned long)((y)[0] & 255))<<56)|(((unsigned long)((y)[1] & 255))<<48)| \
           (((unsigned long)((y)[2] & 255))<<40)|(((unsigned long)((y)[3] & 255))<<32)| \
           (((unsigned long)((y)[4] & 255))<<24)|(((unsigned long)((y)[5] & 255))<<16)| \
           (((unsigned long)((y)[6] & 255))<<8)| (((unsigned long)((y)[7] & 255))); } while(0)

#else /* 64-bit words then  */

#define STORE32H(x, y)        \
  do { unsigned int __t = (x); XMEMCPY(y, &__t, 4); } while(0)

#define LOAD32H(x, y)         \
  do { XMEMCPY(&(x), y, 4); x &= 0xFFFFFFFF; } while(0)

#define STORE64H(x, y)        \
  do { unsigned long __t = (x); XMEMCPY(y, &__t, 8); } while(0)

#define LOAD64H(x, y)         \
  do { XMEMCPY(&(x), y, 8); } while(0)

#endif /* ENDIAN_64BITWORD */
#endif /* ENDIAN_BIG */

#define BSWAP(x)  ( ((x>>24)&0x000000FFUL) | ((x<<24)&0xFF000000UL)  | \
                    ((x>>8)&0x0000FF00UL)  | ((x<<8)&0x00FF0000UL) )


/* 32-bit Rotates */
#if defined(_MSC_VER)
#define LTC_ROx_ASM

/* instrinsic rotate */
#include <stdlib.h>
#pragma intrinsic(_lrotr,_lrotl)
#define ROR(x,n) _lrotr(x,n)
#define ROL(x,n) _lrotl(x,n)
#define RORc(x,n) _lrotr(x,n)
#define ROLc(x,n) _lrotl(x,n)

#elif !defined(__STRICT_ANSI__) && defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__)) && !defined(INTEL_CC) && !defined(LTC_NO_ASM)
#define LTC_ROx_ASM

static inline unsigned int ROL(unsigned int word, int i)
{
   asm ("roll %%cl,%0"
      :"=r" (word)
      :"0" (word),"c" (i));
   return word;
}

static inline unsigned int ROR(unsigned int word, int i)
{
   asm ("rorl %%cl,%0"
      :"=r" (word)
      :"0" (word),"c" (i));
   return word;
}

#ifndef LTC_NO_ROLC

#define ROLc(word,i) ({ \
   unsigned int __ROLc_tmp = word; \
   __asm__ ("roll %2, %0" : \
            "=r" (__ROLc_tmp) : \
            "0" (__ROLc_tmp), \
            "I" (i)); \
            __ROLc_tmp; \
   })
#define RORc(word,i) ({ \
   unsigned int __RORc_tmp = word; \
   __asm__ ("rorl %2, %0" : \
            "=r" (__RORc_tmp) : \
            "0" (__RORc_tmp), \
            "I" (i)); \
            __RORc_tmp; \
   })

#else

#define ROLc ROL
#define RORc ROR

#endif

#elif !defined(__STRICT_ANSI__) && defined(LTC_PPC32)
#define LTC_ROx_ASM

static inline unsigned int ROL(unsigned int word, int i)
{
   asm ("rotlw %0,%0,%2"
      :"=r" (word)
      :"0" (word),"r" (i));
   return word;
}

static inline unsigned int ROR(unsigned int word, int i)
{
   asm ("rotlw %0,%0,%2"
      :"=r" (word)
      :"0" (word),"r" (32-i));
   return word;
}

#ifndef LTC_NO_ROLC

static inline unsigned int ROLc(unsigned int word, const int i)
{
   asm ("rotlwi %0,%0,%2"
      :"=r" (word)
      :"0" (word),"I" (i));
   return word;
}

static inline unsigned int RORc(unsigned int word, const int i)
{
   asm ("rotrwi %0,%0,%2"
      :"=r" (word)
      :"0" (word),"I" (i));
   return word;
}

#else

#define ROLc ROL
#define RORc ROR

#endif


#else

/* rotates the hard way */
#define ROL(x, y) ( (((unsigned int)(x)<<(unsigned int)((y)&31)) | (((unsigned int)(x)&0xFFFFFFFFUL)>>(unsigned int)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROR(x, y) ( ((((unsigned int)(x)&0xFFFFFFFFUL)>>(unsigned int)((y)&31)) | ((unsigned int)(x)<<(unsigned int)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROLc(x, y) ( (((unsigned int)(x)<<(unsigned int)((y)&31)) | (((unsigned int)(x)&0xFFFFFFFFUL)>>(unsigned int)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define RORc(x, y) ( ((((unsigned int)(x)&0xFFFFFFFFUL)>>(unsigned int)((y)&31)) | ((unsigned int)(x)<<(unsigned int)(32-((y)&31)))) & 0xFFFFFFFFUL)

#endif


/* 64-bit Rotates */
#if !defined(__STRICT_ANSI__) && defined(__GNUC__) && defined(__x86_64__) && !defined(_WIN64) && !defined(LTC_NO_ASM)

static inline unsigned long ROL64(unsigned long word, int i)
{
   asm("rolq %%cl,%0"
      :"=r" (word)
      :"0" (word),"c" (i));
   return word;
}

static inline unsigned long ROR64(unsigned long word, int i)
{
   asm("rorq %%cl,%0"
      :"=r" (word)
      :"0" (word),"c" (i));
   return word;
}

#ifndef LTC_NO_ROLC

#define ROL64c(word,i) ({ \
   unsigned long __ROL64c_tmp = word; \
   __asm__ ("rolq %2, %0" : \
            "=r" (__ROL64c_tmp) : \
            "0" (__ROL64c_tmp), \
            "J" (i)); \
            __ROL64c_tmp; \
   })
#define ROR64c(word,i) ({ \
   unsigned long __ROR64c_tmp = word; \
   __asm__ ("rorq %2, %0" : \
            "=r" (__ROR64c_tmp) : \
            "0" (__ROR64c_tmp), \
            "J" (i)); \
            __ROR64c_tmp; \
   })

#else /* LTC_NO_ROLC */

#define ROL64c ROL64
#define ROR64c ROR64

#endif

#else /* Not x86_64  */

#define ROL64(x, y) \
    ( (((x)<<((unsigned long)(y)&63)) | \
      (((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((unsigned long)64-((y)&63)))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROR64(x, y) \
    ( ((((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((unsigned long)(y)&CONST64(63))) | \
      ((x)<<((unsigned long)(64-((y)&CONST64(63)))))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROL64c(x, y) \
    ( (((x)<<((unsigned long)(y)&63)) | \
      (((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((unsigned long)64-((y)&63)))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROR64c(x, y) \
    ( ((((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((unsigned long)(y)&CONST64(63))) | \
      ((x)<<((unsigned long)(64-((y)&CONST64(63)))))) & CONST64(0xFFFFFFFFFFFFFFFF))

#endif

#ifndef MAX
   #define MAX(x, y) ( ((x)>(y))?(x):(y) )
#endif

#ifndef MIN
   #define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

#ifndef LTC_UNUSED_PARAM
   #define LTC_UNUSED_PARAM(x) (void)(x)
#endif

/* extract a byte portably */
#ifdef _MSC_VER
   #define byte(x, n) ((unsigned char)((x) >> (8 * (n))))
#else
   #define byte(x, n) (((x) >> (8 * (n))) & 255)
#endif

#endif 

