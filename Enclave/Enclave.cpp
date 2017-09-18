/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */



#include "string.h"
#include "stdlib.h"
#include "stdio.h"
#include "sgx_trts.h"
#include "sgx_thread.h"
#include "sgx_tseal.h"
#include "Enclave_t.h"

#include "sgx_key.h"
#include "sgx_utils.h"
#include "sgx_trts.h"

#include "tomcrypt_macros.h"
#include "../App/app.h"


void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    print(buf);
}

void zeromem(volatile void *out, size_t outlen)
{
   volatile char *mem = (volatile char *) out;
   while (outlen-- > 0) {
      *mem++ = '\0';
   }
}

static unsigned int setup_mix(unsigned int temp)
{
   return (Te4_3[byte(temp, 2)]) ^
          (Te4_2[byte(temp, 1)]) ^
          (Te4_1[byte(temp, 0)]) ^
          (Te4_0[byte(temp, 3)]);
}


unsigned char savedSecret[100] = {'\0'};
unsigned char savedPlaintext[100] = {'\0'};
unsigned char savedCiphertext[100] = {'\0'};


/** hash descriptor */
extern  struct ltc_hash_descriptor {
    /** name of hash */
    char *name;
    /** internal ID */
    unsigned char ID;
    /** Size of digest in octets */
    unsigned long hashsize;
    /** Input block size in octets */
    unsigned long blocksize;
    /** ASN.1 OID */
    unsigned long OID[16];
    /** Length of DER encoding */
    unsigned long OIDlen;

    /** Init a hash state
      @param hash   The hash to initialize
      @return CRYPT_OK if successful
    */
    int (*init)(hash_state *hash);
    /** Process a block of data
      @param hash   The hash state
      @param in     The data to hash
      @param inlen  The length of the data (octets)
      @return CRYPT_OK if successful
    */
    int (*process)(hash_state *hash, unsigned char *in, unsigned long inlen);
    /** Produce the digest and store it
      @param hash   The hash state
      @param out    [out] The destination of the digest
      @return CRYPT_OK if successful
    */
    int (*done)(hash_state *hash, unsigned char *out);
    /** Self-test
      @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
    */
    int (*test)(void);

    /* accelerated hmac callback: if you need to-do multiple packets just use the generic hmac_memory and provide a hash callback */
    int  (*hmac_block)(unsigned char *key, unsigned long  keylen,
          unsigned char *in,  unsigned long  inlen,
          unsigned char *out, unsigned long *outlen);

} hash_descriptor[];

//int sha256_init(hash_state * md);
//int sha256_process(hash_state * md, const unsigned char *in, unsigned long inlen);
//int sha256_done(hash_state * md, unsigned char *hash);
//int sha256_test(void);

int sha256_init(hash_state * md)
{
    md->sha256.curlen = 0;
    md->sha256.length = 0;
    md->sha256.state[0] = 0x6A09E667UL;
    md->sha256.state[1] = 0xBB67AE85UL;
    md->sha256.state[2] = 0x3C6EF372UL;
    md->sha256.state[3] = 0xA54FF53AUL;
    md->sha256.state[4] = 0x510E527FUL;
    md->sha256.state[5] = 0x9B05688CUL;
    md->sha256.state[6] = 0x1F83D9ABUL;
    md->sha256.state[7] = 0x5BE0CD19UL;
    return 0;
}


/* compress 512-bits */
#ifdef LTC_CLEAN_STACK
static int _sha256_compress(hash_state * md, unsigned char *buf)
#else
static int  sha256_compress(hash_state * md, unsigned char *buf)
#endif
{
    unsigned int S[8], W[64], t0, t1;
#ifdef LTC_SMALL_CODE
    int t;
#endif
    int i;

    /* copy state into S */
    for (i = 0; i < 8; i++) {
        S[i] = md->sha256.state[i];
    }

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++) {
        LOAD32H(W[i], buf + (4*i));
    }

    /* fill W[16..63] */
    for (i = 16; i < 64; i++) {
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    }        

    /* Compress */
#ifdef LTC_SMALL_CODE   
#define RND(a,b,c,d,e,f,g,h,i)                         \
     t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];   \
     t1 = Sigma0(a) + Maj(a, b, c);                    \
     d += t0;                                          \
     h  = t0 + t1;

     for (i = 0; i < 64; ++i) {
         RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i);
         t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4]; 
         S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t;
     }  
#else 
#define RND(a,b,c,d,e,f,g,h,i,ki)                    \
     t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];   \
     t1 = Sigma0(a) + Maj(a, b, c);                  \
     d += t0;                                        \
     h  = t0 + t1;

    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],0,0x428a2f98);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],1,0x71374491);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],2,0xb5c0fbcf);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],3,0xe9b5dba5);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],4,0x3956c25b);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],5,0x59f111f1);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],6,0x923f82a4);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],7,0xab1c5ed5);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],8,0xd807aa98);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],9,0x12835b01);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],10,0x243185be);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],11,0x550c7dc3);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],12,0x72be5d74);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],13,0x80deb1fe);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],14,0x9bdc06a7);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],15,0xc19bf174);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],16,0xe49b69c1);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],17,0xefbe4786);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],18,0x0fc19dc6);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],19,0x240ca1cc);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],20,0x2de92c6f);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],21,0x4a7484aa);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],22,0x5cb0a9dc);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],23,0x76f988da);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],24,0x983e5152);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],25,0xa831c66d);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],26,0xb00327c8);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],27,0xbf597fc7);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],28,0xc6e00bf3);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],29,0xd5a79147);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],30,0x06ca6351);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],31,0x14292967);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],32,0x27b70a85);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],33,0x2e1b2138);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],34,0x4d2c6dfc);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],35,0x53380d13);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],36,0x650a7354);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],37,0x766a0abb);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],38,0x81c2c92e);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],39,0x92722c85);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],40,0xa2bfe8a1);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],41,0xa81a664b);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],42,0xc24b8b70);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],43,0xc76c51a3);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],44,0xd192e819);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],45,0xd6990624);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],46,0xf40e3585);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],47,0x106aa070);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],48,0x19a4c116);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],49,0x1e376c08);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],50,0x2748774c);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],51,0x34b0bcb5);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],52,0x391c0cb3);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],53,0x4ed8aa4a);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],54,0x5b9cca4f);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],55,0x682e6ff3);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],56,0x748f82ee);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],57,0x78a5636f);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],58,0x84c87814);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],59,0x8cc70208);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],60,0x90befffa);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],61,0xa4506ceb);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],62,0xbef9a3f7);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],63,0xc67178f2);

#undef RND     
    
#endif     

    /* feedback */
    for (i = 0; i < 8; i++) {
        md->sha256.state[i] = md->sha256.state[i] + S[i];
    }
    return 0;
}

#ifdef LTC_CLEAN_STACK
static int sha256_compress(hash_state * md, unsigned char *buf)
{
    int err;
	printf("ran!\n");
    err = _sha256_compress(md, buf);
	printf("ran %d!\n", err);
//    burn_stack(sizeof(ulong32) * 74);
    return err;
}
#endif


#define HASH_PROCESS(func_name, compress_name, state_var, block_size)                       \
int func_name (hash_state *md, unsigned char *in, unsigned long inlen)               \
{                                                                                           \
    unsigned long n;                                                                        \
    int           err;                                                                      \
    if (md-> state_var .curlen > sizeof(md-> state_var .buf)) {                             \
       return -1;                                                            \
    }                                                                                       \
    if ((md-> state_var .length + inlen) < md-> state_var .length) {                        \
      return -1;                                                           \
    }                                                                                       \
    while (inlen > 0) {                                                                     \
        if (md-> state_var .curlen == 0 && inlen >= block_size) {                           \
           if ((err = compress_name (md, (unsigned char *)in)) != 0) {               \
              return err;                                                                   \
           }                                                                                \
           md-> state_var .length += block_size * 8;                                        \
           in             += block_size;                                                    \
           inlen          -= block_size;                                                    \
        } else {                                                                            \
           n = MIN(inlen, (block_size - md-> state_var .curlen));                           \
           XMEMCPY(md-> state_var .buf + md-> state_var.curlen, in, (size_t)n);              \
           md-> state_var .curlen += n;                                                     \
           in             += n;                                                             \
           inlen          -= n;                                                             \
           if (md-> state_var .curlen == block_size) {                                      \
              if ((err = compress_name (md, md-> state_var .buf)) != 0) {            \
                 return err;                                                                \
              }                                                                             \
              md-> state_var .length += 8*block_size;                                       \
              md-> state_var .curlen = 0;                                                   \
           }                                                                                \
       }                                                                                    \
    }                                                                                       \
    return 0;                                                                        \
}
HASH_PROCESS(sha256_process, sha256_compress, sha256, 64)

int sha256_done(hash_state *md, unsigned char *out)
{
    int i;

    if (md->sha256.curlen >= sizeof(md->sha256.buf)) {
       return -1;
    }


    /* increase the length of the message */
    md->sha256.length += md->sha256.curlen * 8;

    /* append the '1' bit */
    md->sha256.buf[md->sha256.curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
 *      * then compress.  Then we can fall back to padding zeros and length
 *           * encoding like normal.
 *                */
    if (md->sha256.curlen > 56) {
        while (md->sha256.curlen < 64) {
            md->sha256.buf[md->sha256.curlen++] = (unsigned char)0;
        }
        sha256_compress(md, md->sha256.buf);
        md->sha256.curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->sha256.curlen < 56) {
        md->sha256.buf[md->sha256.curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64H(md->sha256.length, md->sha256.buf+56);
    sha256_compress(md, md->sha256.buf);

    /* copy output */
    for (i = 0; i < 8; i++) {
        STORE32H(md->sha256.state[i], out+(4*i));
    }

    return 0;
}


int  sha256_test(void)
{
 #ifndef LTC_TEST
    return -1;
 #else    
  static const struct {
      char *msg;
      unsigned char hash[32];
  } tests[] = {
    { "abc",
      { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad }
    },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 }
    },
  };

  int i;
  unsigned char tmp[32];
  hash_state md;

  for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
      sha256_init(&md);
      sha256_process(&md, (unsigned char*)tests[i].msg, (unsigned long)strlen(tests[i].msg));
      sha256_done(&md, tmp);
      if (XMEMCMP(tmp, tests[i].hash, 32) != 0) {
         return CRYPT_FAIL_TESTVECTOR;
      }
  }
  return 0;
 #endif
}


const struct ltc_hash_descriptor sha256_desc =
{
    "sha256",
    0,
    32,
    64,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 1,  },
   9,

    &sha256_init,
    &sha256_process,
    &sha256_done,
    &sha256_test,
    NULL
};

struct ltc_hash_descriptor hash_descriptor[1];
//extern const struct ltc_hash_descriptor sha256_desc;
#define LTC_HMAC_BLOCKSIZE sha256_desc.blocksize

int hash_memory(int hash, unsigned char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen)
{
    hash_state *md;
    int err;


    if (*outlen < hash_descriptor[hash].hashsize) {
       *outlen = hash_descriptor[hash].hashsize;
       return -1;
    }

    md = (hash_state *) XMALLOC(sizeof(hash_state));
    if (md == NULL) {
       return -1;
    }

    if ((err = hash_descriptor[hash].init(md)) != 0) {
       goto LBL_ERR;
    }
    if ((err = hash_descriptor[hash].process(md, in, inlen)) != 0) {
       goto LBL_ERR;
    }
    err = hash_descriptor[hash].done(md, out);
    *outlen = hash_descriptor[hash].hashsize;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
    zeromem(md, sizeof(hash_state));
#endif
    XFREE(md);

    return err;
}


int hmac_init(hmac_state *hmac, int hash,  unsigned char *key, unsigned long keylen)
{
    unsigned char *buf;
    unsigned long hashsize;
    unsigned long i, z;
    int err;

    hmac->hash = hash;
    hashsize   = hash_descriptor[hash].hashsize;

    /* valid key length? */
    if (keylen == 0) {
        return -1;
    }

    /* allocate ram for buf */
    buf = (unsigned char*) XMALLOC(LTC_HMAC_BLOCKSIZE);
    if (buf == NULL) {
       return -1;
    }

    /* allocate memory for key */
    hmac->key = (unsigned char*) XMALLOC(LTC_HMAC_BLOCKSIZE);
    if (hmac->key == NULL) {
       XFREE(buf);
       return -1;
    }
    /* (1) make sure we have a large enough key */
    if(keylen > LTC_HMAC_BLOCKSIZE) {
        z = LTC_HMAC_BLOCKSIZE;
        if ((err = hash_memory(hash, key, keylen, hmac->key, &z)) != 0) {
           goto LBL_ERR;
        }
        keylen = hashsize;
    } else {
        XMEMCPY(hmac->key, key, (size_t)keylen);
    }

    if(keylen < LTC_HMAC_BLOCKSIZE) {
       zeromem((hmac->key) + keylen, (size_t)(LTC_HMAC_BLOCKSIZE - keylen));
    }

    /* Create the initial vector for step (3) */
    for(i=0; i < LTC_HMAC_BLOCKSIZE;   i++) {
       buf[i] = hmac->key[i] ^ 0x36;
    }

    /* Pre-pend that to the hash data */
    if ((err = hash_descriptor[hash].init(&hmac->md)) != 0) {
       goto LBL_ERR;
    }

    if ((err = hash_descriptor[hash].process(&hmac->md, buf, LTC_HMAC_BLOCKSIZE)) != 0) {
       goto LBL_ERR;
    }
    goto done;
LBL_ERR:
    /* free the key since we failed */
    XFREE(hmac->key);
done:
#ifdef LTC_CLEAN_STACK
   zeromem(buf, LTC_HMAC_BLOCKSIZE);
#endif

   XFREE(buf);
   return err;
}


int hmac_process(hmac_state *hmac,  unsigned char *in, unsigned long inlen)
{
    return hash_descriptor[hmac->hash].process(&hmac->md, in, inlen);
}

int hmac_done(hmac_state *hmac, unsigned char *out, unsigned long *outlen)
{
    unsigned char *buf, *isha;
    unsigned long hashsize, i;
    int hash, err;


    /* test hash */
    hash = hmac->hash;

    /* get the hash message digest size */
    hashsize = hash_descriptor[hash].hashsize;

    /* allocate buffers */
    buf  = (unsigned char*) XMALLOC(LTC_HMAC_BLOCKSIZE);
    isha = (unsigned char*) XMALLOC(hashsize);
    if (buf == NULL || isha == NULL) {
       if (buf != NULL) {
          XFREE(buf);
       }
       if (isha != NULL) {
          XFREE(isha);
       }
       return -1;
    }

    /* Get the hash of the first HMAC vector plus the data */
    if ((err = hash_descriptor[hash].done(&hmac->md, isha)) != 0) {
       goto LBL_ERR;
    }

    /* Create the second HMAC vector vector for step (3) */
    for(i=0; i < LTC_HMAC_BLOCKSIZE; i++) {
        buf[i] = hmac->key[i] ^ 0x5C;
    }

    /* Now calculate the "outer" hash for step (5), (6), and (7) */
    if ((err = hash_descriptor[hash].init(&hmac->md)) != 0) {
       goto LBL_ERR;
    }
    if ((err = hash_descriptor[hash].process(&hmac->md, buf, LTC_HMAC_BLOCKSIZE)) != 0) {
       goto LBL_ERR;
    }
    if ((err = hash_descriptor[hash].process(&hmac->md, isha, hashsize)) != 0) {
       goto LBL_ERR;
    }
    if ((err = hash_descriptor[hash].done(&hmac->md, buf)) != 0) {
       goto LBL_ERR;
    }

    /* copy to output  */
    for (i = 0; i < hashsize && i < *outlen; i++) {
        out[i] = buf[i];
    }
    *outlen = i;

    err = 0;
LBL_ERR:
    XFREE(hmac->key);
#ifdef LTC_CLEAN_STACK
    zeromem(isha, hashsize);
    zeromem(buf,  hashsize);
    zeromem(hmac, sizeof(*hmac));
#endif

    XFREE(isha);
    XFREE(buf);

    return err;
}



int SETUP(const unsigned char *key, unsigned long keylen, int num_rounds, symmetric_key *skey)
{
    int i;
    unsigned int temp, *rk;
    unsigned int *rrk;

    if (keylen != 16 && keylen != 24 && keylen != 32) {
       return -1;
    }

    if (num_rounds != 0 && num_rounds != (10 + ((keylen/8)-2)*2)) {
       return -1;
    }

    skey->rijndael.Nr = 10 + ((keylen/8)-2)*2;

    /* setup the forward key */
    i                 = 0;
    rk                = skey->rijndael.eK;
    LOAD32H(rk[0], key     );
    LOAD32H(rk[1], key +  4);
    LOAD32H(rk[2], key +  8);
    LOAD32H(rk[3], key + 12);
    if (keylen == 16) {
        for (;;) {
            temp  = rk[3];
            rk[4] = rk[0] ^ setup_mix(temp) ^ rcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) {
               break;
            }
            rk += 4;
        }
    } else if (keylen == 24) {
        LOAD32H(rk[4], key + 16);
        LOAD32H(rk[5], key + 20);
        for (;;) {
        #ifdef _MSC_VER
            temp = skey->rijndael.eK[rk - skey->rijndael.eK + 5];
        #else
            temp = rk[5];
        #endif
            rk[ 6] = rk[ 0] ^ setup_mix(temp) ^ rcon[i];
            rk[ 7] = rk[ 1] ^ rk[ 6];
            rk[ 8] = rk[ 2] ^ rk[ 7];
            rk[ 9] = rk[ 3] ^ rk[ 8];
            if (++i == 8) {
                break;
            }
            rk[10] = rk[ 4] ^ rk[ 9];
            rk[11] = rk[ 5] ^ rk[10];
            rk += 6;
        }
    } else if (keylen == 32) {
        LOAD32H(rk[4], key + 16);
        LOAD32H(rk[5], key + 20);
        LOAD32H(rk[6], key + 24);
        LOAD32H(rk[7], key + 28);
        for (;;) {
        #ifdef _MSC_VER
            temp = skey->rijndael.eK[rk - skey->rijndael.eK + 7];
        #else
            temp = rk[7];
        #endif
            rk[ 8] = rk[ 0] ^ setup_mix(temp) ^ rcon[i];
            rk[ 9] = rk[ 1] ^ rk[ 8];
            rk[10] = rk[ 2] ^ rk[ 9];
            rk[11] = rk[ 3] ^ rk[10];
            if (++i == 7) {
                break;
            }
            temp = rk[11];
            rk[12] = rk[ 4] ^ setup_mix(RORc(temp, 8));
            rk[13] = rk[ 5] ^ rk[12];
            rk[14] = rk[ 6] ^ rk[13];
            rk[15] = rk[ 7] ^ rk[14];
            rk += 8;
        }
    } else {
       /* this can't happen */
       /* coverity[dead_error_line] */
       return -1;
    }
    /* setup the inverse key now */
    rk   = skey->rijndael.dK;
    rrk  = skey->rijndael.eK + (28 + keylen) - 4;

    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    /* copy first */
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk   = *rrk;
    rk -= 3; rrk -= 3;

    for (i = 1; i < skey->rijndael.Nr; i++) {
        rrk -= 4;
        rk  += 4;
   
        temp = rrk[0];
        rk[0] =
            Tks0[byte(temp, 3)] ^
            Tks1[byte(temp, 2)] ^
            Tks2[byte(temp, 1)] ^
            Tks3[byte(temp, 0)];
        temp = rrk[1];
        rk[1] =
            Tks0[byte(temp, 3)] ^
            Tks1[byte(temp, 2)] ^
            Tks2[byte(temp, 1)] ^
            Tks3[byte(temp, 0)];
        temp = rrk[2];
        rk[2] =
            Tks0[byte(temp, 3)] ^
            Tks1[byte(temp, 2)] ^
            Tks2[byte(temp, 1)] ^
            Tks3[byte(temp, 0)];
        temp = rrk[3];
        rk[3] =
            Tks0[byte(temp, 3)] ^
            Tks1[byte(temp, 2)] ^
            Tks2[byte(temp, 1)] ^
            Tks3[byte(temp, 0)];
    }

    /* copy last */
    rrk -= 4;
    rk  += 4;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk   = *rrk;

    return 0;
}

int ECB_ENC(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{
    unsigned int s0, s1, s2, s3, t0, t1, t2, t3, *rk;
    int Nr, r;
    Nr = skey->rijndael.Nr;
    rk = skey->rijndael.eK;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    LOAD32H(s0, pt      ); s0 ^= rk[0];
    LOAD32H(s1, pt  +  4); s1 ^= rk[1];
    LOAD32H(s2, pt  +  8); s2 ^= rk[2];
    LOAD32H(s3, pt  + 12); s3 ^= rk[3];

    /*
     * Nr - 1 full rounds:
     */
    r = Nr >> 1;
    for (;;) {
        t0 =
            Te0(byte(s0, 3)) ^
            Te1(byte(s1, 2)) ^
            Te2(byte(s2, 1)) ^
            Te3(byte(s3, 0)) ^
            rk[4];
        t1 =
            Te0(byte(s1, 3)) ^
            Te1(byte(s2, 2)) ^
            Te2(byte(s3, 1)) ^
            Te3(byte(s0, 0)) ^
            rk[5];
        t2 =
            Te0(byte(s2, 3)) ^
            Te1(byte(s3, 2)) ^
            Te2(byte(s0, 1)) ^
            Te3(byte(s1, 0)) ^
            rk[6];
        t3 =
            Te0(byte(s3, 3)) ^
            Te1(byte(s0, 2)) ^
            Te2(byte(s1, 1)) ^
            Te3(byte(s2, 0)) ^
            rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }

        s0 =
            Te0(byte(t0, 3)) ^
            Te1(byte(t1, 2)) ^
            Te2(byte(t2, 1)) ^
            Te3(byte(t3, 0)) ^
            rk[0];
        s1 =
            Te0(byte(t1, 3)) ^
            Te1(byte(t2, 2)) ^
            Te2(byte(t3, 1)) ^
            Te3(byte(t0, 0)) ^
            rk[1];
        s2 =
            Te0(byte(t2, 3)) ^
            Te1(byte(t3, 2)) ^
            Te2(byte(t0, 1)) ^
            Te3(byte(t1, 0)) ^
            rk[2];
        s3 =
            Te0(byte(t3, 3)) ^
            Te1(byte(t0, 2)) ^
            Te2(byte(t1, 1)) ^
            Te3(byte(t2, 0)) ^
            rk[3];
    }

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
        (Te4_3[byte(t0, 3)]) ^
        (Te4_2[byte(t1, 2)]) ^
        (Te4_1[byte(t2, 1)]) ^
        (Te4_0[byte(t3, 0)]) ^
        rk[0];
    STORE32H(s0, ct);
    s1 =
        (Te4_3[byte(t1, 3)]) ^
        (Te4_2[byte(t2, 2)]) ^
        (Te4_1[byte(t3, 1)]) ^
        (Te4_0[byte(t0, 0)]) ^
        rk[1];
    STORE32H(s1, ct+4);
    s2 =
        (Te4_3[byte(t2, 3)]) ^
        (Te4_2[byte(t3, 2)]) ^
        (Te4_1[byte(t0, 1)]) ^
        (Te4_0[byte(t1, 0)]) ^
        rk[2];
    STORE32H(s2, ct+8);
    s3 =
        (Te4_3[byte(t3, 3)]) ^
        (Te4_2[byte(t0, 2)]) ^
        (Te4_1[byte(t1, 1)]) ^
        (Te4_0[byte(t2, 0)]) ^
        rk[3];
    STORE32H(s3, ct+12);

    return 0;
}



int ECB_DEC(const unsigned char *ct, unsigned char *pt, symmetric_key *skey)
{
    unsigned int s0, s1, s2, s3, t0, t1, t2, t3, *rk;
    int Nr, r;


    Nr = skey->rijndael.Nr;
    rk = skey->rijndael.dK;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    LOAD32H(s0, ct      ); s0 ^= rk[0];
    LOAD32H(s1, ct  +  4); s1 ^= rk[1];
    LOAD32H(s2, ct  +  8); s2 ^= rk[2];
    LOAD32H(s3, ct  + 12); s3 ^= rk[3];

#ifdef LTC_SMALL_CODE
    for (r = 0; ; r++) {
        rk += 4;
        t0 =
            Td0(byte(s0, 3)) ^
            Td1(byte(s3, 2)) ^
            Td2(byte(s2, 1)) ^
            Td3(byte(s1, 0)) ^
            rk[0];
        t1 =
            Td0(byte(s1, 3)) ^
            Td1(byte(s0, 2)) ^
            Td2(byte(s3, 1)) ^
            Td3(byte(s2, 0)) ^
            rk[1];
        t2 =
            Td0(byte(s2, 3)) ^
            Td1(byte(s1, 2)) ^
            Td2(byte(s0, 1)) ^
            Td3(byte(s3, 0)) ^
            rk[2];
        t3 =
            Td0(byte(s3, 3)) ^
            Td1(byte(s2, 2)) ^
            Td2(byte(s1, 1)) ^
            Td3(byte(s0, 0)) ^
            rk[3];
        if (r == Nr-2) {
           break;
        }
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    rk += 4;

#else
    /*
     * Nr - 1 full rounds:
     */
    r = Nr >> 1;
    for (;;) {

        t0 =
            Td0(byte(s0, 3)) ^
            Td1(byte(s3, 2)) ^
            Td2(byte(s2, 1)) ^
            Td3(byte(s1, 0)) ^
            rk[4];
        t1 =
            Td0(byte(s1, 3)) ^
            Td1(byte(s0, 2)) ^
            Td2(byte(s3, 1)) ^
            Td3(byte(s2, 0)) ^
            rk[5];
        t2 =
            Td0(byte(s2, 3)) ^
            Td1(byte(s1, 2)) ^
            Td2(byte(s0, 1)) ^
            Td3(byte(s3, 0)) ^
            rk[6];
        t3 =
            Td0(byte(s3, 3)) ^
            Td1(byte(s2, 2)) ^
            Td2(byte(s1, 1)) ^
            Td3(byte(s0, 0)) ^
            rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }


        s0 =
            Td0(byte(t0, 3)) ^
            Td1(byte(t3, 2)) ^
            Td2(byte(t2, 1)) ^
            Td3(byte(t1, 0)) ^
            rk[0];
        s1 =
            Td0(byte(t1, 3)) ^
            Td1(byte(t0, 2)) ^
            Td2(byte(t3, 1)) ^
            Td3(byte(t2, 0)) ^
            rk[1];
        s2 =
            Td0(byte(t2, 3)) ^
            Td1(byte(t1, 2)) ^
            Td2(byte(t0, 1)) ^
            Td3(byte(t3, 0)) ^
            rk[2];
        s3 =
            Td0(byte(t3, 3)) ^
            Td1(byte(t2, 2)) ^
            Td2(byte(t1, 1)) ^
            Td3(byte(t0, 0)) ^
            rk[3];
    }
#endif

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
        (Td4[byte(t0, 3)] & 0xff000000) ^
        (Td4[byte(t3, 2)] & 0x00ff0000) ^
        (Td4[byte(t2, 1)] & 0x0000ff00) ^
        (Td4[byte(t1, 0)] & 0x000000ff) ^
        rk[0];
    STORE32H(s0, pt);
    s1 =
        (Td4[byte(t1, 3)] & 0xff000000) ^
        (Td4[byte(t0, 2)] & 0x00ff0000) ^
        (Td4[byte(t3, 1)] & 0x0000ff00) ^
        (Td4[byte(t2, 0)] & 0x000000ff) ^
        rk[1];
    STORE32H(s1, pt+4);
    s2 =
        (Td4[byte(t2, 3)] & 0xff000000) ^
        (Td4[byte(t1, 2)] & 0x00ff0000) ^
        (Td4[byte(t0, 1)] & 0x0000ff00) ^
        (Td4[byte(t3, 0)] & 0x000000ff) ^
        rk[2];
    STORE32H(s2, pt+8);
    s3 =
        (Td4[byte(t3, 3)] & 0xff000000) ^
        (Td4[byte(t2, 2)] & 0x00ff0000) ^
        (Td4[byte(t1, 1)] & 0x0000ff00) ^
        (Td4[byte(t0, 0)] & 0x000000ff) ^
        rk[3];
    STORE32H(s3, pt+12);

    return 0;
}



int cbc_start(unsigned char *IV, unsigned char *key, unsigned long keylen, int num_rounds, symmetric_CBC *cbc)
{
   int x, err;

   if ((err = SETUP(key, keylen, num_rounds, &cbc->key)) != 0) {
      return err;
   }

   cbc->blocklen = 16;
   cbc->cipher   = 0;
   for (x = 0; x < cbc->blocklen; x++) {
       cbc->IV[x] = IV[x];
   }
   return 0;
}

void setup_key(unsigned char *IV, unsigned char *key_info, unsigned long keylen, int rounds, symmetric_CBC *cipher){
	int err; 
	err = cbc_start(IV, key_info, keylen, rounds, cipher);
	if(err != 0){
		printf("Error occurred\n");
	}
}

int cbc_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CBC *cbc)
{
   int x, err;

   if (len % cbc->blocklen) {
      printf("We have a problem");
	  return -1;
   }
  
  while (len) {
	for (x = 0; x < cbc->blocklen; x++) {
	   cbc->IV[x] ^= pt[x];
	}

		 if ((err = ECB_ENC(cbc->IV, ct, &cbc->key)) != 0) {
			return err;
		 }

		 for (x = 0; x < cbc->blocklen; x++) {
			cbc->IV[x] = ct[x];
		 }
		ct  += cbc->blocklen;
		pt  += cbc->blocklen;
		len -= cbc->blocklen;
   }
   return 0;
}

int cbc_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_CBC *cbc)
{
   int x, err;
   unsigned char tmp[16];
   unsigned char tmpy;

      while (len) {

         if ((err = ECB_DEC(ct, tmp, &cbc->key)) != 0) {
            return err;
         }
		for (x = 0; x < cbc->blocklen; x++) {
		   tmpy       = tmp[x] ^ cbc->IV[x];
		   cbc->IV[x] = ct[x];
		   pt[x]      = tmpy;
		}

         ct  += cbc->blocklen;
         pt  += cbc->blocklen;
         len -= cbc->blocklen;
   }
   return 0;
}

/*
unsigned char key[25];
unsigned char IV[16];
int key_len;

void aes_create_key(int key_length)
{
	int err = sgx_read_rand((unsigned char *)&key, key_length);
	if (err != SGX_SUCCESS)
       printf("ERROR\n");
	
	err = sgx_read_rand((unsigned char *)&IV, 16);
	if (err != SGX_SUCCESS)
       printf("ERROR\n");
	
	int i;
	for(i = 0; i < key_length; i++)
	   printf("%08x \n", key[i]);
	printf("\n");
		key_len = key_length;
}
*/


unsigned char *key = NULL;
unsigned long keylen = 0;

void dump_key(unsigned char *secret, size_t len)
{
   if(len > 1)
   {
       keylen = len - 1;
       key = (unsigned char *) malloc((keylen+1) * sizeof(unsigned char));
       memset(key, '\0', keylen+1);
       memcpy(key, secret, keylen);
       printf("Enclave.cpp: user key: \n%s\n", key);
   }
   else
   {
      ;
   }
}

void gen_key(unsigned char *secretlen, size_t len)
{
   int err;
   keylen =  atoi((char *)secretlen);
   key = (unsigned char *) malloc(keylen * sizeof(unsigned char));
   err = sgx_read_rand(key, keylen);
   if (err != SGX_SUCCESS)
   {
      printf("Enclave.cpp: Error generating key\n");
   }

   int i;
   printf("Enclave.cpp: random key: 0x");
   for(i = 0; i < keylen; i++)
   {
      printf("%02x", key[i]);
   }
   printf("\n");
}

int init = 0;
//#define BUFFERSIZE 4096
#define BLOCKSIZE 16
symmetric_key ecb_key;

void encrypt_aes_ecb(unsigned char *plaintext, size_t len, unsigned char *ciphertext, size_t plen)
{
   int err;
   unsigned char current_block_plaintext[BLOCKSIZE] = {'\0'};
   unsigned char current_block_ciphertext[BLOCKSIZE] = {'\0'};
   unsigned int chunk = 0;
   unsigned int remained = len - 1;
	
   if(!init)
   {
      init = 1;
      err = SETUP(key, keylen, 0, &ecb_key);
      if(err == -1)
      {
         printf("Enclave.cpp: Error initializing aes\n");
      }
   }	

   while((chunk + BLOCKSIZE) <= (len - 1))
   {
      memset(current_block_plaintext, '\0', BLOCKSIZE);
      memset(current_block_ciphertext, '\0', BLOCKSIZE);
      memcpy(current_block_plaintext, (unsigned char *)plaintext + chunk, BLOCKSIZE);
      ECB_ENC(current_block_plaintext, current_block_ciphertext, &ecb_key);
      memcpy(ciphertext + chunk, current_block_ciphertext, BLOCKSIZE);
      remained = remained - BLOCKSIZE;
      chunk = chunk + BLOCKSIZE;
   }
   /* ZERO padding */
   if(remained != 0)
   {
      memset(current_block_plaintext, '\0', BLOCKSIZE);
      memset(current_block_ciphertext, '\0', BLOCKSIZE);
      memcpy(current_block_plaintext, (unsigned char *)plaintext + chunk, remained);
      memset((unsigned char *)current_block_plaintext + ((chunk + remained) % BLOCKSIZE), 0x00, BLOCKSIZE - remained);
      ECB_ENC(current_block_plaintext, current_block_ciphertext, &ecb_key);
      memcpy(ciphertext + chunk, current_block_ciphertext, BLOCKSIZE);
      chunk = chunk + BLOCKSIZE;
   }
/*
   printf("Enclave.cpp: aes ciphertext: ");
   for(i = 0; i < plen; i++)
   {
      if((i % 16 == 0) && i > 0)
      { 
         printf(" ");
      }
      printf("%02x", ciphertext[i]);
   }
   printf("\n");
*/
}

void decrypt_aes_ecb(unsigned char *ciphertext, size_t plen, unsigned char *plaintext, unsigned long len){
   int err;
   unsigned char current_block_plaintext[16] = {'\0'};
   unsigned char current_block_ciphertext[16] = {'\0'};
   unsigned int chunk = 0;
   unsigned int remained = len;

   while((chunk + BLOCKSIZE) <= len)
   {
      memset(current_block_plaintext, '\0', BLOCKSIZE);
      memset(current_block_ciphertext, '\0', BLOCKSIZE);
      memcpy(current_block_ciphertext, (unsigned char *)ciphertext + chunk, BLOCKSIZE);
      ECB_DEC(current_block_ciphertext, current_block_plaintext, &ecb_key);
      memcpy(plaintext + chunk, current_block_plaintext, BLOCKSIZE);
      remained = remained - BLOCKSIZE;
      chunk = chunk + BLOCKSIZE;
   }
   /* ZERO padded */
   if(remained != 0)
   {
      memset(current_block_plaintext, '\0', BLOCKSIZE);
      memset(current_block_ciphertext, '\0', BLOCKSIZE);
      memcpy(current_block_ciphertext, (unsigned char *)ciphertext + chunk, BLOCKSIZE);
      ECB_DEC(current_block_ciphertext, current_block_plaintext, &ecb_key);
      memcpy(plaintext + chunk, current_block_plaintext, remained);
      remained = remained - remained;
      chunk = chunk + BLOCKSIZE;
   }
/*
   int i = 0
   for(i = 0; i < plen; i++)
   {
      if((i % 16 == 0) && i > 0)
      { 
         printf("\n");
      }
      printf("%02x", ciphertext[i]);
   }
   printf("\n");
*/
}


unsigned char *IV = NULL;
symmetric_CBC cipher;	

void encrypt_aes_cbc(unsigned char *plaintext, size_t len, unsigned char *ciphertext, size_t plen)
{
   int i;
   int err;
   unsigned char current_block_plaintext[BLOCKSIZE] = {'\0'};
   unsigned char current_block_ciphertext[BLOCKSIZE] = {'\0'};
   unsigned int chunk = 0;
   unsigned int remained = len - 1;

   if(!init)
   {
      init = 1;
      IV = (unsigned char *) malloc(16 * sizeof(unsigned char));
      err = sgx_read_rand(IV, 16);
      if (err != SGX_SUCCESS)
      {
         printf("Enclave.cpp: Error generating key\n");
      }
      printf("Enclave.cpp: Initialization Vector: 0x");
      for(i = 0; i < 16; i++)
      {
         printf("%02x", IV[i]);
      }
      printf("\n");

      setup_key(IV, key, keylen, 0, &cipher);
   }	

   while((chunk + BLOCKSIZE) <= (len - 1))
   {
      memset(current_block_plaintext, '\0', BLOCKSIZE);
      memset(current_block_ciphertext, '\0', BLOCKSIZE);
      memcpy(current_block_plaintext, (unsigned char *)plaintext + chunk, BLOCKSIZE);
      err = cbc_encrypt(current_block_plaintext, current_block_ciphertext, BLOCKSIZE, &cipher);
      if(err != 0)
      {
         printf("Enclave.cpp: Error on creating cbc cipher\n");
         break;
      }
      memcpy(ciphertext + chunk, current_block_ciphertext, BLOCKSIZE);
      remained = remained - BLOCKSIZE;
      chunk = chunk + BLOCKSIZE;
   }
   /* ZERO padding */
   if(remained != 0)
   {
      memset(current_block_plaintext, '\0', BLOCKSIZE);
      memset(current_block_ciphertext, '\0', BLOCKSIZE);
      memcpy(current_block_plaintext, (unsigned char *)plaintext + chunk, remained);
      memset((unsigned char *)current_block_plaintext + ((chunk + remained) % BLOCKSIZE), 0x00, BLOCKSIZE - remained);
      err = cbc_encrypt(current_block_plaintext, current_block_ciphertext, BLOCKSIZE, &cipher);
      if(err != 0)
      {
         printf("Enclave.cpp: Error on creating cbc cipher\n");
      }
      memcpy(ciphertext + chunk, current_block_ciphertext, BLOCKSIZE);
      chunk = chunk + BLOCKSIZE;
   }
}

void decrypt_aes_cbc(unsigned char *ciphertext, size_t plen, unsigned char *plaintext, unsigned long len)
{

   int err;
   unsigned char current_block_plaintext[16] = {'\0'};
   unsigned char current_block_ciphertext[16] = {'\0'};
   unsigned int chunk = 0;
   unsigned int remained = len;
   if(init)
   {
      init = 0;
      setup_key(IV, key, keylen, 0, &cipher);
   }

   while((chunk + BLOCKSIZE) <= len)
   {
      memset(current_block_plaintext, '\0', BLOCKSIZE);
      memset(current_block_ciphertext, '\0', BLOCKSIZE);
      memcpy(current_block_ciphertext, (unsigned char *)ciphertext + chunk, BLOCKSIZE);
      err = cbc_decrypt(current_block_ciphertext, current_block_plaintext, BLOCKSIZE, &cipher);
      if(err != 0)
      {
         printf("Enclave.cpp: Error on creating cbc cipher\n");
         break;
      }
      memcpy(plaintext + chunk, current_block_plaintext, BLOCKSIZE);
      remained = remained - BLOCKSIZE;
      chunk = chunk + BLOCKSIZE;
   }
   /* ZERO padded */
   if(remained != 0)
   {
      memset(current_block_plaintext, '\0', BLOCKSIZE);
      memset(current_block_ciphertext, '\0', BLOCKSIZE);
      memcpy(current_block_ciphertext, (unsigned char *)ciphertext + chunk, BLOCKSIZE);
      err = cbc_decrypt(current_block_ciphertext, current_block_plaintext, BLOCKSIZE, &cipher);
      if(err != 0)
      {
         printf("Enclave.cpp: Error on creating cbc cipher\n");
      }
      memcpy(plaintext + chunk, current_block_plaintext, remained);
      remained = remained - remained;
      chunk = chunk + BLOCKSIZE;
   }
/*
   int i = 0
   for(i = 0; i < plen; i++)
   {
      if((i % 16 == 0) && i > 0)
      { 
         printf("\n");
      }
      printf("%02x", ciphertext[i]);
   }
   printf("\n");
*/

}

#define SHA256_LEN 32
hash_state state;
unsigned char sha256_out[SHA256_LEN] = {'\0'};

void gen_sha256(unsigned char *plaintext, size_t len)
{
   int err;   
   if(!init)
   {
      init = 1;
      sha256_init(&state);
   }	

   err = sha256_process(&state, plaintext, len-1);
   if(err != 0)
   {
      printf("Enclave.cpp: Error process hmac with sha256 hash!\n");
   }


   if(len < BUFFERSIZE + 1)
   {
      init = 0;
      err = sha256_done(&state, sha256_out);
      if(err == 0)
      {
         printf("Enclave.cpp: sha256 hash: ");
         int i;
         for(i = 0; i < 32; i++)
         {
            printf("%02x", sha256_out[i]);
         }
         printf("\n");
      }
      else
      {
         printf("Enclave.cpp: Error creating sha256 hash!\n");
      }
   }
}

void get_sha256(unsigned char *ciphertext, size_t len)
{
   if(len == SHA256_LEN)
   {
      memcpy(ciphertext, sha256_out, SHA256_LEN);
   }
   else
   {
      memcpy(ciphertext, "false", strlen("false") + 1);
   }
}



#define HMAC_SHA256_LEN 32
hmac_state hmac;
unsigned long hmac_sha256_len = 32;
unsigned char hmac_sha256_out[HMAC_SHA256_LEN] = {'\0'};
int hash = 0;
unsigned char keyy[6] = "hello";
unsigned long keyylen = 5;
#define KEYLEN 32

void gen_hmac_sha256(unsigned char *plaintext, size_t len)
{

   int err;   
   if(!init)
   {
      init = 1;
      XMEMCPY(&hash_descriptor[hash], &sha256_desc, sizeof(struct ltc_hash_descriptor));
      err = hmac_init(&hmac, hash, key, keylen);
      if (err != 0) 
      {
         printf("Enclave.cpp: Error initializing hmac with sha256 hash!\n");
      }
   }

   err = hmac_process(&hmac, plaintext, len-1);
   if (err != 0)
   {
      printf("Enclave.cpp: Error process hmac with sha256 hash!\n");
   }

   if(len < BUFFERSIZE + 1)
   {
      init = 0;
      err = hmac_done(&hmac, hmac_sha256_out, &hmac_sha256_len);
      if (err == 0)
      {
         printf("Enclave.cpp: hmac sha256 hash: ");
         int i;
         for(i = 0; i < 32; i++)
         {
            printf("%02x", hmac_sha256_out[i]);
         }
         printf("\n");
      }
      else
      {
         printf("Enclave.cpp: Error creating hmac sha256 hash!\n");
      }
   }
}

void get_hmac_sha256(unsigned char *ciphertext, size_t len) {
   if(len == HMAC_SHA256_LEN)
   {
      memcpy(ciphertext, hmac_sha256_out, HMAC_SHA256_LEN);
   }
   else
   {
      memcpy(ciphertext, "false", strlen("false") + 1);
   }
}

