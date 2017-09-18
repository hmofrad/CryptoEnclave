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



// App.cpp : Define the entry point for the console application.
//
#include "app.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <assert.h>
#include <fstream>
#include <thread>
#include <iostream>
#include "sgx_key.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_tseal.h"
#include "rwlock.h"
#include "ErrorSupport.h"

#define ENCLAVE_NAME "libenclave.signed.so"
#define TOKEN_NAME   "Enclave.token"
//#define BUFFERSIZE   4096
#define SHA256_LEN        32
#define HMAC_SHA256_LEN   32
// Global data
sgx_enclave_id_t global_eid = 0;
sgx_launch_token_t token = {0};
rwlock_t lock_eid;
struct sealed_buf_t sealed_buf;

using namespace std;

// Ocall function
void print(const char *str)
{
    cout<<str;
}

void print_bits(unsigned char *bits, size_t len)
{
   int i;
   for(i = 0; i < len; i++)
   {
      printf("%02x", bits[i]);
   }
}

void print_blocks(unsigned char *bits, size_t len)
{
   int i;
   for(i = 0; i < len; i++)
   {
      if((i % 16 == 0) && i > 0)
      { 
         printf("\n");
      }
      printf("%02x", bits[i]);
   }
}


int main(int argc, char* argv[])
{
   (void)argc;
   (void)argv;

   int fid;
   if((argc == 5) && !strcmp(argv[1], "-a") && !strcmp(argv[2], "sha256") && !strcmp(argv[3], "-infile"))
   {
      fid = open(argv[4], O_RDONLY|O_LARGEFILE);
      if (fid == -1)
      {
         printf("USAGE: %s -a <sha256|hmac_sha256|aes_ecb|aes_cbc> [-userkey|-randomkey <key|keylen>] -intext|-infile <input>\n", argv[0]);
         return (-1);
      }
   }
   else if((argc == 5) && !strcmp(argv[1], "-a") && !strcmp(argv[2], "sha256") &&  !strcmp(argv[3], "-intext"))
   {
      ;
   }
   else if((argc == 7) && !strcmp(argv[1], "-a") &&  (!strcmp(argv[2], "hmac_sha256") || !strcmp(argv[2], "aes_ecb") || !strcmp(argv[2], "aes_cbc")) && !strcmp(argv[5], "-infile"))
   {
      fid = open(argv[6], O_RDONLY|O_LARGEFILE);
      if (fid == -1)
      {
         printf("USAGE: %s -a <sha256|hmac_sha256|aes_ecb|aes_cbc> [-userkey|-randomkey <key|keylen>] -intext|-infile <input>\n", argv[0]);
         return (-1);
      }
   }
   else if((argc == 7) && !strcmp(argv[1], "-a") && (!strcmp(argv[2], "hmac_sha256") || !strcmp(argv[2], "aes_ecb") || !strcmp(argv[2], "aes_cbc")) && !strcmp(argv[5], "-intext"))
   {
      ;
   }
   else
   {
      printf("USAGE: %s -a <sha256|hmac_sha256|aes_ecb|aes_cbc> [-userkey|-randomkey <key|keylen>] -intext|-infile <input>\n", argv[0]);
      return (-1);
   }

   int updated = 0;
   if(SGX_SUCCESS != sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL))
   {
      printf("App: error, failed to create enclave.\n");
      return (-1);
   }


   unsigned char buf[BUFFERSIZE+1] = {'\0'};
   size_t len;
   if(!strcmp(argv[2], "sha256"))
   {
      unsigned char sha256_out[SHA256_LEN] = {'\0'};
      if(!strcmp(argv[3], "-infile"))
      {
         do
         {
            len = read(fid,buf,BUFFERSIZE);
            if (len < 0 )
            {
               close (fid);
               return (-1);
            }
            gen_sha256(global_eid, buf, len + 1);
            memset(buf,'\0',sizeof(buf));
         } 
         while (len == sizeof(buf) - 1);

         if (close(fid)) 
         {
            return (-1);
         }

         get_sha256(global_eid, sha256_out, SHA256_LEN);
         printf("    App.cpp: sha256 hash: ");
         print_bits(sha256_out, 32);
         printf("\n");
      }

      else if(!strcmp(argv[3], "-intext"))
      {
         len = strlen(argv[4]);
         if(len < BUFFERSIZE)
         {
            gen_sha256(global_eid, (unsigned char *) argv[4], len + 1);
            get_sha256(global_eid, sha256_out, SHA256_LEN);
            printf("    App.cpp: sha256 hash: ");
            print_bits(sha256_out, 32);
            printf("\n");
         }
         else
         {
            printf("We do not support string literals more than %d\n", BUFFERSIZE);
            return(-1);
         }
      }
      else
      {
         printf("USAGE: %s -a <sha256|hmac_sha256|aes_ecb|aes_cbc> [-userkey|-randomkey <key|keylen>] -intext|-infile <input>\n", argv[0]);
         return (-1);
      }
   }

   if(!strcmp(argv[2], "hmac_sha256"))
   {
      unsigned char hmac_sha256_out[HMAC_SHA256_LEN] = {'\0'};
      if(!strcmp(argv[5], "-infile"))
      {
         if(!strcmp(argv[3], "-userkey"))
         {
            if(!strlen(argv[4]))
            {
               printf("We do not support empty secrets\n");    
               return(-1);
            } 
            dump_key(global_eid, (unsigned char *)argv[4], strlen(argv[4]) + 1);
            printf("    App.cpp: hmac sha256 hash  key: %s\n", argv[4] );
         }
	 else if(!strcmp(argv[3], "-randomkey"))
         {
            gen_key(global_eid, (unsigned char *)argv[4], strlen(argv[4]) + 1);
         }
         else
         {
            printf("USAGE: %s -a <sha256|hmac_sha256|aes_ecb|aes_cbc> [-userkey|-randomkey <key|keylen>] -intext|-infile <input>\n", argv[0]);
            return (-1);
         }
         do
         {
            len = read(fid, buf, BUFFERSIZE);
            if (len < 0 )
            {
               close (fid);
               return (-1);
            }
            gen_hmac_sha256(global_eid, buf, len + 1);
            memset(buf,'\0',sizeof(buf));
         }
         while (len == sizeof(buf) - 1);

         if (close(fid)) 
         {
            return (-1);
         }

         get_hmac_sha256(global_eid, hmac_sha256_out, HMAC_SHA256_LEN);
         printf("    App.cpp: hmac sha256 hash: ");
         print_bits(hmac_sha256_out, 32);
         printf("\n");
      }
      else if(!strcmp(argv[5], "-intext"))
      {
         if(!strcmp(argv[3], "-userkey"))
         {
            if(!strlen(argv[4]))
            {
               printf("We do not support empty secrets\n");    
               return(-1);
            } 
            dump_key(global_eid, (unsigned char *)argv[4], strlen(argv[4]) + 1);
            printf("    App.cpp: hmac sha256 hash  key: %s\n", argv[4] );
         }
	 else if(!strcmp(argv[3], "-randomkey"))
         {
            gen_key(global_eid, (unsigned char *)argv[4], strlen(argv[4]) + 1);
         }
         else
         {
            printf("USAGE: %s -a <sha256|hmac_sha256|aes_ecb|aes_cbc> [-userkey|-randomkey <key|keylen>] -intext|-infile <input>\n", argv[0]);
            return (-1);
         }
         len = strlen(argv[6]);
         if(len < BUFFERSIZE)
         {
            gen_hmac_sha256(global_eid, (unsigned char *) argv[6], len + 1);
            get_hmac_sha256(global_eid, hmac_sha256_out, HMAC_SHA256_LEN);
            printf("    App.cpp: hmac sha256 hash: ");
            print_bits(hmac_sha256_out, 32);
            printf("\n");
         }
         else
         {
            printf("We do not support string literals more than %d\n", BUFFERSIZE);
            return(-1);
         }
      }
      else
      {
         printf("USAGE: %s -a <sha256|hmac_sha256|aes_ecb|aes_cbc> [-userkey|-randomkey <key|keylen>] -intext|-infile <input>\n", argv[0]);
         return (-1);
      }
   }

   size_t plen = len;
   size_t n = -1;
   size_t m = -1;
   unsigned char *plaintext = NULL;
   unsigned char *ciphertext = NULL;
   if(!strcmp(argv[2], "aes_ecb"))
   {
      if(!strcmp(argv[3], "-randomkey") && ((atoi(argv[4]) == 16) || (atoi(argv[4]) == 24) || (atoi(argv[4]) == 32) ) )
      {
         gen_key(global_eid, (unsigned char *)argv[4], strlen(argv[4]) + 1);
      }
      else
      {
         printf("We only support 16, 24, and 32 bytes keys\n");
         return (-1);
      }
      if(!strcmp(argv[5], "-infile"))
      {
         do
         {
            len = read(fid, buf, BUFFERSIZE);
            if (len < 0)
            {
               close (fid);
               return (-1);
            }
            plen = len;
            if(plen % 16 != 0)
            {
               plen = plen + (16 - (plen % 16));
            }
            n++;
            ciphertext = (unsigned char *) realloc(ciphertext, ((n * BUFFERSIZE) + plen) * sizeof(unsigned char));
            encrypt_aes_ecb(global_eid, (unsigned char *) buf, len + 1, (unsigned char *)ciphertext + (n * BUFFERSIZE), plen);
            memset(buf,'\0',sizeof(buf));
         }
         while (len == sizeof(buf) - 1);

         if (close(fid)) 
         {
            return (-1);
         }
         printf("    App.cpp: aes ecb ciphertext: \n");
         //print_blocks(ciphertext, (n * BUFFERSIZE) + plen);
         printf("\n");

         plaintext = (unsigned char *) malloc((((n*BUFFERSIZE) + len) + 1) * sizeof(unsigned char));
         memset(plaintext,'\0',(n*BUFFERSIZE) + len + 1);
         do
         {
            m++;
            decrypt_aes_ecb(global_eid, (unsigned char *)ciphertext + (m * BUFFERSIZE), BUFFERSIZE + 1, (unsigned char *)plaintext + (m * BUFFERSIZE), BUFFERSIZE);
         } while(m < n - 1);
         m++;
         decrypt_aes_ecb(global_eid, (unsigned char *)ciphertext + (m * BUFFERSIZE),  plen + 1, (unsigned char *)plaintext + (m * BUFFERSIZE), len);
         printf("%s\n", plaintext);

      }
      else if(!strcmp(argv[5], "-intext"))
      {
         len = strlen(argv[6]);
         plen = len;
         if(plen % 16 != 0)
         {
           plen = plen + (16 - (plen % 16));
         }
         if(len < BUFFERSIZE)
         {
            plaintext = (unsigned char *) malloc((len + 1) * sizeof(unsigned char));
            memset(plaintext, '\0', len+1);
            ciphertext = (unsigned char *) malloc(plen * sizeof(unsigned char));
            memset(ciphertext, '\0', plen);
            encrypt_aes_ecb(global_eid, (unsigned char *) argv[6], len + 1, ciphertext, plen);
            printf("    App.cpp: aes ecb ciphertext: \n");
            print_blocks(ciphertext, plen);
            printf("\n");
            decrypt_aes_ecb(global_eid, ciphertext, plen + 1, plaintext, len);
            printf("    App.cpp: aes ecb plaintext: \n");
            printf("%s\n", plaintext);
         }
         else
         {
            printf("We do not support string literals more than %d\n", BUFFERSIZE);
            return(-1);
         }
      }
      else
      {
         printf("USAGE: %s -a <sha256|hmac_sha256|aes_ecb|aes_cbc> [-userkey|-randomkey <key|keylen>] -intext|-infile <input>\n", argv[0]);
         return (-1);
      }

   }
   if(!strcmp(argv[2], "aes_cbc"))
   {
      if(!strcmp(argv[3], "-randomkey") && ((atoi(argv[4]) == 16) || (atoi(argv[4]) == 24) || (atoi(argv[4]) == 32)))
      {
         gen_key(global_eid, (unsigned char *)argv[4], strlen(argv[4]) + 1);
      }
      else if(!strcmp(argv[3], "-userkey") && ((strlen(argv[4]) == 16) || (strlen(argv[4]) == 24) || (strlen(argv[4]) == 32)))
      {
         if(!strlen(argv[4]))
         {
            printf("We do not support empty secrets\n");    
            return(-1);
         } 
         dump_key(global_eid, (unsigned char *)argv[4], strlen(argv[4]) + 1);
         printf("    App.cpp: hmac sha256 hash  key: %s\n", argv[4] );
      }
      else
      {
         printf("We only support 16, 24, and 32 bytes keys\n");
         return (-1);
      }
      if(!strcmp(argv[5], "-infile"))
      {
         do
         {
            len = read(fid, buf, BUFFERSIZE);
            if (len < 0 )
            {
               close (fid);
               return (-1);
            }
            plen = len;
            if(plen % 16 != 0)
            {
               plen = plen + (16 - (plen % 16));
            }
            n++;
            ciphertext = (unsigned char *) realloc(ciphertext, ((n * BUFFERSIZE) + plen) * sizeof(unsigned char));
            encrypt_aes_cbc(global_eid, (unsigned char *) buf, len + 1, (unsigned char *)ciphertext + (n * BUFFERSIZE), plen);
            memset(buf,'\0',sizeof(buf));
         }
         while (len == sizeof(buf) - 1);

         if (close(fid)) 
         {
            return (-1);
         }
         printf("    App.cpp: aes cbc ciphertext: \n");
         //print_blocks(ciphertext, (n * BUFFERSIZE) + plen);
         printf("\n");

         plaintext = (unsigned char *) malloc((((n*BUFFERSIZE) + len) + 1) * sizeof(unsigned char));
         memset(plaintext,'\0',(n*BUFFERSIZE) + len + 1);
         do
         {
            m++;
            decrypt_aes_cbc(global_eid, (unsigned char *)ciphertext + (m * BUFFERSIZE), BUFFERSIZE + 1, (unsigned char *)plaintext + (m * BUFFERSIZE), BUFFERSIZE);
         } while(m < n - 1);
         m++;
         decrypt_aes_cbc(global_eid, (unsigned char *)ciphertext + (m * BUFFERSIZE),  plen + 1, (unsigned char *)plaintext + (m * BUFFERSIZE), len);
//         printf("%s\n", plaintext);

         
      }
      else if(!strcmp(argv[5], "-intext"))
      {
         len = strlen(argv[6]);
         plen = len;
         if(plen % 16 != 0)
         {
           plen = plen + (16 - (plen % 16));
         }
         if(len < BUFFERSIZE)
         {
            plaintext = (unsigned char *) malloc((len + 1) * sizeof(unsigned char));
            memset(plaintext, '\0', len+1);
            ciphertext = (unsigned char *) malloc(plen * sizeof(unsigned char));
            memset(ciphertext, '\0', plen);
            encrypt_aes_cbc(global_eid, (unsigned char *) argv[6], len + 1, ciphertext, plen);
            printf("    App.cpp: aes cbc ciphertext: \n");
            print_blocks(ciphertext, plen);
            printf("\n");
            decrypt_aes_cbc(global_eid, ciphertext, plen + 1, plaintext, len);
            printf("    App.cpp: aes cbc plaintext: \n");
            printf("%s\n", plaintext);
         }
         else
         {
            printf("We do not support string literals more than %d\n", BUFFERSIZE);
            return(-1);
         }
      }
      else
      {
         printf("USAGE: %s -a <sha256|hmac_sha256|aes_ecb|aes_cbc> [-userkey|-randomkey <key|keylen>] -intext|-infile <input>\n", argv[0]);
         return (-1);
      }
   }
  
    if(SGX_SUCCESS != sgx_destroy_enclave(global_eid))
    {
        printf("App: error, failed to destroy enclave.\n");
    }    

    return (0);
}

