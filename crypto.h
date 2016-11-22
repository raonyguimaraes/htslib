/* The MIT License

   Copyright (C) 2016 Genome Research Ltd

   Authors: Petr Danecek

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
*/

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <config.h>
#if USE_CRYPTO

#include <stdio.h>
#include <stdint.h>

#define USE_OPENSSL 1
#define CRYPTO_SHA2_LEN 64
#define CRYPTO_IV_LEN 16

typedef struct
{
    uint8_t active;      // is the encoding/decoding mode turned on?
    char hashed_key[64]; // SHA-2 encoded key
    int attach_key;      // create 1:DC block or 0:EC block
    uint8_t key[32];     // active key
    uint8_t ivec[16];    // initialization vector
    void *lib;           // library of keys, khash mapping from hash to key
    uint8_t *buf;        // ?can openssl be made to encrypt inplace?
    int mbuf;
}
crypto_t;

int crypto_init(crypto_t *crypto, char mode);
void crypto_destroy(crypto_t *crypto);

int crypto_set_key(crypto_t *crypto, const char *hashed_key);
int crypto_set_ivec(crypto_t *crypto, const uint8_t *ivec);

int encrypt_buffer(crypto_t *aes, uint64_t offset, uint8_t *buffer, int length);
int decrypt_buffer(crypto_t *aes, uint64_t offset, uint8_t *buffer, int length);

#endif
#endif
