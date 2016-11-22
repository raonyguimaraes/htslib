/* The MIT License

   Copyright (C) 2016 Genome Research Ltd

   Authors: Petr Danecek, Tomas Hromada

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

#include "crypto.h"
#if USE_CRYPTO
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include "htslib/hts.h"
#include "htslib/kseq.h"
#include "htslib/khash.h"

#define HASHED_KEY_LEN 64

KHASH_MAP_INIT_STR(str2str, const char*)
KSTREAM_INIT2(static,int,read,65536)

static uint8_t hex8(const char *str)
{
    uint8_t a = str[0] <= '9' ? str[0] - '0' : str[0] - 'A' + 10;
    uint8_t b = str[1] <= '9' ? str[1] - '0' : str[1] - 'A' + 10;
    return (a << 4) | b;
}
static int _crypto_init_lib(crypto_t *crypto, kstring_t *str, const char *hts_key)
{
    int fd = open(hts_key,O_RDONLY);
    if ( fd<0 ) return -1;

    khint_t k;
    int ret, i, iline = 0;
    kstream_t *ks;

    str->l = 0;
    ks = ks_init(fd);
    while (ks_getuntil(ks, KS_SEP_LINE, str, &ret) >= 0) 
    {
        iline++;
        if ( str->s[0] == '#' ) continue;   // comment line
        if ( str->l != 2*HASHED_KEY_LEN + 1 || (str->s[64]!='\t' && str->s[HASHED_KEY_LEN]!=' ') )
        {
            fprintf(stderr,"Could not parse %d-th line in %s\n", iline, hts_key);
            exit(1);
        }
        str->s[HASHED_KEY_LEN] = 0;

        uint8_t *key = (uint8_t*) malloc(sizeof(crypto->key));
        for (i=0; i<sizeof(crypto->key); i++) key[i] = hex8(str->s + HASHED_KEY_LEN + 1 + 2*i);

        khash_t(str2str) *lib = (khash_t(str2str)*)crypto->lib;
        k = kh_put(str2str, lib, strdup(str->s), &ret);
        kh_val(lib, k) = (char*) key;
    }
    ks_destroy(ks);

    close(fd);
    return 0;
}

int crypto_set_key(crypto_t *crypto, const char *hashed_key)
{
    khash_t(str2str) *lib = (khash_t(str2str)*) crypto->lib;
    khint_t k = kh_get(str2str, lib, hashed_key);
    if ( k == kh_end(lib) ) return -1;
    memcpy(crypto->key, kh_val(lib,k), sizeof(crypto->key));
    memcpy(crypto->hashed_key, kh_key(lib,k), CRYPTO_SHA2_LEN);
    return 0;
}

int crypto_set_ivec(crypto_t *crypto, const uint8_t *ivec)
{
    memcpy(crypto->ivec, ivec, sizeof(crypto->ivec));
    return 0;
}

int crypto_init(crypto_t *crypto, char mode)
{
    memset(crypto, 0, sizeof(crypto_t));
    kstring_t str = {0,0,0};
    char *path = getenv("HTS_KEYS");
    if ( !path ) return -1;
    if ( !crypto->lib ) crypto->lib = kh_init(str2str);
    int beg = 0, end;
    while (1)
    {
        end = beg;
        while ( path[end] && path[end]!=':' ) end++;
        char tmp = path[end]; path[end] = 0;
        if ( _crypto_init_lib(crypto, &str, path)==0 ) break;
        if ( !tmp ) return -1;
        path[end] = tmp;
    }
    free(str.s);
    if ( mode=='w' )
    {   
        path = getenv("HTS_ENC");
        if ( !path ) return 0;
        if ( crypto_set_key(crypto, path)!=0 ) 
        {
            fprintf(stderr,"The key %s not found\n", path);
            return -1;
        }
        srandom(time(NULL));
        int i = 0;
        while ( i<16 ) crypto->ivec[i++] = random() % 255;
        crypto->attach_key = 1;
    }
    crypto->active = 1;
    return 0;
}
void crypto_destroy(crypto_t *crypto)
{
    if ( !crypto ) return;
    free(crypto->buf);
    khash_t(str2str) *lib = (khash_t(str2str)*)crypto->lib;
    if ( lib )
    {
        khint_t k;
        for (k = 0; k < kh_end(lib); k++)
        {
            if ( !kh_exist(lib, k)) continue;
            free((char*)kh_key(lib, k));
            free((char*)kh_val(lib, k));
        }
        kh_destroy(str2str, lib);
    }
}

#if USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

static inline void openssl_handle_errors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
static inline int openssl_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;
    if (!(ctx = EVP_CIPHER_CTX_new())) openssl_handle_errors();
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) openssl_handle_errors();
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) openssl_handle_errors();
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) openssl_handle_errors();
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len - plaintext_len;
}
static inline int openssl_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len, plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) openssl_handle_errors();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) openssl_handle_errors();
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) openssl_handle_errors();
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) openssl_handle_errors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len - plaintext_len;
}

// uint64_t offset, uint8_t ivec[16]
static inline void set_iv(crypto_t *crypto, uint8_t *offset, uint8_t *ivec)
{
    int i;
    memcpy(ivec, crypto->ivec, 16);
    if ( ed_is_big() )
        for (i=0; i<8; i++) ivec[i] ^= offset[8-i-1];
    else
        for (i=0; i<8; i++) ivec[i] ^= offset[i];
}

int encrypt_buffer(crypto_t *crypto, uint64_t offset, uint8_t *buffer, int plaintext_len)
{
    int len, ciphertext_len;
    uint8_t ivec[16];
    hts_expand(uint8_t, plaintext_len + 16, crypto->mbuf, crypto->buf);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if ( !ctx ) openssl_handle_errors();
    set_iv(crypto, (uint8_t*)&offset, (uint8_t*)ivec);
    if ( EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, crypto->key, ivec) != 1 ) openssl_handle_errors();
    if ( EVP_EncryptUpdate(ctx, crypto->buf, &len, buffer, plaintext_len) != 1 ) openssl_handle_errors();
    ciphertext_len = len;
    if ( EVP_EncryptFinal_ex(ctx, crypto->buf + len, &len) != 1 ) openssl_handle_errors();
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    int aes_padding = ciphertext_len - plaintext_len;
    memcpy(buffer, crypto->buf, plaintext_len + aes_padding);
    return aes_padding;
}

// This can generate valgrind's uninitialized memory warnings. Apparently
// openssl increases entropy this way, the data should be ok though.
int decrypt_buffer(crypto_t *crypto, uint64_t offset, uint8_t *buffer, int ciphertext_len)
{
    int len, plaintext_len;
    uint8_t ivec[16];
    hts_expand(uint8_t, ciphertext_len, crypto->mbuf, crypto->buf);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if ( !ctx ) openssl_handle_errors();
    set_iv(crypto, (uint8_t*)&offset, (uint8_t*)ivec);
    if ( EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, crypto->key, ivec) != 1 ) openssl_handle_errors();
    if ( EVP_DecryptUpdate(ctx, crypto->buf, &len, buffer, ciphertext_len) != 1 ) openssl_handle_errors();
    plaintext_len = len;
    if ( EVP_DecryptFinal_ex(ctx, crypto->buf + len, &len) != 1 ) openssl_handle_errors();
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    int aes_padding =  ciphertext_len - plaintext_len;
    memcpy(buffer, crypto->buf, ciphertext_len - aes_padding);
    return aes_padding;
}
#endif // USE_OPENSSL
#endif // USE_CRYPTO
