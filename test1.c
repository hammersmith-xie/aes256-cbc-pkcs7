#include <iostream>
#include <string>
#include <string.h>
#include "aes.h"

#include "evp.h"
#include "bio.h"
#include "buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>





char * Base64Encode(const char *buffer, int length, bool newLine)
{
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    if (!newLine) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, buffer, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    BIO_set_close(b64, BIO_NOCLOSE);

    char *buff = (char *)malloc((int)bptr->length + 1);
    memcpy(buff, bptr->data, (int)bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);

    return buff;
}




void testEncrypt() {
    char encrypt_string[8192] = {0};
    AES_KEY aes;
    char key[33] = "12345678901234561234567890123456";
    char iv[33] = "00000000000000000000000000000000";
    std::string input_string = "songshiqi";
    int nLen = input_string.length();
    int nBei = nLen / AES_BLOCK_SIZE + 1;
    int nTotal = nBei * AES_BLOCK_SIZE;
    
    char * enc_s = (char *)malloc((size_t)(nTotal+1));
    memset(enc_s,'\0',nTotal+1);	
    //char enc_s[/*nTotal + 1*/4096] = "";//{0};
    int nNumber;
    if (nLen % 16 > 0)
        nNumber = nTotal - nLen;
    else
        nNumber = 16;
    memset(enc_s, nNumber, nTotal);
    memcpy(enc_s, input_string.data(), nLen);
    if (AES_set_encrypt_key((unsigned char *) key, 256, &aes) < 0) {
        free(enc_s);
	exit(-1);
    }
    AES_cbc_encrypt((unsigned char *) enc_s, (unsigned char *) encrypt_string, nBei * 16,
                    &aes,
                    (unsigned char *) iv, AES_ENCRYPT);
   char *res = Base64Encode((const char *) encrypt_string, nBei * 16,true);
    free(enc_s);
    printf("the encrypt result is %s %d\n", res,strlen(res));
}
int main()
{
	testEncrypt();
	testEncrypt();
}
