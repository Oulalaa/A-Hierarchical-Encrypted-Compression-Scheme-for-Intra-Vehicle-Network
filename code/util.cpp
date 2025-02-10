#include <Arduino.h>
#include <ASCON.h>
#include "aead/ascon-aead-common.h"
#include "core/ascon-util-snp.h"
#include <string.h>
#include "util.h"

void printDuration(char * title, long duration){
    Serial.print(title);
    Serial.print(" duration: ");
    Serial.print(duration);
    Serial.println(" us");
}
void printDurationMS(char * title, long duration){
    Serial.print(title);
    Serial.print(duration*1.0/1000);
    Serial.println(" ms");
}
bool ByteCmp(const uint8_t* buf1, const uint8_t* buf2, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        if (buf1[i] != buf2[i]) {
            return false; // 如果发现不相等的元素，则返回false
        }
    }
    return true; // 所有元素都相等
}
void ByteCopy(uint8_t data[], int dataLen, uint8_t out[])
{  
    for(int i = 0; i < dataLen; i++){
        out[i] = data[i];
    }
}
void PrintBuffer(unsigned char *buffer, int n){
  for(int i = 0; i < n; i++){
    Serial.print("0x");
    if(buffer[i] < 16) {
      Serial.print("0"); // 如果小于0x10，添加一个前导0
    }
    Serial.print(buffer[i], HEX); // 以十六进制形式打印
    if (i < n-1) {
      Serial.print(","); // 除了最后一个数，每个数后面都打印逗号
    }
  }
  Serial.println(); // 每打印完一行后换行
}


void ascon128_aead_encrypt2
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *k)
{
    ascon_state_t state;
    /* Set the length of the returned ciphertext */
    *clen = mlen;

    /* Initialize the ASCON state */
    ascon_init(&state);
    ascon_overwrite_bytes(&state, k, 8, ASCON128_KEY_SIZE);
    ascon_permute(&state, 0);
    // 加密数据
    size_t offset = 0;
    while (offset < mlen) {
        size_t blockLen = min(mlen - offset, 8);
        ascon_encrypt_partial(&state, c + offset, m + offset, 0, blockLen);
        offset += blockLen;
        // 对于完整的8字节块，执行置换
        if (blockLen == 8) {
            ascon_permute(&state, 6);
        }
    }
    ascon_free(&state);
}

void ascon128_aead_decrypt2
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *k)
{
    ascon_state_t state;
    *mlen = clen;
    /* Initialize the ASCON state */
    ascon_init(&state);
    ascon_overwrite_bytes(&state, k, 8, ASCON128_KEY_SIZE);
    ascon_permute(&state, 0);
    // 解密数据
    size_t offset = 0;
    while (offset < clen) {
        size_t blockLen = min(clen - offset, 8);
        ascon_decrypt_partial(&state, m + offset, c + offset, 0, blockLen);
        offset += blockLen;
        
        // 对于完整的8字节块，执行置换
        if (blockLen == 8) {
            ascon_permute(&state, 6);
        }
    }
    ascon_free(&state);
}

int ASCONEncrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *out, int &outLen){
    size_t len;
    
    if(dataLen%8==0){
        ascon128_aead_encrypt2(out,&len,data,dataLen,key);
        outLen = len;
        return 0;
    }
    size_t pLen = dataLen + 8 - dataLen%8;
    unsigned char *p = new unsigned char[pLen]();
    ByteCopy(data,dataLen,p);
    ascon128_aead_encrypt2(out,&len,p,pLen,key);
    outLen = len;
    delete[] p;
    return 0;
}
int ASCONDecrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *out, int &outLen){
    size_t len;
    ascon128_aead_decrypt2(out,&len,data,dataLen,key);
    outLen = len;
    return 0;
}

int Xor(unsigned char *data, int dataLen, unsigned char *key,  unsigned char *out)
{
    for(int i = 0; i < dataLen; i++){
        out[i] = data[i] ^ key[i];
    }
    return 0;
}


int Hash(unsigned char *data, int dataLen, unsigned char *out, int &outLen)
{
    ascon_hash(out,data,dataLen);
    outLen = ASCON_HASH_SIZE;
    return 0;
}

int Mac(unsigned char *data, int dataLen, unsigned char *key, unsigned char *out, int &outLen)
{
    ascon_mac(out,data,dataLen,key);
    outLen = ASCON_PRF_TAG_SIZE;
    return 0;
}

int Kdf(unsigned char *data, int dataLen, int outLen, unsigned char *out)
{
    ascon_pbkdf2(out,outLen,data,dataLen,0,0,0);
    return 0;
}

int KdfXor(unsigned char *data, int dataLen, unsigned char *out, int &outLen)
{
    Hash(data,dataLen,out,outLen);
    return 0;
}
