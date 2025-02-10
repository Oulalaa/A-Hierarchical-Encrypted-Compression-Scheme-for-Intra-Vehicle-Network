#ifndef UTIL_H
#define UTIL_H
#include <Arduino.h>
#define START_TIME(x) x = micros()
#define END_TIME(x) x = micros() - x


void printDuration(char * title, long duration);
void printDurationMS(char * title, long duration);
bool ByteCmp(const uint8_t* buf1, const uint8_t* buf2, size_t length);
void ByteCopy(uint8_t data[],int dataLen,uint8_t out[]);
void PrintBuffer(unsigned char *buffer, int n);
int ASCONEncrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *out, int &outLen);
int ASCONDecrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *out, int &outLen);
int Xor(unsigned char *data, int dataLen, unsigned char *key, unsigned char *out);
int Hash(unsigned char *data, int dataLen, unsigned char* out,int &outLen);
int Mac(unsigned char *data, int dataLen, unsigned char *key,unsigned char *out, int &outLen);
int Kdf(unsigned char *data, int dataLen,int outLen, unsigned char* out);
int KdfXor(unsigned char *data, int dataLen, unsigned char* out,int &outLen);
#endif // UTIL_H