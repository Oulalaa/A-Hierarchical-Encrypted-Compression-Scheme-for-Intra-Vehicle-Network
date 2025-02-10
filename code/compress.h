#ifndef COMPRESS_H
#define COMPRESS_H
#include <Arduino.h>
#define G 4
#define GN (64/G)
#define SIGN (16/G)
#define FILLONE ((G) == 1 ? 0x01U : (G) == 2 ? 0x03U : (G) == 4 ? 0x0FU : 0xFFU)

typedef uint64_t MSG;
typedef uint16_t SIG[4];
typedef uint16_t *PSIG[4];


// unsigned char max(unsigned char x, unsigned char y);

// unsigned char min(unsigned char x, unsigned char y);
// 交换两个元素的函数
void swap(unsigned char* a, unsigned char* b);
// 输出char数组
// void PrintHex(unsigned char* buffer,int n);
// 输出MSG
// void PrintMSG(MSG msg) ;

int LenMSG(MSG msg);
// msg转char数组
int MSG2Buffer(MSG msg,unsigned char* buffer);
// char数组转msg
int Buffer2MSG(unsigned char* buffer, int n, MSG &msg);
// 统计1的个数
int CountBits(unsigned int n); 
// 获取数据宽度
int GetWidth(unsigned char x);
// 获取数据宽度
int GetWidth(uint16_t x);
class COMPRESSER {
private:
    unsigned char GTable[GN];
    int Cnt[GN]={0},Wid[GN]={0};
    MSG CurMsg = 0;
    SIG Sig = {0};
    int Mj = 0;
    int partition(int low, int high);
    void putG2Sig(int pos,unsigned char g);
    unsigned char getGFromSig(unsigned char pos);
    void QuickSort(int low=0, int high=GN-1);
    int SenderSeqConfi(MSG msg);
    int RecverSeqConfi();
    int compress_raw(MSG &msg);
    int uncompress_raw(MSG msg);
    void updateMj();
public:
    COMPRESSER();
    ~COMPRESSER();
    void InsertMsg(MSG msg);
    void InsertMsg(unsigned char data[], int dataLen);
    int Compress(unsigned char data[], int dataLen,unsigned char out[], int& outLen);
    int Compress(MSG data,MSG& out);
    int Uncompress(unsigned char data[], int dataLen,unsigned char out[], int& outLen);
    int Uncompress(MSG data,MSG& out);
};
#endif // COMPRESS_H