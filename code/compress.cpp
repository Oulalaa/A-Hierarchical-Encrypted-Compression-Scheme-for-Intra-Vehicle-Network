
#include "compress.h"

#define max(a,b) ((a)>(b)?(a):(b))
#define min(a,b) ((a)<(b)?(a):(b))
// unsigned char max(unsigned char x, unsigned char y){
//     if(x > y) {
//         return x;
//     }
//     return y;
// }
// unsigned char min(unsigned char x, unsigned char y){
//     if(x < y) {
//         return x;
//     }
//     return y;
// }
// 交换两个元素的函数
void swap(unsigned char* a, unsigned char* b) {
    int t = *a;
    *a = *b;
    *b = t;
}

// 输出char数组
// void PrintHex(unsigned char* buffer,int n) {
//     for(int i = 0; i < n; i++){
//         printf("0x%02x%c",buffer[i],i==n-1?'\n':',');
//     }
// }
// 输出MSG
// void PrintMSG(MSG msg) {
//     printf("0x%016llx\n",msg);
// }
int LenMSG(MSG msg){
    int len = 0;
    while (msg) {
        msg >>= 8;
        len++;
    }
    return len;
}
// msg转char数组
int MSG2Buffer(MSG msg,unsigned char* buffer){
    int len = 0;
    while (msg) {
        buffer[len++] = msg & 0xff;
        msg >>= 8;
    }
    return len;
}
// char数组转msg
int Buffer2MSG(unsigned char* buffer, int n, MSG &msg){
    msg = 0;
    for(int i = n-1; i >= 0; i--){
        msg =(msg<<8)|buffer[i];
    }
    return 0;
}
// 统计1的个数
int CountBits(unsigned int n) {
    int count = 0;
    while (n) {
        n &= (n - 1); // 把最低位的1变成0
        count++;
    }
    return count;
}

// 获取数据宽度
int GetWidth(unsigned char x) {
    if (x == 0) return 0;
    if (x <= 0x1) return 1;
    if (x <= 0x3) return 2;
    if (x <= 0x7) return 3;
    if (x <= 0xF) return 4;
    if (x <= 0x1F) return 5;
    if (x <= 0x3F) return 6;
    if (x <= 0x7F) return 7;
    return 8; // 对于unsigned char来说，最大宽度为8
}
int GetWidth(uint16_t x) {
    if (x == 0) return 0; 
    int width = 1; // 初始化为1，因为x至少是1位
    if (x >= 0x100) {
        width += 8;
        x >>= 8;
    }
    if (x >= 0x10) {
        width += 4;
        x >>= 4;
    }
    if (x >= 0x4) {
        width += 2;
        x >>= 2;
    }
    if (x >= 0x2) {
        width += 1;
    }
    return width;
}

COMPRESSER::~COMPRESSER(){

}
COMPRESSER::COMPRESSER()
{
    Mj = 0;
    for(int i = 0; i < GN; i++) {
        this->GTable[i] = i;
        //this->Cnt[i] = i;
        //this->Wid[i] = i;
    }
}

void COMPRESSER::updateMj()
{
    if(Mj>=100) {
        this->QuickSort(0,GN-1);
        for(int i = 0; i < GN; i++) {
            this->Cnt[i] = 0;
            this->Wid[i] = 0;
        }
        Mj = 0;
    }
    Mj++;
}

void COMPRESSER::InsertMsg(MSG msg)
{
    MSG xorMsg = msg ^ this->CurMsg;
    for(int i = 0; i < GN; i++) {
        unsigned char g = xorMsg & FILLONE;
        this->Cnt[i] += (g!=0);
        this->Wid[i] += GetWidth(g);
        xorMsg >>= G;
    }
    this->CurMsg = msg;
    updateMj();
}
void COMPRESSER::InsertMsg(unsigned char data[], int dataLen)
{
    MSG msg=0;
    Buffer2MSG(data,dataLen,msg);
    this->InsertMsg(msg);
}

int COMPRESSER::Compress(unsigned char data[], int dataLen, unsigned char out[], int &outLen)
{
    MSG msg = 0;
    if(Buffer2MSG(data,dataLen,msg)<0){
        return -1;
    } 
    SenderSeqConfi(msg);
    compress_raw(msg);
    outLen = MSG2Buffer(msg,out);
    return 0;
}

int COMPRESSER::Compress(MSG data, MSG &out)
{
    SenderSeqConfi(data);
    if(compress_raw(out)<0){
        return -1;
    }
    return LenMSG(out);
}

int COMPRESSER::Uncompress(unsigned char data[], int dataLen, unsigned char out[], int &outLen)
{
    MSG msg=0;
    Buffer2MSG(data, dataLen, msg);
    uncompress_raw(msg);
    RecverSeqConfi();
    outLen = MSG2Buffer(CurMsg,out);
    return 0;
}

int COMPRESSER::Uncompress(MSG data, MSG &out)
{
    uncompress_raw(data);
    RecverSeqConfi();
    out = CurMsg;
    return 0;
}


// 快速排序函数
void COMPRESSER::QuickSort(int low, int high) {
    if (low < high) {
        int pi = partition(low, high);
        QuickSort(low, pi - 1);
        QuickSort(pi + 1, high);
    }
}

// 分区函数
int COMPRESSER::partition(int low, int high) {
    // 基准值
    int pivotCnt = this->Cnt[this->GTable[high]];
    int pivotWid = this->Wid[this->GTable[high]];
    int i = (low - 1); 

    for (int j = low; j <= high - 1; j++) {
        if(this->Cnt[this->GTable[j]] == pivotCnt){
            if(this->Wid[this->GTable[j]] >= pivotWid){
                i++; 
                swap(&this->GTable[i], &this->GTable[j]);
            }
        }else if (this->Cnt[this->GTable[j]] >= pivotCnt) {
            i++; 
            swap(&this->GTable[i], &this->GTable[j]);
        }
        // if (this->Cnt[this->GTable[j]] >= pivotCnt) {
        //     i++; 
        //     swap(&this->GTable[i], &this->GTable[j]);
        // }
    }
    swap(&this->GTable[i + 1], &this->GTable[high]);
    return (i + 1);
}
void COMPRESSER::putG2Sig(int pos,unsigned char g){
    unsigned char x = pos%4;
    unsigned char y = pos/4;
    Sig[x] |= ((uint16_t)g << (G*y));
}
unsigned char COMPRESSER::getGFromSig(unsigned char pos){
    unsigned char x = pos%4;
    unsigned char y = pos/4;
    return (Sig[x]>>(G*y))&FILLONE;
}
int COMPRESSER::SenderSeqConfi(MSG msg)
{
    MSG xorMsg = msg ^ this->CurMsg;
    Sig[0]=Sig[1]=Sig[2]=Sig[3]=0;
    for(int i = 0; i < GN; i++) {
        unsigned char g = xorMsg & FILLONE;
        Cnt[i] += (g!=0);
        Wid[i] += GetWidth(g);
        putG2Sig(this->GTable[i],g);
        xorMsg >>= G;
    }
    this->CurMsg = msg;
    updateMj();
    return 0;
}
int COMPRESSER::RecverSeqConfi()
{
    MSG xorMsg = 0;
    for(int i = GN-1; i >= 0; i--) {
        unsigned char g = getGFromSig(GTable[i]);
        Cnt[i] += (g!=0);
        Wid[i] += GetWidth(g);
        xorMsg = (xorMsg<<G)|g;
    }
    CurMsg ^= xorMsg;
    updateMj();
    return 0;
}
int COMPRESSER::compress_raw(MSG &msg)
{    
    // Sig[0]=0x4D;
    // Sig[1]=0x66;
    // Sig[2]=0;
    // Sig[3]=0x2a;
    // PrintMSG(Sig[0]);
    // PrintMSG(Sig[1]);
    // PrintMSG(Sig[2]);
    // PrintMSG(Sig[3]);
    unsigned char sh = 0;
    PSIG pSig;
    int sigCnt = 0;
    msg = 0;
    for(int i = 0; i < 4; i++){
        sh = (sh >> 1)|(Sig[i] != 0)<<3;
        if(sh&0x08) {
            pSig[sigCnt++]=&Sig[i];
        }
    }
    if(sh==0){
        return 0;
    }
    int r = max(GetWidth(Sig[0]),max(GetWidth(Sig[1]),max(GetWidth(Sig[2]),GetWidth(Sig[3]))));
    int length = (r*sigCnt+11)>>3;
    if(length > 7){
        return -1;
    }
    for(int i = r - 1; i >= 0; i--) {
        for(int j = sigCnt-1; j >= 0; j--) {
            msg = (msg<<1)|((*pSig[j]>>i)&1);
        }
    }
    msg =(msg << 4)|sh;
    return 0;
}


int COMPRESSER::uncompress_raw(MSG msg)
{
    //unsigned char sh;
    //msg >>= 4;
    PSIG pSig;
    char sigCnt = 0;
    for(int i = 0; i < 4; i++){
        Sig[i] = 0;
        if(msg & 1){
            pSig[sigCnt++] = &Sig[i];
        }
        msg >>= 1;
    }
    int i = 0;
    while(msg) {
        for(int j = 0; j < sigCnt; j++){
            *pSig[j] |=( (msg&1)<<i);
            msg >>= 1;
        }
        i++;
    }
    return 0;
}


// void TestCompresser(){
//     COMPRESSER Compresser;
//     COMPRESSER Uncompresser;
//     Compresser.InsertMsg(0x1940000000000000ULL);
//     Uncompresser.InsertMsg(0x1940000000000000ULL);
//     MSG tmp,tmp2;
//     int a = Compresser.Compress(0x4160000000000008ULL,tmp);
//     printf("%d\n",a);
//     Uncompresser.Uncompress(tmp,tmp2);
//     PrintMSG(tmp);
//     PrintMSG(tmp2);
//     Compresser.Compress(0x1940000000000000ULL,tmp);
//     Uncompresser.Uncompress(tmp,tmp2);
//     PrintMSG(tmp);
//     PrintMSG(tmp2);
//     Compresser.Compress(0x3960000000000000ULL,tmp);
//     PrintMSG(tmp);
//     Uncompresser.Uncompress(tmp,tmp2);
//     PrintMSG(tmp2);
// }


// int main() {
//     TestCompresser();
//     printf("%d\n",LenMSG(0x11));
//     return 0;
// }
