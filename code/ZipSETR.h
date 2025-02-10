#ifndef ZIPSETR_H
#define ZIPSETR_H
#include "GradeSETR.h"
#include "compress.h"
#define DYN_KEY_SIZE 7
#define MAX_KEY_XOR_SIZE 40
class ZIPENCHELPER{
    protected:
    
    public:
    INFO *info;
    COMPRESSER zipHelper;
    unsigned char K_xor[MAX_KEY_XOR_SIZE];
    unsigned char K_dyn[DYN_KEY_SIZE];
    size_t klen,kcur;
    int curStep;
    uint32_t recvCnt;
    ZIPENCHELPER(INFO *info);
    virtual ~ZIPENCHELPER();
    void KxorUpdate(unsigned char* seed,int seedLen);
    bool checkStep(CUSTID id);
    void IncreaseStep();
    void ResetStep();
};

class ZIPENCSENDER : public ZIPENCHELPER{
    private:
    bool firstFlag;
    int Lv3MsgSend(uint8_t data[],int dataLen,CUSMSG &sendBuf);
    public:
    ZIPENCSENDER(INFO *info);
    ~ZIPENCSENDER();
    int KdynDistriStep1(CUSMSG &sendBuf);
    int KdynDistriStep3(CUSMSG recvBuf);
    int ZipEncSend(uint8_t data[],int dataLen,CUSMSG &sendBuf,GSETRSENDER *gsender=nullptr);

};
class ZIPENCRECVER : public ZIPENCHELPER{
    private:
    int Lv3MsgRecv(CUSMSG recvBuf, uint8_t out[], int &outLen);
    public:
    ZIPENCRECVER(INFO *info);
    ~ZIPENCRECVER();
    int KdynDistriStep2(CUSMSG recvBuf, CUSMSG &sendBuf);
    int ZipEncRecv(CUSMSG recvBuf,uint8_t out[], int &outLen, GSETRRECVER *grecver=nullptr);
};
#endif // ZIPSETR_H