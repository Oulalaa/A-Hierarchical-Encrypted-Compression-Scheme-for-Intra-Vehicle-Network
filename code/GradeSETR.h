#ifndef GRADESETR_H
#define GRADESETR_H

#include "CustomizeCAN.h"
#define PRE_KEY_SIZE 16
#define SESS_KEY_SIZE 16
#define AUTHDM_SIZE 8
#define AUTHPM_SIZE 1
#define DEBUG


class INFO {
public:
    uint8_t EID;
    uint8_t MID;
    uint8_t GECU;
    unsigned char K_pre[PRE_KEY_SIZE];
    unsigned char K_sess[SESS_KEY_SIZE];
    uint16_t CTR;
    uint8_t *EIDList;
    int ListNums;
    bool AuthState;
    void IncreaseCTR();
    INFO(uint8_t mid);
    ~INFO();
    void LoadKpre(unsigned char data[]);
    void SetEIDList(uint8_t *EIDList,int nums);
    int FindEID(uint8_t eid);
    bool GetAuthState();
};

class NODEAUTH2 {
private:
    INFO *info;
    uint8_t R1[7],R2[7];
    int curStep;
    unsigned char K_tmp[SESS_KEY_SIZE];
    bool checkStep(CUSTID id);
    void IncreaseStep();
    void ResetStep();
public:
    NODEAUTH2(INFO *info);
    int AccessAuth2Step1(CUSMSG &sendBuf);
    int AccessAuth2Step2(CUSMSG recvBuf,CUSMSG &sendBuf);
    int AccessAuth2Step3(CUSMSG recvBuf,CUSMSG &sendBuf);
    int AccessAuth2Step4(CUSMSG recvBuf,CUSMSG &sendBuf);
    int AccessAuth2Step5(CUSMSG recvBuf);
};
class NODEAUTHN {
private:
    INFO *info;
    uint8_t *Ri;
    int curStep;
    uint64_t recvCnt;
    unsigned char K_tmp[SESS_KEY_SIZE];
    bool checkStep(CUSTID id);
    void IncreaseStep();
    void ResetStep();
public:
    NODEAUTHN(INFO *info);
    ~NODEAUTHN();
    int AccessAuthNStep1(CUSMSG &sendBuf);
    int AccessAuthNStep2(CUSMSG recvBuf,CUSMSG &sendBuf);
    int AccessAuthNStep3(CUSMSG recvBuf,CUSMSG &sendBuf1,CUSMSG &sendBuf2,CUSMSG &sendBuf3);
    int AccessAuthNStep4(CUSMSG recvBuf,CUSMSG &sendBuf);
    int AccessAuthNStep5(CUSMSG recvBuf);
};
class GSETRSENDER{
    CUSMSG preMsg;
    INFO *info;
    bool authDMFlag;
public:
    GSETRSENDER(INFO *info);
    int Lv1MsgSend(uint8_t data[],int dataLen,CUSMSG &sendBuf);
    int Lv2MsgSend(uint8_t data[],int dataLen,CUSMSG &sendBuf);
    int Lv3MsgSend(uint8_t data[],int dataLen,CUSMSG &sendBuf);
    int Lv4MsgSend(uint8_t data[],int dataLen,CUSMSG &sendBuf);
    int AuthMsgSend(CUSMSG &sendBuf);
};
class GSETRRECVER{
    CUSMSG preMsg;
    INFO *info;
    bool authDMFlag;
public:
    GSETRRECVER(INFO *info);
    int Lv1MsgRecv(CUSMSG recvBuf,uint8_t out[],int &outLen);
    int Lv2MsgRecv(CUSMSG recvBuf,uint8_t out[],int &outLen);
    int Lv3MsgRecv(CUSMSG recvBuf,uint8_t out[],int &outLen);
    int Lv4MsgRecv(CUSMSG recvBuf,uint8_t out[],int &outLen);
    int AuthMsgRecv(CUSMSG recvBuf);
    int SwitchMsg(CUSMSG recvBuf,uint8_t out[],int &outLen);
};

void NodeAuth2SelfTest();
void NodeAuth3SelfTest();
void GSETRSelfTest();
#endif // GRADESETR_H