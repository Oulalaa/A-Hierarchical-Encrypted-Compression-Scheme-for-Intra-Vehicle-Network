#include "ZipSETR.h"
#include "util.h"
#define UPDATEKORLEN(kcur, klen, width) \
    do { \
        (kcur) += (width); \
        (klen) -= (width); \
    } while(0)

static unsigned char buffer[64];
#ifdef DEBUG
static unsigned long Duration;
#endif
ZIPENCHELPER::ZIPENCHELPER(INFO *info)
{
    this->info = info;
    //this->zipHelper = new COMPRESSER();
    kcur = 0,klen = 0;
    curStep = 0;
    recvCnt = 0;
}

ZIPENCHELPER::~ZIPENCHELPER()
{  
    //delete zipHelper;
}

void ZIPENCHELPER::KxorUpdate(unsigned char *seed, int seedLen)
{
    buffer[0] = K_xor[klen-1];
    ByteCopy(K_dyn,DYN_KEY_SIZE,buffer+1);
    ByteCopy(seed, seedLen,buffer+1+DYN_KEY_SIZE);
    size_t inLen = 1+DYN_KEY_SIZE+seedLen;
    int outLen;
    ByteCopy(K_xor+kcur,klen-1,K_xor);
    KdfXor(buffer,inLen,K_xor+klen-1,outLen);
    kcur = 0, klen += 31;
}
bool ZIPENCHELPER::checkStep(CUSTID id)
{
    uint32_t curStep;
    if(id.GetExtVal(0,3,curStep)>=0&&curStep == this->curStep){
        return true;
    }
    Serial.print("step err!need:");
    Serial.print(this->curStep);
    Serial.print("  get:");
    Serial.println(curStep);
    return false;
}

void ZIPENCHELPER::IncreaseStep()
{
    this->curStep = (this->curStep+1)%3;
}

void ZIPENCHELPER::ResetStep()
{
    this->curStep = 0;
}
ZIPENCSENDER::ZIPENCSENDER(INFO *info):ZIPENCHELPER(info){
    this->firstFlag = true;
}
ZIPENCSENDER::~ZIPENCSENDER(){

}
int ZIPENCSENDER::KdynDistriStep1(CUSMSG &sendBuf)
{
    #ifdef DEBUG
    Serial.print("==============ECUs");
    Serial.print(info->EID);
    Serial.println("==============");
    Serial.println("开始动态密钥初始化！");
    START_TIME(Duration);
    #endif
    sendBuf.id.SetExtFlag(true);
    sendBuf.id.SetMID(this->info->MID);
    sendBuf.id.SetMSGTYPE(MSGTYPE::ZIPKEYEX);
    sendBuf.id.SetExtVal(0,3,0);
    if(!checkStep(sendBuf.id)){
        ResetStep();
    }
    for(int i = 0; i < 7; i++){
        buffer[i] = random(0xff);
    }
    Kdf(buffer,7,DYN_KEY_SIZE,K_dyn);
    #ifdef DEBUG
    Serial.print("EIDs:");
    Serial.println(info->EID);
    Serial.print("R:");
    PrintBuffer(buffer,7);
    Serial.print("Kdyn:");
    PrintBuffer(K_dyn,DYN_KEY_SIZE);
    #endif
    int outLen;
    //unsigned char buffer[25];
    buffer[0] = info->CTR&0xffU;
    buffer[1] = (info->CTR>>8)&0xffU;
    ByteCopy(K_dyn,DYN_KEY_SIZE,buffer+2);
    Mac(buffer,DYN_KEY_SIZE+2,info->K_sess,buffer+DYN_KEY_SIZE+2,outLen);
    buffer[1] = buffer[DYN_KEY_SIZE+2];
    sendBuf.len = 8;
    ASCONEncrypt(buffer+1,8,info->K_sess,sendBuf.data,sendBuf.len);
    #ifdef DEBUG
    Serial.print("AUTHdyn:0x");
    Serial.println(buffer[1],HEX);
    Serial.print("C:");
    PrintBuffer(sendBuf.data,sendBuf.len);
    Serial.println("step1完成！");
    #endif
    IncreaseStep();
    return 0;
}

int ZIPENCSENDER::KdynDistriStep3(CUSMSG recvBuf)
{
    if(!checkStep(recvBuf.id)){
        return -1;
    }
    uint32_t eid;
    int outLen;
    //unsigned char buffer[26];
    if(recvBuf.id.GetExtVal(3,8,eid) < 0) {
        Serial.print(eid);
        return -1;
    } 
    int idx = info->FindEID(eid);
    if(idx < 0 || (((1ULL<<idx)&recvCnt )!= 0)){
        Serial.print(idx);
        return -1;
    }
    buffer[0] = info->CTR&0xffU;
    buffer[1] = (info->CTR>>8)&0xffU;
    buffer[2] = eid;
    ByteCopy(K_dyn,DYN_KEY_SIZE,buffer+3);
    Mac(buffer,10,info->K_sess,buffer+10,outLen);
    #ifdef DEBUG
    Serial.print("XAUTH");
    Serial.print(idx);
    Serial.print(":");
    PrintBuffer(buffer+10,8);
    #endif
    if(!ByteCmp(buffer+10,recvBuf.data,8)){
        #ifdef DEBUG
        Serial.println("验证失败！");
        Serial.println("================================");
        #endif
        return -1;
    }
    //把recvCnt当作二进制集合用，最多可容纳63个元素
    recvCnt |= (1ULL<<idx);
    if(recvCnt+1!=(1ULL<<info->ListNums)){
        return 1;
    }
    //收到所有节点消息后
    ByteCopy(info->K_sess,SESS_KEY_SIZE,buffer);
    ByteCopy(K_dyn,DYN_KEY_SIZE,buffer+SESS_KEY_SIZE);
    KdfXor(buffer,SESS_KEY_SIZE+DYN_KEY_SIZE,K_xor,outLen);
    kcur = 0, klen = outLen;
    info->IncreaseCTR();
    #ifdef DEBUG
    END_TIME(Duration);
    printDurationMS("step3完成！动态密钥初始化成功，耗时：",Duration);
    Serial.print("Kxor:");
    PrintBuffer(K_xor,klen);
    Serial.println("================================");
    #endif
    ResetStep();
    return 0;
}

int ZIPENCSENDER::ZipEncSend(uint8_t data[], int dataLen, CUSMSG &sendBuf, GSETRSENDER *gsender)
{
    if(firstFlag){
        #ifdef DEBUG
        Serial.println("===========首条消息，不压缩============");
        #endif
        firstFlag = false;
        zipHelper.InsertMsg(data,dataLen);
        if(gsender!= nullptr){
            return gsender->Lv3MsgSend(data,dataLen,sendBuf);
        }
        return this->Lv3MsgSend(data,dataLen,sendBuf);
    }
    int outLen;
    // unsigned char buffer[25]={0,0,0,0,0,0,0,0,0,0};
    sendBuf.data64=0;
    sendBuf.len=0;
    if(zipHelper.Compress(data,dataLen,sendBuf.data+1,sendBuf.len)<0){
        #ifdef DEBUG
        Serial.println("==========无法压缩，正常发送===========");
        #endif
        if(gsender!= nullptr){
            return gsender->Lv3MsgSend(data,dataLen,sendBuf);
        }
        return this->Lv3MsgSend(data,dataLen,sendBuf);
    }
    #ifdef DEBUG
    Serial.println("=============压缩加密发送=============");
    Serial.print("原始内容：");
    PrintBuffer(data,dataLen);
    Serial.print("压缩后内容：");
    if(sendBuf.len == 0){
        Serial.println(0);
    }else{
       PrintBuffer(sendBuf.data+1,sendBuf.len); 
    }
    #endif
    memset(buffer+2,0,8*sizeof(uint8_t));
    buffer[0] = info->CTR&0xFFU;
    buffer[1] = (info->CTR>>8)&0xFFU;
    ByteCopy(data,dataLen,buffer+2);
    Mac(buffer,10,info->K_sess,buffer+10,outLen);
    info->IncreaseCTR();
    sendBuf.data[0] = buffer[10];
    sendBuf.len++;
    Xor(sendBuf.data,sendBuf.len,K_xor+kcur,sendBuf.data);
    UPDATEKORLEN(kcur,klen,sendBuf.len);
    if(klen<=9){
        KxorUpdate(buffer+11,15);
    }
    #ifdef DEBUG
    Serial.print("AUTHpm：0x");
    Serial.println(buffer[10],HEX);
    Serial.print("压缩加密内容：");
    PrintBuffer(sendBuf.data,sendBuf.len);
    Serial.println("压缩加密完成！");
    Serial.println("=====================================");
    #endif
    sendBuf.id.SetExtFlag(false);
    sendBuf.id.SetMID(this->info->MID);
    sendBuf.id.SetMSGTYPE(MSGTYPE::ZIPENC);
    return 0;
}

int ZIPENCSENDER::Lv3MsgSend(uint8_t data[], int dataLen, CUSMSG &sendBuf)
{
    
    if(dataLen > 8){
        return -1;
    }
    #ifdef DEBUG
    Serial.println("==========仅加密级别消息发送==========");
    Serial.print("原始内容：");
    PrintBuffer(data,dataLen);
    #endif
    int outLen;
    //unsigned char buffer[16];
    ASCONEncrypt(data,dataLen,info->K_sess,sendBuf.data,sendBuf.len);
    sendBuf.id.SetMID(info->MID);
    sendBuf.id.SetMTYPE(MTYPE::NORMAL);
    sendBuf.id.SetSTYPE(STYPE::ENCONLY);
    #ifdef DEBUG
    Serial.print("发送内容：");
    PrintBuffer(sendBuf.data,sendBuf.len);
    Serial.println("====================================");
    #endif
    return 0;
}
ZIPENCRECVER::ZIPENCRECVER(INFO *info):ZIPENCHELPER(info){

}
ZIPENCRECVER::~ZIPENCRECVER(){

}
int ZIPENCRECVER::KdynDistriStep2(CUSMSG recvBuf, CUSMSG &sendBuf)
{
    #ifdef DEBUG
    Serial.print("==============ECUr");
    Serial.print(info->EID);
    Serial.println("==============");
    Serial.println("接收到动态密钥初始化信息！");
    #endif
    if(!checkStep(recvBuf.id)){
        ResetStep();
    }
    IncreaseStep();
    //unsigned char buffer[26];
    int outLen;
    ASCONDecrypt(recvBuf.data,recvBuf.len,info->K_sess,buffer+2,outLen);
    #ifdef DEBUG
    Serial.print("DEC:");
    PrintBuffer(buffer+2,outLen);
    #endif
    uint8_t auth = buffer[2];
    buffer[1] = info->CTR&0xffU;
    buffer[2] = (info->CTR>>8)&0xffU;
    Mac(buffer+1,9,info->K_sess,buffer+10,outLen);
    #ifdef DEBUG
    Serial.print("XAUTHdyn:0x");
    Serial.println(buffer[10],HEX);
    #endif
    if(buffer[10] != auth){
        #ifdef DEBUG
        Serial.println("验证失败！");
        Serial.println("================================");
        #endif
        return -1;
    }
    ByteCopy(buffer+3,DYN_KEY_SIZE,K_dyn);
    buffer[0] = info->CTR&0xffU;
    buffer[1] = (info->CTR>>8)&0xffU;
    buffer[2] = info->EID;
    Mac(buffer,3+DYN_KEY_SIZE,info->K_sess,buffer+3+DYN_KEY_SIZE,outLen);
    #ifdef DEBUG
    Serial.print("AUTHi:");
    PrintBuffer(buffer+3+DYN_KEY_SIZE,8);
    #endif
    ByteCopy(buffer+3+DYN_KEY_SIZE,8,sendBuf.data);
    sendBuf.len = 8;
    sendBuf.id.SetMID(this->info->MID);
    sendBuf.id.SetExtFlag(true);
    sendBuf.id.SetMSGTYPE(MSGTYPE::ZIPKEYEX);
    sendBuf.id.SetExtVal(0,3,1);
    sendBuf.id.SetExtVal(3,8,info->EID);
    ByteCopy(info->K_sess,SESS_KEY_SIZE,buffer);
    ByteCopy(K_dyn,DYN_KEY_SIZE,buffer+SESS_KEY_SIZE);
    KdfXor(buffer,SESS_KEY_SIZE+DYN_KEY_SIZE,K_xor,outLen);
    kcur = 0, klen = outLen;
    info->IncreaseCTR();
    ResetStep();
    #ifdef DEBUG
    Serial.println("step2完成！Kdyn初始化成功");
    Serial.print("Kxor:");
    PrintBuffer(K_xor,klen);
    Serial.println("================================");
    #endif
    return 0;
}

int ZIPENCRECVER::ZipEncRecv(CUSMSG recvBuf, uint8_t out[], int &outLen, GSETRRECVER *grecver)
{
    MSGTYPE msgtype = recvBuf.id.GETMSGTYPE();
    if(msgtype==MSGTYPE::ENCONLY){
        #ifdef DEBUG
        Serial.println("======未压缩消息，使用常规方法处理=====");
        #endif
        
        int ret;
        if(grecver!= nullptr){
            ret = grecver->Lv3MsgRecv(recvBuf, out, outLen);
        }else{
            ret = this->Lv3MsgRecv(recvBuf, out, outLen);
        }
        if(ret != 0){
            return ret;
        }
        zipHelper.InsertMsg(out,outLen);
        return 0;
    }else if(msgtype==MSGTYPE::ZIPENC){
        #ifdef DEBUG
        Serial.println("============解密及验证恢复============");
        Serial.print("接收内容：");
        PrintBuffer(recvBuf.data,recvBuf.len);
        #endif
        // unsigned char buffer[25]={0,0,0,0,0,0,0,0,0,0};
        memset(buffer+2,0,8*sizeof(uint8_t));
        Xor(recvBuf.data,recvBuf.len,K_xor+kcur,recvBuf.data);
        uint8_t auth = recvBuf.data[0];
        zipHelper.Uncompress(recvBuf.data+1,recvBuf.len-1,buffer+2,outLen);
        buffer[0] = info->CTR&0xFFU;
        buffer[1] = (info->CTR>>8)&0xFFU;
        Mac(buffer,10,info->K_sess,buffer+10,outLen);
        #ifdef DEBUG
        Serial.print("解密内容：");
        PrintBuffer(recvBuf.data,recvBuf.len);
        Serial.print("解压缩内容：");
        PrintBuffer(buffer+2,8);
        Serial.print("XAUTHpm：0x");
        Serial.println(buffer[10],HEX);
        #endif
        if(buffer[10]!=auth){
            #ifdef DEBUG
            Serial.println("验证失败！");
            Serial.println("================================");
            #endif
            return -1;
        }
        UPDATEKORLEN(kcur,klen,recvBuf.len);
        if(klen<=9){
            KxorUpdate(buffer+11,15);
        }
        info->IncreaseCTR();
        ByteCopy(buffer+2,8,out);
        outLen = 8;
        #ifdef DEBUG
        Serial.println("解密及恢复验证完成！");
        Serial.println("=====================================");
        #endif
        return 0;
    }
    return -1;
}
int ZIPENCRECVER::Lv3MsgRecv(CUSMSG recvBuf, uint8_t out[], int &outLen)
{
    
    if(recvBuf.len < 8){
        return -1;
    }
    #ifdef DEBUG
    Serial.println("==========仅加密级别消息接收==========");
    Serial.print("接收内容：");
    PrintBuffer(recvBuf.data,recvBuf.len);
    #endif
    ASCONDecrypt(recvBuf.data,8,info->K_sess,out,outLen);
    #ifdef DEBUG
    Serial.print("还原内容：");
    PrintBuffer(out,outLen);
    Serial.println("====================================");
    #endif
    return 0;
}