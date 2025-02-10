#include "GradeSETR.h"
#include "util.h"
static unsigned char buffer[32];  //栈内存不足时，将局部变量替换为全局变量
#ifdef DEBUG
static unsigned long Duration;
#endif
void INFO::IncreaseCTR()
{
    this->CTR++;
}
bool INFO::GetAuthState()
{
    return AuthState;
}

INFO::INFO(uint8_t mid)
{
    this->MID = mid;
    this->EIDList = new uint8_t[0];
    ListNums = 0;
    CTR = 0;
    AuthState = false;
}

INFO::~INFO()
{
    delete[] EIDList;
}

void INFO::LoadKpre(unsigned char data[])
{
    ByteCopy(data,PRE_KEY_SIZE,K_pre);
}

void INFO::SetEIDList(uint8_t *EIDList, int nums)
{
    delete[] this->EIDList;
    this->EIDList = new uint8_t[nums];
    for(int i = 0; i < nums; i++){
        this->EIDList[i] = EIDList[i];
    }
    this->ListNums = nums;
}

int INFO::FindEID(uint8_t eid)
{
    for(int i = 0; i < this->ListNums; i++){
        if(eid == EIDList[i]){
            return i;
        }
    }
    return -1;
}

bool NODEAUTH2::checkStep(CUSTID id)
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

void NODEAUTH2::IncreaseStep()
{
    this->curStep = (this->curStep+1)%5;
}

void NODEAUTH2::ResetStep()
{
    this->curStep = 0;
}

NODEAUTH2::NODEAUTH2(INFO *info)
{
    this->info = info;
    this->curStep = 0;
}

int NODEAUTH2::AccessAuth2Step1(CUSMSG &sendBuf)
{
    #ifdef DEBUG
    Serial.print("==============ECU");
    Serial.print(info->EID);
    Serial.println("==============");
    Serial.println("开始两节点间身份认证！");
    START_TIME(Duration);
    #endif
    sendBuf.id.SetExtFlag(true);
    sendBuf.id.SetMID(this->info->MID);
    sendBuf.id.SetMTYPE(MTYPE::AUTHDM);
    sendBuf.id.SetSTYPE(STYPE::NONE);
    sendBuf.id.SetExtVal(0,3,0);
    //unsigned char buffer[16];
    if(!checkStep(sendBuf.id)){
        ResetStep();
    }
    buffer[0] = info->EID;
    for(int i = 0; i < 7; i++){
        buffer[i+1] = R1[i] = random(0xff);
    }
    #ifdef DEBUG
    Serial.print("EID1:");
    Serial.println(info->EID);
    Serial.print("R1:");
    PrintBuffer(R1,7);
    #endif
    sendBuf.len = 8;
    ASCONEncrypt(buffer,8,info->K_pre,sendBuf.data,sendBuf.len);
    #ifdef DEBUG
    Serial.print("C1:");
    PrintBuffer(sendBuf.data,sendBuf.len);
    Serial.println("step1完成！");
    #endif
    IncreaseStep();
    return 0;
}
int NODEAUTH2::AccessAuth2Step2(CUSMSG recvBuf,CUSMSG &sendBuf)
{
    #ifdef DEBUG
    Serial.print("==============ECU");
    Serial.print(info->EID);
    Serial.println("==============");
    Serial.println("接收到两节点间认证请求，认证开始！");
    #endif
    if(!checkStep(recvBuf.id)){
        ResetStep();
    }
    IncreaseStep();
    //unsigned char buffer[16];
    int outLen;
    ASCONDecrypt(recvBuf.data,recvBuf.len,info->K_pre,buffer,outLen);
    #ifdef DEBUG
    Serial.print("DEC:");
    PrintBuffer(buffer,outLen);
    #endif
    if(buffer[0]!=info->EIDList[0]){
        return -1;
    }
    buffer[0] = info->EID;
    for(int i = 0; i < 7; i++){
        R1[i] = buffer[i+1];
        R2[i] = random(0xff);
        buffer[i+1] = R2[i];
    }
    #ifdef DEBUG
    Serial.print("EID2:");
    PrintBuffer(buffer,1);
    Serial.print("R2:");
    PrintBuffer(&buffer[1],7);
    #endif
    sendBuf.len = 8;
    ASCONEncrypt(buffer,8,info->K_pre,sendBuf.data,sendBuf.len);
    #ifdef DEBUG
    Serial.print("C2:");
    PrintBuffer(sendBuf.data,sendBuf.len);
    #endif
    sendBuf.id.SetMID(this->info->MID);
    sendBuf.id.SetMTYPE(MTYPE::AUTHDM);
    sendBuf.id.SetSTYPE(STYPE::NONE);
    sendBuf.id.SetExtFlag(true);
    sendBuf.id.SetExtVal(0,3,1);
    IncreaseStep();
    for(int i = 0; i < 7; i++){
        buffer[i] = R1[i];
        buffer[i+7] = R2[i];
    }
    
    Kdf(buffer,14,SESS_KEY_SIZE,K_tmp);
    #ifdef DEBUG
    Serial.print("KDF:");
    PrintBuffer(K_tmp,SESS_KEY_SIZE);
    Serial.println("step2完成！");
    #endif
    return 0;
}

int NODEAUTH2::AccessAuth2Step3(CUSMSG recvBuf, CUSMSG &sendBuf)
{
    if(!checkStep(recvBuf.id)){
        return -1;
    }
    IncreaseStep();
    //unsigned char buffer[16];
    int outLen;
    ASCONDecrypt(recvBuf.data,recvBuf.len,info->K_pre,buffer,outLen);
    #ifdef DEBUG
    Serial.print("DEC:");
    PrintBuffer(buffer,outLen);
    #endif
    if(buffer[0]!=info->EIDList[0]){
        return -1;
    }
    for(int i = 0; i < 7; i++){
        R2[i] = buffer[i+1];
    }
    for(int i = 0; i < 7; i++){
        buffer[i] = R1[i];
        buffer[i+7] = R2[i];
    }
    Kdf(buffer,14,SESS_KEY_SIZE,K_tmp);
    #ifdef DEBUG
    Serial.print("KDF:");
    PrintBuffer(K_tmp,SESS_KEY_SIZE);
    #endif
    Mac(R1,7,K_tmp,buffer,outLen);
    #ifdef DEBUG
    Serial.print("AUTH1:");
    PrintBuffer(buffer,8);
    Serial.println("step3完成！");
    #endif
    ByteCopy(buffer,8,sendBuf.data);
    sendBuf.len = 8;
    sendBuf.id.SetMID(this->info->MID);
    sendBuf.id.SetMTYPE(MTYPE::AUTHDM);
    sendBuf.id.SetSTYPE(STYPE::NONE);
    sendBuf.id.SetExtFlag(true);
    sendBuf.id.SetExtVal(0,3,2);
    IncreaseStep();
    return 0;
}
int NODEAUTH2::AccessAuth2Step4(CUSMSG recvBuf, CUSMSG &sendBuf)
{
    if(!checkStep(recvBuf.id)){
        return -1;
    }
    IncreaseStep();
    // unsigned char buffer[16];
    int outLen;
    Mac(R1,7,K_tmp,buffer,outLen);
    #ifdef DEBUG
    Serial.print("XAUTH1:");
    PrintBuffer(buffer,8);
    #endif
    if(!ByteCmp(buffer,recvBuf.data,8)){
        return -1;
    }
    Mac(R2,7,K_tmp,buffer,outLen);
    #ifdef DEBUG
    Serial.print("AUTH2:");
    PrintBuffer(buffer,8);
    #endif
    ByteCopy(buffer,8,sendBuf.data);
    sendBuf.len = 8;
    sendBuf.id.SetMID(this->info->MID);
    sendBuf.id.SetMTYPE(MTYPE::AUTHDM);
    sendBuf.id.SetSTYPE(STYPE::NONE);
    sendBuf.id.SetExtFlag(true);
    sendBuf.id.SetExtVal(0,3,3);
    ResetStep();
    ByteCopy(K_tmp,SESS_KEY_SIZE,info->K_sess);
    this->info->AuthState = true;
    #ifdef DEBUG
    Serial.println("step4完成！两节点认证成功");
    Serial.println("================================");
    #endif
    return 0;
}

int NODEAUTH2::AccessAuth2Step5(CUSMSG recvBuf)
{
    if(!checkStep(recvBuf.id)){
        return -1;
    }
    IncreaseStep();
    // unsigned char buffer[16];
    int outLen;
    Mac(R2,7,K_tmp,buffer,outLen);
    #ifdef DEBUG
    Serial.print("XAUTH2:");
    PrintBuffer(buffer,8);
    #endif
    if(!ByteCmp(buffer,recvBuf.data,8)){
        return -1;
    }
    ByteCopy(K_tmp,SESS_KEY_SIZE,info->K_sess);
    this->info->AuthState = true;
    #ifdef DEBUG
    END_TIME(Duration);
    printDurationMS("step5完成！两节点认证成功，耗时：",Duration);
    Serial.println("================================");
    #endif
    ResetStep();
    return 0;
}
void NodeAuth2SelfTest(){
    uint8_t k[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t eidList1[1] = {2}; 
    uint8_t eidList2[1] = {1}; 
    INFO info1(0x111),info2(0x111);
    info1.EID=1,info1.SetEIDList(eidList1,1);
    info2.EID=2,info2.SetEIDList(eidList2,1);
    info1.LoadKpre(k);
    info2.LoadKpre(k);
    NODEAUTH2 auth1(&info1),auth2(&info2);
    CUSMSG msg1,msg2;
    Serial.println(auth1.AccessAuth2Step1(msg1));
    Serial.println(auth2.AccessAuth2Step2(msg1,msg2));
    Serial.println(auth1.AccessAuth2Step3(msg2,msg1));
    Serial.println(auth2.AccessAuth2Step4(msg1,msg2));
    Serial.println(auth1.AccessAuth2Step5(msg2));
    PrintBuffer(info1.K_sess,SESS_KEY_SIZE);
    PrintBuffer(info2.K_sess,SESS_KEY_SIZE);
}

bool NODEAUTHN::checkStep(CUSTID id)
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

void NODEAUTHN::IncreaseStep()
{
    this->curStep = (this->curStep+1)%5;
}

void NODEAUTHN::ResetStep()
{
    this->curStep = 0;
    this->recvCnt = 0;
}

NODEAUTHN::NODEAUTHN(INFO *info)
{
    this->info = info;
    ResetStep();
    int len = 14+8;
    if(info->EID == info->GECU){
        len = (info->ListNums+1)*7;
    }
    this->Ri = new uint8_t[len];
}

NODEAUTHN::~NODEAUTHN()
{
    delete[] Ri;
}

int NODEAUTHN::AccessAuthNStep1(CUSMSG &sendBuf)
{
    #ifdef DEBUG
    Serial.print("==============ECU");
    Serial.print(info->EID);
    Serial.println("==============");
    Serial.print("开始");
    Serial.print(info->ListNums+1);
    Serial.println("节点间身份认证！");
    START_TIME(Duration);
    #endif
    sendBuf.id.SetMID(this->info->MID);
    sendBuf.id.SetMTYPE(MTYPE::AUTHDM);
    sendBuf.id.SetSTYPE(STYPE::NONE);
    sendBuf.id.SetExtFlag(true);
    sendBuf.id.SetExtVal(0,3,0);
    //unsigned char buffer[16];
    if(!checkStep(sendBuf.id)){
        ResetStep();
    }
    buffer[0] = info->EID;
    for(int i = 0; i < 7; i++){
        buffer[i+1] = this->Ri[i] = random(0xff);
    }
    #ifdef DEBUG
    Serial.print("EIDg:");
    Serial.println(info->EID);
    Serial.print("Rg:");
    PrintBuffer(Ri,7);
    #endif
    sendBuf.len = 8;
    ASCONEncrypt(buffer,8,info->K_pre,sendBuf.data,sendBuf.len);
    #ifdef DEBUG
    Serial.print("Cg:");
    PrintBuffer(sendBuf.data,sendBuf.len);
    Serial.println("step1完成！");
    #endif
    IncreaseStep();
    return 0;
}
int NODEAUTHN::AccessAuthNStep2(CUSMSG recvBuf,CUSMSG &sendBuf)
{
    #ifdef DEBUG
    Serial.print("==============ECU");
    Serial.print(info->EID);
    Serial.println("==============");
    Serial.print("接收到");
    Serial.print(info->ListNums+1);
    Serial.println("节点间认证请求，认证开始！");
    #endif
    if(!checkStep(recvBuf.id)){
        ResetStep();
    }
    IncreaseStep();
    //unsigned char buffer[16];
    int outLen;
    ASCONDecrypt(recvBuf.data,recvBuf.len,info->K_pre,buffer,outLen);
    #ifdef DEBUG
    Serial.print("DEC:");
    PrintBuffer(buffer,outLen);
    #endif
    if(buffer[0]!=info->GECU){
        return -1;
    }
    buffer[0] = info->EID;
    for(int i = 0; i < 7; i++){
        Ri[i] = buffer[i+1];
        Ri[i+7] = random(0xff);
        buffer[i+1] = Ri[i+7];
    }
    #ifdef DEBUG
    Serial.print("EIDi:");
    Serial.println(buffer[0]);
    Serial.print("Ri:");
    PrintBuffer(buffer+1,7);
    #endif
    sendBuf.len = 8;
    ASCONEncrypt(buffer,8,info->K_pre,sendBuf.data,sendBuf.len);
    #ifdef DEBUG
    Serial.print("Ci:");
    PrintBuffer(sendBuf.data,sendBuf.len);
    Serial.println("step2完成！");
    #endif
    sendBuf.id.SetMID(this->info->MID);
    sendBuf.id.SetMTYPE(MTYPE::AUTHDM);
    sendBuf.id.SetSTYPE(STYPE::NONE);
    sendBuf.id.SetExtFlag(true);
    sendBuf.id.SetExtVal(0,3,1);
    sendBuf.id.SetExtVal(3,8,info->EID);
    IncreaseStep();
    return 0;
}

int NODEAUTHN::AccessAuthNStep3(CUSMSG recvBuf, CUSMSG &sendBuf1,CUSMSG &sendBuf2,CUSMSG &sendBuf3)
{
    if(!checkStep(recvBuf.id)){
        return -1;
    }
    //缓存消息
    //unsigned char buffer[16];
    int outLen;
    ASCONDecrypt(recvBuf.data,recvBuf.len,info->K_pre,buffer,outLen);
    #ifdef DEBUG
    Serial.print("DEC:");
    PrintBuffer(buffer,outLen);
    #endif
    int idx = info->FindEID(buffer[0]);
    if(idx < 0 || (((1ULL<<idx)&recvCnt )!= 0)){
        return -1;
    }
    //把recvCnt当作二进制集合用，最多可容纳63个元素
    recvCnt |= (1ULL<<idx);
    for(int i = 0; i < 7; i++){
        Ri[i+((idx+1)*7)] = buffer[i+1];
    }
    if(recvCnt+1!=(1ULL<<info->ListNums)){
        return 1;
    }
    //收到所有节点消息后
    IncreaseStep();
    Kdf(Ri,(info->ListNums+1)*7,SESS_KEY_SIZE,K_tmp);
    ASCONEncrypt(K_tmp,SESS_KEY_SIZE,info->K_pre,buffer,outLen);
    #ifdef DEBUG
    Serial.print("KDF:");
    PrintBuffer(K_tmp,SESS_KEY_SIZE);
    Serial.print("Ck:");
    PrintBuffer(buffer,outLen);
    #endif
    ByteCopy(buffer,8,sendBuf1.data);
    ByteCopy(buffer+8,8,sendBuf2.data);
    sendBuf1.len = 8;
    sendBuf1.id.SetMID(this->info->MID);
    sendBuf1.id.SetMTYPE(MTYPE::AUTHDM);
    sendBuf1.id.SetSTYPE(STYPE::NONE);
    sendBuf1.id.SetExtFlag(true);
    sendBuf1.id.SetExtVal(0,3,2);
    sendBuf1.id.SetExtVal(3,2,0);
    sendBuf2.len = 8;
    sendBuf2.id.SetMID(this->info->MID);
    sendBuf2.id.SetMTYPE(MTYPE::AUTHDM);
    sendBuf2.id.SetSTYPE(STYPE::NONE);
    sendBuf2.id.SetExtFlag(true);
    sendBuf2.id.SetExtVal(0,3,2);
    sendBuf2.id.SetExtVal(3,2,1);
    Mac(Ri,7,K_tmp,buffer,outLen);
    #ifdef DEBUG
    Serial.print("AUTHg:");
    PrintBuffer(buffer,8);
    Serial.println("step3完成！");
    #endif
    ByteCopy(buffer,8,sendBuf3.data);
    sendBuf3.len = 8;
    sendBuf3.id.SetMID(this->info->MID);
    sendBuf3.id.SetMTYPE(MTYPE::AUTHDM);
    sendBuf3.id.SetSTYPE(STYPE::NONE);
    sendBuf3.id.SetExtFlag(true);
    sendBuf3.id.SetExtVal(0,3,2);
    sendBuf3.id.SetExtVal(3,2,2);
    this->recvCnt=0;
    IncreaseStep();
    return 0;
}
int NODEAUTHN::AccessAuthNStep4(CUSMSG recvBuf, CUSMSG &sendBuf)
{
    if(!checkStep(recvBuf.id)){
        return -1;
    }
    //缓存消息
    uint32_t val;
    int outLen;
    if(recvBuf.id.GetExtVal(3,2,val) < 0 || (((1ULL<<val)&recvCnt) != 0)) {
        return -1;
    }
    switch (val)
    {
    case 0:
        ByteCopy(recvBuf.data,8,K_tmp);
        break;
    case 1:
        ByteCopy(recvBuf.data,8,K_tmp+8);
        break;
    case 2:
        ByteCopy(recvBuf.data,8,Ri+14);
        break;
    default:
        return -1;
    }
    //把recvCnt当作二进制集合用，最多可容纳63个元素
    recvCnt |= (1ULL<<val);
    if(recvCnt+1!=(1ULL<<3)){
        return 1;
    }
    //收到所有消息后
    IncreaseStep();
    //unsigned char buffer[32];
    ASCONDecrypt(K_tmp,16,info->K_pre,buffer,outLen);
    #ifdef DEBUG
    Serial.print("Ksess:");
    PrintBuffer(buffer,16);
    #endif
    Mac(Ri,7,buffer,buffer+16,outLen);
    #ifdef DEBUG
    Serial.print("XAUTHg:");
    PrintBuffer(buffer+16,8);
    #endif
    if(!ByteCmp(buffer+16,Ri+14,8)){
        return -1;
    }
    ByteCopy(buffer,SESS_KEY_SIZE,info->K_sess);
    this->info->AuthState = true;
    Mac(Ri+7,7,info->K_sess,buffer,outLen);
    #ifdef DEBUG
    Serial.print("AUTHi:");
    PrintBuffer(buffer,8);
    Serial.print("step4完成！");
    Serial.print(info->ListNums+1);
    Serial.println("节点认证成功");
    Serial.println("================================");
    #endif
    ByteCopy(buffer,8,sendBuf.data);
    sendBuf.len = 8;
    sendBuf.id.SetMID(this->info->MID);
    sendBuf.id.SetMTYPE(MTYPE::AUTHDM);
    sendBuf.id.SetSTYPE(STYPE::NONE);
    sendBuf.id.SetExtFlag(true);
    sendBuf.id.SetExtVal(0,3,3);
    sendBuf.id.SetExtVal(3,8,info->EID);
    ResetStep();
    return 0;
}

    
int NODEAUTHN::AccessAuthNStep5(CUSMSG recvBuf)
{

    if(!checkStep(recvBuf.id)){
        return -1;
    }
    //缓存消息
    uint32_t eid;
    int outLen;
    //unsigned char buffer[16];
    if(recvBuf.id.GetExtVal(3,8,eid) < 0) {
        return -1;
    } 
    int idx = info->FindEID(eid);
    if(idx < 0 || (((1ULL<<idx)&recvCnt )!= 0)){
        return -1;
    }
    Mac(Ri+((idx+1)*7),7,K_tmp,buffer,outLen);
    #ifdef DEBUG
    Serial.print("XAUTH");
    Serial.print(idx);
    Serial.print(":");
    PrintBuffer(buffer,8);
    #endif
    if(!ByteCmp(buffer,recvBuf.data,8)){
        return -1;
    }
    //把recvCnt当作二进制集合用，最多可容纳63个元素
    recvCnt |= (1ULL<<idx);
    if(recvCnt+1!=(1ULL<<info->ListNums)){
        return 1;
    }
    //收到所有节点消息后
    ByteCopy(K_tmp,SESS_KEY_SIZE,info->K_sess);
    this->info->AuthState = true;
    #ifdef DEBUG
    END_TIME(Duration);
    Serial.print("step5完成！");
    Serial.print(info->ListNums+1);
    printDurationMS("节点认证成功，耗时：",Duration);
    Serial.println("================================");
    #endif
    ResetStep();
    return 0;
}


void NodeAuth3SelfTest(){
    //uno会炸
    uint8_t k[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t eidList1[2] = {2,3}; 
    uint8_t eidList2[2] = {1,3}; 
    uint8_t eidList3[2] = {1,2};
    INFO info1(0x111),info2(0x111),info3(0x111);
    NODEAUTHN auth1(&info1),auth2(&info2),auth3(&info3);
    CUSMSG msg1,msg2,msg3,msg4,msg5;
    info1.EID=1,info1.GECU=3,info1.SetEIDList(eidList1,2);
    info2.EID=2,info2.GECU=3,info2.SetEIDList(eidList2,2);
    info3.EID=3,info3.GECU=3,info3.SetEIDList(eidList3,2);
    info1.LoadKpre(k);
    info2.LoadKpre(k);
    info3.LoadKpre(k);
    Serial.println(auth3.AccessAuthNStep1(msg1));
    Serial.println(auth1.AccessAuthNStep2(msg1,msg2));
    Serial.println(auth2.AccessAuthNStep2(msg1,msg3));
    Serial.println(auth3.AccessAuthNStep3(msg2,msg4,msg5,msg1));
    Serial.println(auth3.AccessAuthNStep3(msg3,msg4,msg5,msg1));
    Serial.println(auth2.AccessAuthNStep4(msg4,msg2));
    Serial.println(auth2.AccessAuthNStep4(msg5,msg2));
    Serial.println(auth2.AccessAuthNStep4(msg1,msg2));
    Serial.println(auth3.AccessAuthNStep5(msg2));
    Serial.println(auth1.AccessAuthNStep4(msg4,msg3));
    Serial.println(auth1.AccessAuthNStep4(msg5,msg3));
    Serial.println(auth1.AccessAuthNStep4(msg1,msg3));
    Serial.println(auth3.AccessAuthNStep5(msg3));
    PrintBuffer(info1.K_sess,SESS_KEY_SIZE);
    PrintBuffer(info2.K_sess,SESS_KEY_SIZE);
    PrintBuffer(info3.K_sess,SESS_KEY_SIZE);
}



GSETRSENDER::GSETRSENDER(INFO *info)
{
    this->info = info;
    authDMFlag = false;
}

int GSETRSENDER::Lv1MsgSend(uint8_t data[],int dataLen,CUSMSG &sendBuf)
{
    
    if(dataLen > 8){
        return -1;
    }
    #ifdef DEBUG
    Serial.println("==========无操作级别消息发送==========");
    Serial.print("原始内容：");
    PrintBuffer(data,dataLen);
    #endif
    ByteCopy(data,dataLen,sendBuf.data);
    sendBuf.len=dataLen;
    sendBuf.id.SetMID(info->MID);
    sendBuf.id.SetMTYPE(MTYPE::NORMAL);
    sendBuf.id.SetSTYPE(STYPE::NONE);
    this->preMsg = sendBuf;
    this->authDMFlag = true;
    #ifdef DEBUG
    Serial.print("发送内容：");
    PrintBuffer(sendBuf.data,sendBuf.len);
    Serial.println("====================================");
    #endif
    return 0;
}

int GSETRSENDER::Lv2MsgSend(uint8_t data[], int dataLen, CUSMSG &sendBuf)
{
   
    if(dataLen > 7){
        return -1;
    }
    #ifdef DEBUG
    Serial.println("==========仅验证级别消息发送==========");
    Serial.print("原始内容：");
    PrintBuffer(data,dataLen);
    #endif
    int outLen;
    // unsigned char buffer[25];
    buffer[0] = info->CTR&0xff;
    buffer[1] = (info->CTR>>8)&0xff;
    ByteCopy(data,dataLen,buffer+2);
    Mac(buffer,dataLen+2,info->K_sess,buffer+9,outLen);
    sendBuf.data[0] = buffer[9];
    #ifdef DEBUG
    Serial.print("AUTHpm：0x");
    Serial.println(buffer[9],HEX);
    #endif
    ByteCopy(data,dataLen,sendBuf.data+1);
    sendBuf.len=dataLen+1;
    sendBuf.id.SetMID(info->MID);
    sendBuf.id.SetMTYPE(MTYPE::NORMAL);
    sendBuf.id.SetSTYPE(STYPE::AUTHONLY);
    info->IncreaseCTR();
    this->preMsg = sendBuf;
    this->authDMFlag = true;
    #ifdef DEBUG
    Serial.print("发送内容：");
    PrintBuffer(sendBuf.data,sendBuf.len);
    Serial.println("====================================");
    #endif
    return 0;
}

int GSETRSENDER::Lv3MsgSend(uint8_t data[], int dataLen, CUSMSG &sendBuf)
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
    // unsigned char buffer[16];
    ASCONEncrypt(data,dataLen,info->K_sess,sendBuf.data,sendBuf.len);
    sendBuf.id.SetMID(info->MID);
    sendBuf.id.SetMTYPE(MTYPE::NORMAL);
    sendBuf.id.SetSTYPE(STYPE::ENCONLY);
    this->preMsg = sendBuf;
    this->authDMFlag = true;
    #ifdef DEBUG
    Serial.print("发送内容：");
    PrintBuffer(sendBuf.data,sendBuf.len);
    Serial.println("====================================");
    #endif
    return 0;
}

int GSETRSENDER::Lv4MsgSend(uint8_t data[], int dataLen, CUSMSG &sendBuf)
{
    if(dataLen > 7){
        return -1;
    }
    #ifdef DEBUG
    Serial.println("========验证+加密级别消息发送=========");
    Serial.print("原始内容：");
    PrintBuffer(data,dataLen);
    #endif
    int outLen;
    // unsigned char buffer[25]={0,0,0,0,0,0,0,0,0,0};
    memset(buffer+2,0,8*sizeof(uint8_t));
    buffer[0] = info->CTR&0xff;
    buffer[1] = (info->CTR>>8)&0xff;
    ByteCopy(data,dataLen,buffer+2);
    Mac(buffer,9,info->K_sess,buffer+9,outLen);
    buffer[1] = buffer[9];
    #ifdef DEBUG
    Serial.print("AUTHpm：0x");
    Serial.println(buffer[9],HEX);
    #endif
    ASCONEncrypt(buffer+1,8,info->K_sess,sendBuf.data,sendBuf.len);
    sendBuf.id.SetMID(info->MID);
    sendBuf.id.SetMTYPE(MTYPE::NORMAL);
    sendBuf.id.SetSTYPE(STYPE::ENCAUTH);
    info->IncreaseCTR();
    this->preMsg = sendBuf;
    this->authDMFlag = true;
    #ifdef DEBUG
    Serial.print("发送内容：");
    PrintBuffer(sendBuf.data,sendBuf.len);
    Serial.println("====================================");
    #endif
    return 0;
}

int GSETRSENDER::AuthMsgSend(CUSMSG &sendBuf)
{ 
    if(!authDMFlag){
        return -1;
    }
    #ifdef DEBUG
    Serial.println("===========消息验证码发送============");
    #endif
    int outLen;
    // unsigned char buffer[26];
    buffer[0] = info->CTR&0xff;
    buffer[1] = (info->CTR>>8)&0xff;
    ByteCopy(preMsg.data,preMsg.len,buffer+2);
    Mac(buffer,preMsg.len+2,info->K_sess,buffer+10,outLen);
    ByteCopy(buffer+10,8,sendBuf.data);
    sendBuf.len=8;
    sendBuf.id.SetMID(info->MID);
    sendBuf.id.SetMTYPE(MTYPE::AUTHDM);
    sendBuf.id.SetSTYPE(STYPE::ENCAUTH);
    info->IncreaseCTR();
    authDMFlag = false;
    #ifdef DEBUG
    Serial.print("发送内容：");
    PrintBuffer(sendBuf.data,sendBuf.len);
    Serial.println("====================================");
    #endif
    return 0;
}

GSETRRECVER::GSETRRECVER(INFO *info)
{
    this->info = info;
    authDMFlag = false;
}

int GSETRRECVER::Lv1MsgRecv(CUSMSG recvBuf, uint8_t out[], int &outLen)
{
    
    if(recvBuf.len < 0){
        return -1;
    }
    #ifdef DEBUG
    Serial.println("==========无操作级别消息接收==========");
    Serial.print("接收内容：");
    PrintBuffer(recvBuf.data,recvBuf.len);
    #endif
    ByteCopy(recvBuf.data,recvBuf.len,out);
    outLen = recvBuf.len;
    preMsg = recvBuf;
    authDMFlag = true;
    #ifdef DEBUG
    Serial.print("还原内容：");
    PrintBuffer(out,outLen);
    Serial.println("====================================");
    #endif
    return 0;
}

int GSETRRECVER::Lv2MsgRecv(CUSMSG recvBuf, uint8_t out[], int &outLen)
{
    
    if(recvBuf.len<0){
        return -1;
    }
    #ifdef DEBUG
    Serial.println("==========仅验证级别消息接收==========");
    Serial.print("接收内容：");
    PrintBuffer(recvBuf.data,recvBuf.len);
    #endif
    // unsigned char buffer[25]={0};
    buffer[0] = info->CTR&0xff;
    buffer[1] = (info->CTR>>8)&0xff;
    ByteCopy(recvBuf.data+1,recvBuf.len-1,buffer+2);
    Mac(buffer,recvBuf.len+1,info->K_sess,buffer+9,outLen);
    #ifdef DEBUG
    Serial.print("AUTHpm：0x");
    Serial.println(buffer[9],HEX);
    #endif
    if(buffer[9]!=recvBuf.data[0]){
        outLen = 0;
        return -1;
    }
    ByteCopy(recvBuf.data+1,recvBuf.len-1,out);
    outLen = recvBuf.len-1;
    info->IncreaseCTR();
    preMsg = recvBuf;
    authDMFlag = true;
    #ifdef DEBUG
    Serial.print("还原内容：");
    PrintBuffer(out,outLen);
    Serial.println("====================================");
    #endif
    return 0;
}

int GSETRRECVER::Lv3MsgRecv(CUSMSG recvBuf, uint8_t out[], int &outLen)
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
    preMsg = recvBuf;
    authDMFlag = true;
    #ifdef DEBUG
    Serial.print("还原内容：");
    PrintBuffer(out,outLen);
    Serial.println("====================================");
    #endif
    return 0;
}

int GSETRRECVER::Lv4MsgRecv(CUSMSG recvBuf, uint8_t out[], int &outLen)
{
    
    if(recvBuf.len < 8){
        return -1;
    }
    #ifdef DEBUG
    Serial.println("========验证+加密级别消息接收=========");
    Serial.print("接收内容：");
    PrintBuffer(recvBuf.data,recvBuf.len);
    #endif
    // unsigned char buffer[25];
    ASCONDecrypt(recvBuf.data,8,info->K_sess,buffer+1,outLen);
    uint8_t auth = buffer[1];
    buffer[0] = info->CTR&0xff;
    buffer[1] = (info->CTR>>8)&0xff;
    Mac(buffer,9,info->K_sess,buffer+9,outLen);
    #ifdef DEBUG
    Serial.print("AUTHpm：0x");
    Serial.println(buffer[9],HEX);
    #endif
    if(buffer[9]!=auth){
        outLen = 0;
        #ifdef DEBUG
        Serial.println("验证失败！");
        Serial.println("====================================");
        #endif
        return -1;
    }
    ByteCopy(buffer+2,7,out);
    outLen = 7;
    info->IncreaseCTR();
    preMsg = recvBuf;
    authDMFlag = true;
    #ifdef DEBUG
    Serial.print("还原内容：");
    PrintBuffer(out,outLen);
    Serial.println("====================================");
    #endif
    return 0;
}

int GSETRRECVER::AuthMsgRecv(CUSMSG recvBuf)
{
    
    if(!authDMFlag || recvBuf.len < 8 ){
        return -1;
    }
    #ifdef DEBUG
    Serial.println("===========消息验证码接收============");
    Serial.print("接收内容：");
    PrintBuffer(recvBuf.data,recvBuf.len);
    #endif
    int outLen;
    // unsigned char buffer[26];
    buffer[0] = info->CTR&0xff;
    buffer[1] = (info->CTR>>8)&0xff;
    ByteCopy(preMsg.data,preMsg.len,buffer+2);
    Mac(buffer,preMsg.len+2,info->K_sess,buffer+10,outLen);
    #ifdef DEBUG
    Serial.print("mid:");
    Serial.print(preMsg.id.GetMID());
    Serial.print("  body:");
    PrintBuffer(preMsg.data,preMsg.len);
    #endif
    if(!ByteCmp(buffer+10,recvBuf.data,8)) {
        #ifdef DEBUG
        Serial.println("验证失败！");
        Serial.println("====================================");
        #endif
        return -2;
    }
    info->IncreaseCTR();
    authDMFlag = false;
    #ifdef DEBUG
    Serial.println("验证成功！");
    #endif
    #ifdef DEBUG
    Serial.println("====================================");
    #endif
    return 0;
}
int GSETRRECVER::SwitchMsg(CUSMSG recvBuf, uint8_t out[], int &outLen)
{
    uint8_t mid = recvBuf.id.GetMID();
    if(mid != info->MID){
        return -3;
    }
    STYPE stype = recvBuf.id.GetSTYPE();
    MTYPE mtype = recvBuf.id.GetMTYPE();
    if(mtype == MTYPE::NORMAL){
        switch (stype)
        {
        case STYPE::NONE:
            return Lv1MsgRecv(recvBuf,out,outLen);
            break;
        case STYPE::AUTHONLY:
            return Lv2MsgRecv(recvBuf,out,outLen);
            break;
        case STYPE::ENCONLY:
            return Lv3MsgRecv(recvBuf,out,outLen);
            break;
        case STYPE::ENCAUTH:
            return Lv4MsgRecv(recvBuf,out,outLen);
            break;
        default:
            return -1;
        }
    }
    if(mtype==MTYPE::AUTHDM&&stype==STYPE::ENCAUTH){
        return AuthMsgRecv(recvBuf);
    }
    return 0;
}
void GSETRSelfTest()
{
    unsigned char k[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    INFO info1(0x111),info2(0x111);
    ByteCopy(k,SESS_KEY_SIZE,info1.K_sess);
    ByteCopy(k,SESS_KEY_SIZE,info2.K_sess);
    GSETRSENDER sender(&info1);
    GSETRRECVER recver(&info2);
    CUSMSG msg1;
    unsigned char buffer1[8] = {1,2,3,4};
    unsigned char buffer2[8] = {0};
    
    int outLen;
    Serial.println("Lv1");
    sender.Lv1MsgSend(buffer1,7,msg1);
    PrintBuffer(msg1.data,msg1.len);
    recver.Lv1MsgRecv(msg1,buffer2,outLen);
    PrintBuffer(buffer2,outLen);

    Serial.println("Lv2");
    sender.Lv2MsgSend(buffer1,7,msg1);
    PrintBuffer(msg1.data,msg1.len);
    recver.Lv2MsgRecv(msg1,buffer2,outLen);
    PrintBuffer(buffer2,outLen);

    Serial.println("Lv3");
    sender.Lv3MsgSend(buffer1,7,msg1);
    PrintBuffer(msg1.data,msg1.len);
    recver.Lv3MsgRecv(msg1,buffer2,outLen);
    PrintBuffer(buffer2,outLen);

    Serial.println("Lv4");
    sender.Lv4MsgSend(buffer1,7,msg1);
    PrintBuffer(msg1.data,msg1.len);
    recver.Lv4MsgRecv(msg1,buffer2,outLen);
    PrintBuffer(buffer2,outLen);

    Serial.println("auth");
    sender.AuthMsgSend(msg1);
    PrintBuffer(msg1.data,msg1.len);
    Serial.println(recver.AuthMsgRecv(msg1));

}