#include "GradeSETRUtil.h"
//节省栈空间用，删掉后去掉各函数中对应的注释即可
static CUSMSG msg,sendMsg,sendMsg2,sendMsg3;
static uint32_t step;
bool NodeAuth2Start(CCAN &ccan, NODEAUTH2 &nodeAuth2)
{
    //CUSMSG msg;
    nodeAuth2.AccessAuth2Step1(msg);
    return ccan.CanSend(msg);
}
bool NodeAuthNStart(CCAN &ccan,NODEAUTHN &nodeAuthN)
{
    //CUSMSG msg;
    nodeAuthN.AccessAuthNStep1(msg);
    return ccan.CanSend(msg);

}
int NodeAuth2SUtil(CUSMSG msg, CCAN &ccan, NODEAUTH2 &nodeAuth2)
{
    if(!msg.id.GetExtState()){
        return -1;
    }
    if(msg.id.GetMTYPE()!=MTYPE::AUTHDM || msg.id.GetSTYPE()!=STYPE::NONE){
        return -1;
    }
    //uint32_t step;
    msg.id.GetExtVal(0,3,step);
    //CUSMSG sendMsg;
    switch (step)
    {
    case 1:
        if(nodeAuth2.AccessAuth2Step3(msg,sendMsg)==0&&ccan.CanSend(sendMsg)){
            return 3;
        }
        break;
    case 3:
        if(0==nodeAuth2.AccessAuth2Step5(msg)){
            return 5;
        }
        break;
    default:
        return -1;
        break;
    }
    return -1;
}
int NodeAuthNSUtil(CUSMSG msg, CCAN &ccan, NODEAUTHN &nodeAuthN)
{
    if(!msg.id.GetExtState()){
        return -1;
    }
    
    if(msg.id.GetMTYPE()!=MTYPE::AUTHDM || msg.id.GetSTYPE()!=STYPE::NONE){
        return -1;
    }
    //uint32_t step;
    msg.id.GetExtVal(0,3,step);
    //CUSMSG sendMsg,sendMsg2,sendMsg3;
    int res = 0;
    switch (step)
    {
    case 1:
        res = nodeAuthN.AccessAuthNStep3(msg,sendMsg,sendMsg2,sendMsg3);
        if(res==0){
            res &= ccan.CanSend(sendMsg);
            //delay(500);
            res &= ccan.CanSend(sendMsg2);
            //delay(500);
            res &= ccan.CanSend(sendMsg3);
            if(res){
                return 3;
            }
        }
        break;
    case 3:
        res = nodeAuthN.AccessAuthNStep5(msg);
        if(res == 0){
            return 5;
        }
        break;
    default:
        return -1;
        break;
    }
    if(res == 1){
        return 0;
    }
    return -1;
}
int NodeAuth2RUtil(CUSMSG msg, CCAN &ccan, NODEAUTH2 &nodeAuth2)
{
    if(!msg.id.GetExtState()){
        return -1;
    }
    
    if(msg.id.GetMTYPE()!=MTYPE::AUTHDM || msg.id.GetSTYPE()!=STYPE::NONE){
        return -1;
    }
    //uint32_t step;
    msg.id.GetExtVal(0,3,step);
    //CUSMSG sendMsg;
    bool res = true;
    switch (step)
    {
    case 0:
        if(nodeAuth2.AccessAuth2Step2(msg,sendMsg)==0){
            if(ccan.CanSend(sendMsg)){
                return 2;
            }
        }
        break;
    case 2:
        if(nodeAuth2.AccessAuth2Step4(msg,sendMsg)==0){
            if(ccan.CanSend(sendMsg)){
                return 4;
            }
        }
        break;
    default:
        return -1;
        break;
    }
    return -1;
}
int NodeAuthNRUtil(CUSMSG msg, CCAN &ccan, NODEAUTHN &nodeAuthN)
{
    if(!msg.id.GetExtState()){
        return -1;
    }
    
    if(msg.id.GetMTYPE()!=MTYPE::AUTHDM || msg.id.GetSTYPE()!=STYPE::NONE){
        return -1;
    }
    //uint32_t step;
    msg.id.GetExtVal(0,3,step);
    //CUSMSG sendMsg;
    int res = 0;
    switch (step)
    {
    case 0:
        if(0==nodeAuthN.AccessAuthNStep2(msg,sendMsg)){
            if(ccan.CanSend(sendMsg)){
                return 2;
            }
        }
        break;
    case 2:
        res = nodeAuthN.AccessAuthNStep4(msg,sendMsg);
        if(res == 0&&ccan.CanSend(sendMsg)){
            return 4;
        }
        break;
    default:
        return -1;
        break;
    }
    if(res == 1){
        return 0;
    }
    return -1;
}

int MsgSendUtil(unsigned char data[],int dataLen,MSGTYPE msgtype,bool authDMFlag, CCAN &ccan,GSETRSENDER &sender){
    if(dataLen > 8) {
        return -1;
    }
    CUSMSG msg;
    int ret = 0;
    switch (msgtype)
    {
    case MSGTYPE::PLAIN:
        ret = sender.Lv1MsgSend(data,dataLen,msg);
        break;
    case MSGTYPE::AUTHONLY:
        ret = sender.Lv2MsgSend(data,dataLen,msg);
        break;
    case MSGTYPE::ENCONLY:
        ret = sender.Lv3MsgSend(data,dataLen,msg);
        break;
    case MSGTYPE::AUTHENC:
        ret = sender.Lv4MsgSend(data,dataLen,msg);
        break;
    case MSGTYPE::ZIPENC:
        //ret = sender.Lv1MsgSend(data,dataLen,msg);
        return -1;
        break;
    default:
        return -1;
        break;
    }
    if(ret != 0){
        return ret;
    }
    if(!ccan.CanSend(msg)){
        return -1;
    }
    if(authDMFlag){
        if(0 != sender.AuthMsgSend(msg)){
            return -1;
        }
        //delay(1000);
        if(!ccan.CanSend(msg)){
            return -1;
        }
    }
    return 0;
}
int AuthDMSendUtil(CCAN &ccan,GSETRSENDER &sender){
    CUSMSG msg;
    if(0 != sender.AuthMsgSend(msg)){
            return -1;
    }
    if(!ccan.CanSend(msg)){
        return -1;
    }
    return 0;
}
int MsgRecvUtil(CUSMSG msg, unsigned char out[],int &outLen,GSETRRECVER &recver){
    MSGTYPE msgtype = msg.id.GETMSGTYPE();
    int res = 0;
    switch (msgtype)
    {
    case MSGTYPE::PLAIN:
        return recver.Lv1MsgRecv(msg,out,outLen);
        break;
    case MSGTYPE::AUTHONLY:
        return recver.Lv2MsgRecv(msg,out,outLen);
        break;
    case MSGTYPE::ENCONLY:
        return recver.Lv3MsgRecv(msg,out,outLen);
        break;
    case MSGTYPE::AUTHENC:
        return recver.Lv4MsgRecv(msg,out,outLen);
        break;
    case MSGTYPE::ZIPENC:
        //return recver.Lv1MsgRecv(msg,out,outLen);
        break;
    default:
        return -1;
        break;
    }
    return -1;
}