#include "ZipSETRUtil.h"
static CUSMSG msg,sendMsg;
static uint32_t step;
bool KdynDistriStart(CCAN &ccan, ZIPENCSENDER &sender)
{
    CUSMSG msg;
    sender.KdynDistriStep1(msg);
    return ccan.CanSend(msg);
}

int ZipMsgSendUtil(unsigned char data[], int dataLen, CCAN &ccan, ZIPENCSENDER *zipSender, GSETRSENDER *gSender)
{
    if(dataLen > 8) {
        return -1;
    }
    // CUSMSG msg;
    int ret = zipSender->ZipEncSend(data,dataLen,msg,gSender);
    if(ret != 0){
        return ret;
    }
    if(!ccan.CanSend(msg)){
        return -1;
    }
    return 0;
}

int KdynDistriSUtil(CUSMSG msg, ZIPENCSENDER &sender)
{
    if(!msg.id.GetExtState()){
        return -1;
    }
    if(msg.id.GETMSGTYPE()!=MSGTYPE::ZIPKEYEX){
        return -1;
    }
    
    msg.id.GetExtVal(0,3,step);
    int res = 0;
    if(step != 1){
        return -1;
    }
    res = sender.KdynDistriStep3(msg);
    if(res == 0){
        return 3;
    }else if(res == 1){
        return 0;
    }
    return -1;
}

int KdynDistriRUtil(CUSMSG msg, CCAN &ccan, ZIPENCRECVER &recver)
{
    if(!msg.id.GetExtState()){
        return -1;
    }
    if(msg.id.GETMSGTYPE()!=MSGTYPE::ZIPKEYEX){
        return -1;
    }
    msg.id.GetExtVal(0,3,step);
    if(step == 0&&recver.KdynDistriStep2(msg,sendMsg)==0&&ccan.CanSend(sendMsg)){
        return 2;
    }
    return -1;
}

int ZipMsgRecvUtil(CUSMSG msg, unsigned char out[], int &outLen, ZIPENCRECVER *zipRecver, GSETRRECVER *gRecver)
{
    MSGTYPE msgtype = msg.id.GETMSGTYPE();
    int res = 0;
    switch (msgtype)
    {
    case MSGTYPE::ENCONLY:
    case MSGTYPE::ZIPENC:
        return zipRecver->ZipEncRecv(msg,out,outLen,gRecver);
        break;
    default:
        return -1;
        break;
    }
    return -1;
}
