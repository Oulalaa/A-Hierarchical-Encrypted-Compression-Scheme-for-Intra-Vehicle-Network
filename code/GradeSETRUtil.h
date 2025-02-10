#ifndef GRADESETRUTIL_H
#define GRADESETRUTIL_H
#include "GradeSETR.h"
#include "CustomizeCAN.h"
bool NodeAuth2Start(CCAN &ccan,NODEAUTH2 &nodeAuth2);
bool NodeAuthNStart(CCAN &ccan,NODEAUTHN &nodeAuthN);
int MsgSendUtil(unsigned char data[],int dataLen,MSGTYPE msgtype,bool authDMFlag, CCAN &ccan,GSETRSENDER &sender);
int AuthDMSendUtil(CCAN &ccan,GSETRSENDER &sender);
int NodeAuth2SUtil(CUSMSG msg,CCAN &ccan,NODEAUTH2 &nodeAuth2);
int NodeAuth2RUtil(CUSMSG msg,CCAN &ccan,NODEAUTH2 &nodeAuth2);
int NodeAuthNSUtil(CUSMSG msg,CCAN &ccan,NODEAUTHN &nodeAuthN);
int NodeAuthNRUtil(CUSMSG msg,CCAN &ccan,NODEAUTHN &nodeAuthN);
int MsgRecvUtil(CUSMSG msg, unsigned char out[],int &outLen,GSETRRECVER &recver);
#endif // GRADESETRUTIL_H