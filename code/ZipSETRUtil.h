#ifndef ZIPSETRUTIL_H
#define ZIPSETRUTIL_H
#include "CustomizeCAN.h"
#include "ZipSETR.h"
bool KdynDistriStart(CCAN &ccan,ZIPENCSENDER &sender);
int ZipMsgSendUtil(unsigned char data[],int dataLen, CCAN &ccan,ZIPENCSENDER *zipSender,GSETRSENDER *gSender=nullptr);
int KdynDistriSUtil(CUSMSG msg,ZIPENCSENDER &sender);
int KdynDistriRUtil(CUSMSG msg,CCAN &ccan,ZIPENCRECVER &recver);
int ZipMsgRecvUtil(CUSMSG msg, unsigned char out[],int &outLen,ZIPENCRECVER *zipRecver,GSETRRECVER *gRecver=nullptr);

#endif ZIPSETRUTIL_H