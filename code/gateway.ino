#include <ASCON.h>
#include "util.h"
#include "CustomizeCAN.h"
#include "GradeSETRUtil.h"
#define BAUD 38400

unsigned long g_duration;


//——————————————————————————————————————————————————————————————————————————————
//   SETUP
//——————————————————————————————————————————————————————————————————————————————
static uint32_t gBlinkLedDate = 0 ;

CCAN ccan(10,2);

INFO infoN(0xa);
NODEAUTHN authN(&infoN);
GSETRRECVER recver(&infoN);
unsigned char Kpre[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t listN[2] = {1,2};
void setup() {
  
  //--- Switch on builtin led
  pinMode (LED_BUILTIN, OUTPUT) ;
  digitalWrite (LED_BUILTIN, HIGH) ;
  //--- Start serial
  Serial.begin (BAUD) ;
  //--- Wait for serial (blink led at 10 Hz during waiting)
  while (!Serial) {
    delay (50) ;
    digitalWrite (LED_BUILTIN, !digitalRead (LED_BUILTIN)) ;
  }
    //--- Begin SPI
    SPI.begin () ;
    infoN.EID = 10;
    infoN.GECU = 10;
    infoN.SetEIDList(listN,2);
    infoN.LoadKpre(Kpre);
    ccan.CanBegin();
    //初始化随机数种子
    randomSeed(analogRead(0));
    Serial.println("原神，启动！");
    delay(3000);
    // 三节点间的认证
    NodeAuthNStart(ccan,authN);

    
}

void RecvGECU(){
  CUSMSG inmsg; 
  unsigned char out[8];
  int outLen;
  if (ccan.CanAvailable ()) {
    if (!ccan.CanRecv(inmsg))
    {
      Serial.println("recv:err!");
    }
    int mid = inmsg.id.GetMID();
    MSGTYPE msgtype = inmsg.id.GETMSGTYPE();
    if (mid == infoN.MID)
    {
      switch (msgtype)
      {
      case MSGTYPE::KEYEX:
        NodeAuthNSUtil(inmsg, ccan, authN);
        break;
      case MSGTYPE::PLAIN:
      case MSGTYPE::AUTHONLY:
      case MSGTYPE::ENCONLY:
      case MSGTYPE::AUTHENC:
      case MSGTYPE::ZIPENC:
        MsgRecvUtil(inmsg,out,outLen,recver);
        break;
      case MSGTYPE::AUTHDM:
        recver.AuthMsgRecv(inmsg);
        break;
      default:
        break;
      }
    }
    
  }else{
     //Serial.println("Receive faliure ") ;
  }
}

void loop() {
  if (gBlinkLedDate < millis ()) {
    //   gBlinkLedDate += 100;
    digitalWrite (LED_BUILTIN, !digitalRead (LED_BUILTIN)) ;
  }
  RecvGECU();
  
}