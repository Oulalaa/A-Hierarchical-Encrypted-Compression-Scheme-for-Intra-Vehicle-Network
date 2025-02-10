#include <ASCON.h>
#include "util.h"
#include "CustomizeCAN.h"
#include "GradeSETRUtil.h"
#include "ZipSETRUtil.h"
#define BAUD 38400

unsigned long g_duration;

// ——————————————————————————————————————————————————————————————————————————————
//    SETUP
// ——————————————————————————————————————————————————————————————————————————————
static uint32_t gBlinkLedDate = 0;
static uint32_t gReceivedFrameCount = 0;
static uint32_t gSentFrameCount = 0;
// uno
CCAN ccan(10, 2);
// mega
// CCAN ccan(53,2);


INFO infoN(0xa);
NODEAUTHN authN(&infoN);
// GSETRRECVER recver(&infoN);
ZIPENCRECVER zipRecver(&infoN);
unsigned char Kpre[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

uint8_t listN[2] = {10, 1};
void setup()
{

  //--- Switch on builtin led
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, HIGH);
  //--- Start serial
  Serial.begin(BAUD);
  //--- Wait for serial (blink led at 10 Hz during waiting)
  while (!Serial)
  {
    delay(50);
    digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
  }
  //--- Begin SPI
  SPI.begin();
  // SPI.beginTransaction(SPISettings(8000000, MSBFIRST, SPI_MODE0));

  infoN.EID = 2;
  infoN.GECU = 10;
  infoN.SetEIDList(listN, 2);
  infoN.LoadKpre(Kpre);
  ccan.CanBegin();
  // 初始化随机数种子
  randomSeed(analogRead(0));
  Serial.println("原神，启动！");
  // delay(1000);
  // NodeAuth2Start(ccan,auth2);
}

void RecvECU2()
{
  CUSMSG inmsg;
  unsigned char out[8];
  int outLen;
  if (ccan.CanAvailable())
  {
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
        NodeAuthNRUtil(inmsg, ccan, authN);
        break;
      case MSGTYPE::ENCONLY:
      case MSGTYPE::ZIPENC:
        ZipMsgRecvUtil(inmsg,out,outLen,&zipRecver);
        break;
      case MSGTYPE::ZIPKEYEX:
        KdynDistriRUtil(inmsg,ccan,zipRecver);
        break;
      default:
        break;
      }
    }
  }
  else
  {
    // Serial.println("Receive faliure ") ;
  }
}

void loop()
{
  if (gBlinkLedDate < millis())
  {
    //   gBlinkLedDate += 100;
    digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
  }
  // RecvS();
  RecvECU2();
  // delay(1000);
}