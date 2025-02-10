#include <ASCON.h>
#include "util.h"
#include "CustomizeCAN.h"
#include "GradeSETRUtil.h"
#include "ZipSETRUtil.h"
#include <avr/pgmspace.h>
#define BAUD 38400

unsigned long g_duration;



//——————————————————————————————————————————————————————————————————————————————
//   SETUP
//——————————————————————————————————————————————————————————————————————————————
static uint32_t gBlinkLedDate = 0 ;

//uno
CCAN ccan(10,2);
// mega
//CCAN ccan(53,2);
INFO infoN(0xa);
NODEAUTHN authN(&infoN);
GSETRSENDER sender(&infoN);
ZIPENCSENDER zipSender(&infoN);
unsigned char Kpre[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t listN[2] = {2,10};

union DATA
{
  uint64_t  data64 = 0;
  uint8_t   data8[8];
};
//将can消息写入Flash中，使用时动态读取
const uint64_t readData[] PROGMEM = {
  //#include "code_my_76a_ori.h"
  #include "00000257.h"
};
int senderFlag = false;
int cnt = 0;
void sendData(){
  DATA buf;
  int len = sizeof(readData)/8;
  Serial.print("测试消息数量：");
  Serial.println(len);
  Serial.println("开始发送！");
  while (cnt<len)
  {
    memcpy_P(&buf.data64, readData+cnt,sizeof(uint64_t));
    Serial.print("Data[");
    Serial.print(cnt);
    Serial.print("]:");
    PrintBuffer(buf.data8,8);
    ZipMsgSendUtil(buf.data8,8,ccan,&zipSender);
    delay(1000);
    cnt++;
  }
  
}


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
    //SPI.beginTransaction(SPISettings(8000000, MSBFIRST, SPI_MODE0));
    infoN.EID = 1;
    infoN.GECU = 10;
    infoN.SetEIDList(listN,2);
    infoN.LoadKpre(Kpre);
    ccan.CanBegin();
    //初始化随机数种子
    randomSeed(analogRead(0));
    Serial.println("原神，启动！");
    delay(1000);
    
}


void RecvECU1(){
  CUSMSG inmsg; 
  unsigned char out[8];
  int outLen;
  if (ccan.CanAvailable ()) {
    if (!ccan.CanRecv(inmsg))
    {
      Serial.println("recv:err!");
      return;
    }
    int mid = inmsg.id.GetMID();
    MSGTYPE msgtype = inmsg.id.GETMSGTYPE();
    //info对应的消息类型
    if (mid == infoN.MID) //infoN对应的消息类型
    {      
      int ok ;
      switch (msgtype)
      {
      case MSGTYPE::KEYEX:
        ok = NodeAuthNRUtil(inmsg, ccan, authN);
        if(ok == 4){
          delay(1000);
          KdynDistriStart(ccan,zipSender);
        }
        break;
      case MSGTYPE::ZIPKEYEX:
        ok = KdynDistriSUtil(inmsg,zipSender);
        if(ok==3){
          senderFlag = true;
        }
        break;
      default:
        break;
      }
    }
    
  }else{
     //Serial.println("Receive faliure ") ;
  }
}
unsigned char sendMsg[6] = {1,2,3,4,5};
void loop() {
  if (gBlinkLedDate < millis ()) {
    //   gBlinkLedDate += 100;
    digitalWrite (LED_BUILTIN, !digitalRead (LED_BUILTIN)) ;
  }
  RecvECU1();
  if(senderFlag){
    sendData();
  }
  // if(infoN.GetAuthState()&& cnt >=100 && cnt <= 108){
  //   //发消息
  //   MsgSendUtil(sendMsg,6,MSGTYPE(cnt%8),true,ccan,sender);
  //   //delay(2000);
  // }
  // cnt++;
}