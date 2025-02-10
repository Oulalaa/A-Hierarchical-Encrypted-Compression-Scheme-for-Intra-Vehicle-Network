#include "CustomizeCAN.h"
#include "Arduino.h"
#include "SPI.h"
#include "util.h"
#define SET_BITS(dst, start, width, value) \
    do { \
        uint32_t mask = (((1ULL << ((width))) - 1) << ((start))); \
        (dst) = ((dst) & ~(mask)) | ((((value)*1ULL) << ((start))) & (mask)); \
    } while(0)
#define MASK(LEN) ((((1ULL << (LEN)) - 1)))
ACAN2515 *CCAN::can;
//配置信息改这里
static void receive0 (const CANMessage & inMessage) {
    Serial.println();
    Serial.println ("Function_Receive0 ") ;
}
static void receive1 (const CANMessage & inMessage) {
  Serial.println();
 Serial.println ("Function_Receive1") ;
}
static void receive2 (const CANMessage & inMessage) {
    Serial.println();
    Serial.println ("Function_Receive2") ;
}
static uint32_t QUARTZ_FREQUENCY = 16UL * 1000UL * 1000UL ; // 16 MHz
const ACAN2515Mask rxm0 = extended2515Mask (0x1FE00000) ; // For filter #0 and #1
const ACAN2515Mask rxm1 = standard2515Mask (0x7F8, 0x00, 0) ; // For filter #2 to #5
const ACAN2515AcceptanceFilter filters [] = {
    {extended2515Filter (0x1E00000), receive0},
    {extended2515Filter (0x1400000), receive1},
    {standard2515Filter (0xa<<3, 0x55, 0), receive2}
} ;

CUSTID::CUSTID()
{
    this->rawID=0;
    extFlag = false;
}


void CUSTID::SetMID(uint8_t mid)
{
    if(extFlag){
        SET_BITS(rawID,21,8,mid);
    }else{
        SET_BITS(rawID,3,8,mid);
    }
}

void CUSTID::SetSTYPE(STYPE msgtype)
{
    if(extFlag){
        SET_BITS(rawID,18,2,(int)msgtype);
    }else{
        SET_BITS(rawID,0,2,(int)msgtype);
    }
}
void CUSTID::SetMSGTYPE(MSGTYPE idtype)
{
    if(extFlag){
        SET_BITS(rawID,18,3,(int)idtype);
    }else{
        SET_BITS(rawID,0,3,(int)idtype);
    }
}

void CUSTID::SetMTYPE(MTYPE mtype)
{
    if(extFlag){
        SET_BITS(rawID,20,1,(int)mtype);
    }else{
        SET_BITS(rawID,2,1,(int)mtype);
    }
}

void CUSTID::SetExtFlag(bool extFlag)
{
    if(this->extFlag == extFlag){
        return;
    }
    if(extFlag){
        rawID <<= 18;
    }else{
        rawID >>= 18;
    }
    this->extFlag = extFlag;
}

void CUSTID::SetExtID(uint32_t ext)
{
    SetExtFlag(true);
    SET_BITS(rawID,0,18,ext);
}

void CUSTID::SetRawID(uint32_t rawID, bool extFlag)
{
    this->SetExtFlag(extFlag);
    this->rawID = rawID;
}

uint32_t CUSTID::GetRawID()
{
    return this->rawID;
}

bool CUSTID::GetExtState()
{
    return extFlag;
}

uint8_t CUSTID::GetMID()
{
    if(extFlag){
        return rawID>>21;
    }
    return rawID>>3;
}

STYPE CUSTID::GetSTYPE()
{
    if(extFlag){
        return STYPE((rawID>>18)&0x3UL) ;
    }
    return STYPE(rawID&0x3UL);
}

MTYPE CUSTID::GetMTYPE()
{
    if(extFlag){
        return MTYPE((rawID>>20)&0x1UL);
    }
    return MTYPE((rawID>>2)&0x1UL);
}
MSGTYPE CUSTID::GETMSGTYPE()
{
    if(extFlag){
        return MSGTYPE((rawID>>18)&0x7UL) ;
    }
    return MSGTYPE(rawID&0x7UL);
}
uint32_t CUSTID::GetExtID()
{
    if(extFlag){
        return rawID&0x3ffffUL;
    }
    return 0;
}

int CUSTID::SetExtVal(int pos, int len, uint32_t val)
{
    if(!extFlag){
        return -1;
    }
    //位置超了
    if(pos < 0 || len <= 0 || pos + len > 18){
        return -1;
    }
    SET_BITS(rawID,pos,len,val);
    return 0;
}

int CUSTID::GetExtVal(int pos, int len, uint32_t &val)
{
    if(!extFlag){
        return -1;
    }
    //位置超了
    if(pos < 0 || len <= 0 || pos + len > 18){
        return -1;
    }
    val = (rawID >> pos)&MASK(len);
    return 0;
}

CCAN::CCAN(byte MCP2515_CS, byte MCP2515_INT)
{
    this->MCP2515_CS = MCP2515_CS;
    this->MCP2515_INT = MCP2515_INT;
    this->can = new ACAN2515(MCP2515_CS, SPI, MCP2515_INT) ;
}

CCAN::CCAN()
{
    this->MCP2515_CS = 10;
    this->MCP2515_INT = 2;
    this->can =new ACAN2515(MCP2515_CS, SPI, MCP2515_INT) ;
}

CCAN::~CCAN()
{
    can->end();
    delete can;
}

void CCAN::CanBegin()
{  
    ACAN2515Settings settings (QUARTZ_FREQUENCY, 125UL * 1000UL) ; // CAN bit rate 125 kb/s
    settings.mRequestedMode = ACAN2515Settings::NormalMode ; // Select NormalMode
    const uint32_t errorCode = can->begin (settings,   [] { CCAN::can->isr () ; }, rxm0, rxm1, filters, 3) ;
    if (errorCode != 0) {
      Serial.print ("Configuration error 0x") ;
      Serial.println (errorCode, HEX) ;
     }
}

bool CCAN::CanSend(CUSMSG cusMsg)
{
    CANMessage frame;
    cusMsg.CusMsg2CANMsg(frame);
    return can->tryToSend(frame);
}

bool CCAN::CanRecv(CUSMSG &cusMsg)
{   
    CANMessage frame;
    bool flag = can->receive(frame);
    if(!flag){
        return flag;
    }
    cusMsg.CANMsg2CusMsg(frame);
    return flag;
}

bool CCAN::CanAvailable()
{
    return can->available();
}

void CUSMSG::CANMsg2CusMsg(CANMessage frame)
{
    this->id.SetRawID(frame.id,frame.ext);
    ByteCopy(frame.data,frame.len,this->data);
    this->len=frame.len;
}

void CUSMSG::CusMsg2CANMsg(CANMessage &frame)
{
    frame.id = id.GetRawID() ;
    frame.ext = id.GetExtState() ;
    ByteCopy(this->data,len,frame.data);
    frame.len = len ;
}

