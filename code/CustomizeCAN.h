#ifndef CUSTOMIZECAN_H
#define CUSTOMIZECAN_H
#include "ACAN2515.h"

enum class STYPE{
    NONE = 0,
    AUTHONLY = 1,
    ENCONLY = 2,
    ENCAUTH = 3
};
enum class MTYPE{
    NORMAL = 0,
    AUTHDM = 1
};
enum class MSGTYPE {
    PLAIN,
    AUTHONLY,
    ENCONLY,
    AUTHENC,
    KEYEX,
    ZIPENC,
    ZIPKEYEX,
    AUTHDM
};
class CUSTID{
private:
    uint32_t rawID;
    bool extFlag;
public:
    CUSTID();
    ~CUSTID(){}
    void SetMID(uint8_t mid);
    void SetSTYPE(STYPE stype);
    void SetMTYPE(MTYPE mtype);
    void SetMSGTYPE(MSGTYPE msgtype);
    void SetExtFlag(bool extFlag);
    void SetExtID(uint32_t ext);
    void SetRawID(uint32_t rawID,bool extFlag);
    uint32_t GetRawID();
    bool GetExtState();
    uint8_t GetMID();
    STYPE GetSTYPE();
    MTYPE GetMTYPE();
    MSGTYPE GETMSGTYPE();
    uint32_t GetExtID();
    int SetExtVal(int pos, int len, uint32_t val);
    int GetExtVal(int pos, int len, uint32_t &val);
};
class CUSMSG{
public:
    CUSTID id;
    union {
        uint64_t data64        ; // Caution: subject to endianness
        int64_t  data_s64      ; // Caution: subject to endianness
        uint32_t data32    [2] ; // Caution: subject to endianness
        int32_t  data_s32  [2] ; // Caution: subject to endianness
        float    dataFloat [2] ; // Caution: subject to endianness
        uint16_t data16    [4] ; // Caution: subject to endianness
        int16_t  data_s16  [4] ; // Caution: subject to endianness
        int8_t   data_s8   [8] ;
        uint8_t  data      [8] = {0, 0, 0, 0, 0, 0, 0, 0} ;
     };
    int len;
    void CANMsg2CusMsg(CANMessage frame);
    void CusMsg2CANMsg(CANMessage &frame);
};

class CCAN {
private:
    byte MCP2515_CS; // CS input of MCP2515 (adapt to your design) 
    byte MCP2515_INT; // INT output of MCP2515 (adapt to your design)
public:
    static ACAN2515 *can ;
    CCAN(byte MCP2515_CS,byte MCP2515_INT);
    CCAN();
    ~CCAN();
    void CanBegin();
    bool CanSend(CUSMSG cusMsg);
    bool CanRecv(CUSMSG &cusMsg);
    bool CanAvailable();
};
#endif // CUSTOMIZECAN_H