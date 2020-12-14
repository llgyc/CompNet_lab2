/** 
 * @file socket.h
 * @author Yuchen Gu <llgyc@pku.edu.cn>
 * @brief
 */

#ifndef __TINYTCP_TCP_H__
#define __TINYTCP_TCP_H__

#include <list>
#include <queue>

#include "packetio.h"
#include "ip.h"

namespace tinytcp {
namespace tcp {

const uint8_t PTCL = 0x06;

typedef uint16_t PortType; /* big endian */

/************************    TCP Header    ***************************
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

**********************************************************************/

struct __attribute__((packed)) header {
    PortType srcPort;
    PortType dstPort;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset;
    uint8_t control;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
    /* TODO: Options */
};

enum {
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20
};

const size_t MAXSEGMENTSIZE = eth::MAXFRAMELEN - sizeof(ip::header) - sizeof(tcp::header);

struct Segment {
    tcp::header hd;
    ip::addr_t srcAddr, dstAddr;
    uint16_t length; /* little endian */
    uint8_t *data;
    ~Segment();
};


/*********************    TCP Pseudo Header    ************************
                +--------+--------+--------+--------+
                |           Source Address          |
                +--------+--------+--------+--------+
                |         Destination Address       |
                +--------+--------+--------+--------+
                |  zero  |  PTCL  |    TCP Length   |
                +--------+--------+--------+--------+
**********************************************************************/

struct __attribute__((packed)) pseudoheader {
    ip::addr_t srcAddr;
    ip::addr_t dstAddr;
    uint8_t zero;
    uint8_t PTCL;
    uint16_t length; /* big endian */
};

struct SocketIdent {
    ip::addr_t addr;
    PortType port;
    SocketIdent();
    SocketIdent(ip::addr_t _addr, PortType _port);
    friend bool operator == (const SocketIdent &id1, const SocketIdent &id2);
};

struct SocketPairIdent {
    SocketIdent src, dst;
    SocketPairIdent();
    SocketPairIdent(ip::addr_t srcAddr, PortType srcPort,
        ip::addr_t dstAddr, PortType dstPort);
    SocketPairIdent(const SocketIdent &id1, const SocketIdent &id2);
    friend bool operator == (const SocketPairIdent &id1, const SocketPairIdent &id2);
};

struct TCB;

struct Socket {
    SocketIdent id;
    enum {
        UNSPEC,
        ACTIVE,
        PASSIVE
    } type;
    TCB *tcb;
    int backlog;
    std::queue<TCB *> incomingRequest;
    Socket();
};

struct SequenceNumber {
    uint32_t seq, init; /* little endian */
    SequenceNumber();
    SequenceNumber(const uint32_t &_seq);
    SequenceNumber(const uint32_t &_seq, const uint32_t &_init);
    friend bool operator < (const SequenceNumber &s1, const SequenceNumber &s2);
    friend bool operator <= (const SequenceNumber &s1, const SequenceNumber &s2);
    friend bool operator == (const SequenceNumber &s1, const SequenceNumber &s2);
    friend SequenceNumber operator + (const SequenceNumber &s, uint32_t delta);
    operator uint32_t();
};

const size_t MAXQUEUESIZE = 512; /* Bandwidth ~ 512KB/s */

struct SendQueue {
    uint32_t ISS;
    pthread_t timer;
    pthread_cond_t message_cond;
    pthread_cond_t queue_cond;
    pthread_condattr_t message_condattr;
    pthread_mutex_t timer_thread_mutex;
    pthread_mutex_t message_mutex;
    pthread_mutex_t queue_mutex;
    SequenceNumber SND_UNA, SND_NXT;
    std::list<Segment *> Q;
    SendQueue();
    ~SendQueue();
    void addQueueAndSend(Segment *seg);
    void ackSegment(SequenceNumber seq);
    void flushQueue();
    bool empty();
};


void sendSegment(Segment *seg);

const size_t BUFSIZE = 1024 * 1024; /* 1MB buffer for each connection */

struct ReceiveBuffer {
    uint32_t IRS;
    SequenceNumber RCV_NXT;
    char *buf, *now;
    ReceiveBuffer();
    int read(char *data, int len);
    int write(char *data, int len);
};

struct TimeoutInfo {
    TCB *tcb;
    pthread_mutex_t *mutex;
    pthread_cond_t *cond;
};

struct TCB {
    SocketPairIdent sp;
    enum STATE {
        LISTEN,
        SYN_SENT,
        SYN_RECEIVED,
        ESTABLISHED,
        FIN_WAIT_1,
        FIN_WAIT_2,
        CLOSE_WAIT,
        CLOSING,
        LAST_ACK,
        TIME_WAIT,
        CLOSED
    } state;
    SendQueue *sq;
    ReceiveBuffer *rb;
    pthread_mutex_t *timeout_mutex;
    pthread_cond_t *timeout_cond;
    void processSegment(const void *buf, int len);
    void processSegment_CLOSED(const void *buf, int len);
    void processSegment_LISTEN(const void *buf, int len);
    void processSegment_SYN_SENT(const void *buf, int len);
    void processSegment_OTHERWISE(const void *buf, int len);
    int send(void *buf, size_t nbyte);
    int receive(void *buf, size_t nbyte);
    void close();
    TCB(const SocketPairIdent &_sp);
    ~TCB();
};

enum MessageType {
    RESET = 0x01,
    REFUSED = 0x02,
    SEND_OK = 0x04,
    CLOSE_OK = 0x08,
    CLOSING = 0x10,
    RECV_OK = 0x20,
    CONN_OK = 0x40
};

void init();
void LOCK();
void UNLOCK();
void SIGNAL();
void WAIT();
void MESSAGE(MessageType m, TCB *);
int READMESSAGE();
TCB *READMESSAGESENDER();

Segment *newSegment(SocketPairIdent id, uint8_t control, SequenceNumber seq,
    SequenceNumber ack = SequenceNumber(), char *buf = NULL, int len = 0);
    
void setSocketMap(SocketIdent id, Socket *sock);
void setTCBMap(SocketPairIdent id, TCB *tcb);

}
}

#endif
