#include <map>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "../inc/tcp.h"
#include "../inc/helper.h"

namespace tinytcp {
namespace tcp {

static pthread_mutex_t protocol_stack_mutex;
static pthread_cond_t protocol_stack_cond;
static int protocol_stack_message;
static TCB* protocol_stack_message_sender;

std::vector<std::pair<SocketIdent, Socket *> > id2socket;

std::vector<std::pair<SocketPairIdent, TCB *> > id2conn;

int isSocketExist(const SocketIdent &ident) {
    for (size_t i = 0; i < id2socket.size(); i++) {
        if (id2socket[i].first == ident || 
            (id2socket[i].first.port == ident.port && 
             id2socket[i].first.addr == (uint32_t)INADDR_ANY))
            return i;
    }
    return -1;
}

int isSocketPairExist(const SocketPairIdent &ident) {
    for (size_t i = 0; i < id2conn.size(); i++) {
        if (id2conn[i].first == ident)
            return i;
    }
    return -1;
}

uint32_t calcControlLength(uint8_t control) {
    uint32_t ret = 0;
    if (control & SYN) ret++;
    if (control & FIN) ret++;
    return ret;
}

uint32_t calcSegmentLength(Segment *seg) {
    uint32_t ret = seg->length - sizeof(tcp::header);
    ret += calcControlLength(seg->hd.control);
    return ret;
}

uint32_t calcSegmentLength(tcp::header *hd, int len) {
    uint32_t ret = len - sizeof(tcp::header);
    ret += calcControlLength(hd->control);
    return ret;
}

void TCPSegmentCallback(ip::addr_t src, ip::addr_t dst,
    const void *buf, int len) {
    struct header *hd = (struct header *)buf;
    int ret;
    
    LOCK();
    /* Connection already set up ? */
    struct SocketPairIdent sockpair(src, hd->srcPort, dst, hd->dstPort);
    if ((ret = isSocketPairExist(sockpair)) >= 0) {
        id2conn[ret].second->processSegment(buf, len);
        UNLOCK();
        return;
    }
    /* Listen socket set up ? */
    struct SocketIdent sock(dst, hd->dstPort);
    if ((ret = isSocketExist(sock)) >= 0) {
        struct Socket *sptr = id2socket[ret].second;
        if ((int)sptr->incomingRequest.size() >= sptr->backlog)
            fprintf(stderr, "[WARNING] Too many incoming connections.\n");
        else {
            struct TCB *tcb = new TCB(sockpair);
            tcb->state = TCB::STATE::LISTEN;
            sptr->incomingRequest.push(tcb);
            tcb->processSegment(buf, len);
            id2conn.push_back(std::make_pair(sockpair, tcb));
            SIGNAL();
        }
        UNLOCK();
        return;
    }
    
    /* Reset signal ? */
    /*
      If the state is CLOSED (i.e., TCB does not exist) then

      all data in the incoming segment is discarded.  An incoming
      segment containing a RST is discarded.  An incoming segment not
      containing a RST causes a RST to be sent in response.  The
      acknowledgment and sequence field values are selected to make the
      reset sequence acceptable to the TCP that sent the offending
      segment.

      If the ACK bit is off, sequence number zero is used,

        <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

      If the ACK bit is on,

        <SEQ=SEG.ACK><CTL=RST>

      Return.
    */
    if (!(hd->control & RST)) {
        struct SocketPairIdent rsockpair(dst, hd->dstPort, src, hd->srcPort);
        if (hd->control & ACK) {
            Segment *seg = newSegment(rsockpair, RST, hd->ack);
            sendSegment(seg);
            delete seg;
        } else {
            Segment *seg = newSegment(rsockpair, RST|ACK, (uint32_t)0, 
                SequenceNumber(hd->seq) + calcSegmentLength(hd, len));
            sendSegment(seg);
            delete seg;
        }
    }
    UNLOCK();
    return;
}

Segment::~Segment() {
    if (data) delete [] data;
}

SocketIdent::SocketIdent(ip::addr_t _addr, PortType _port)
    : addr(_addr), port(_port) {}
    
bool operator == (const SocketIdent &id1, const SocketIdent &id2) {
    return id1.addr == id2.addr && id1.port == id2.port;        
}

SocketIdent::SocketIdent() { addr = 0; port = 0; }

SocketPairIdent::SocketPairIdent() {}
    
SocketPairIdent::SocketPairIdent(ip::addr_t srcAddr, PortType srcPort,
    ip::addr_t dstAddr, PortType dstPort)
    : src(srcAddr, srcPort), dst(dstAddr, dstPort) {}

SocketPairIdent::SocketPairIdent(const SocketIdent &id1, const SocketIdent &id2)
    : src(id1), dst(id2) {}
    
bool operator == (const SocketPairIdent &id1, const SocketPairIdent &id2) {
    return id1.src == id2.src && id1.dst == id2.dst;
}

Socket::Socket() {
    type = UNSPEC;
    tcb = NULL;
    backlog = 0;
}


SequenceNumber::SequenceNumber() 
    : seq(0), init(0) {}
    
SequenceNumber::SequenceNumber(const uint32_t &_seq)
    : seq(helper::endian_reverse(_seq)), init(0) {}

SequenceNumber::SequenceNumber(const uint32_t &_seq, const uint32_t &_init) 
    : seq(helper::endian_reverse(_seq)), 
      init(helper::endian_reverse(_init)) {}
      
bool operator < (const SequenceNumber &s1, const SequenceNumber &s2) {
    if (s1.seq < s1.init) return true;
    return (s1.seq - s1.init) < (s2.seq - s2.init);
}

bool operator <= (const SequenceNumber &s1, const SequenceNumber &s2) {
    if (s1.seq < s1.init) return true;
    return (s1.seq - s1.init) <= (s2.seq - s2.init);
}

bool operator == (const SequenceNumber &s1, const SequenceNumber &s2) {
    return s1.seq == s2.seq;
}

SequenceNumber operator + (const SequenceNumber &s, uint32_t delta) {
    SequenceNumber ret(s);
    ret.seq += delta;
    return ret;
}

SequenceNumber::operator uint32_t() {
    return helper::endian_reverse(seq);
}

void *timer_thread(void *arg) {
    SendQueue *q = (SendQueue *)arg;
    pthread_mutex_t *mtx = &q->timer_thread_mutex;
    while (!helper::needQuit(mtx)) {
        struct timespec tv;
        clock_gettime(CLOCK_MONOTONIC, &tv);
        tv.tv_sec += 2;
        pthread_mutex_lock(&q->message_mutex);
        int ret = pthread_cond_timedwait(&q->message_cond, &q->message_mutex, &tv);
        if (ret != ETIMEDOUT) {
            pthread_mutex_unlock(&q->message_mutex);
            continue;
        }
        pthread_mutex_lock(&q->queue_mutex);
        if (q->Q.size() == 0) {
            pthread_mutex_unlock(&q->queue_mutex);
            pthread_mutex_unlock(&q->message_mutex);
            continue;
        }
        for (auto x: q->Q)
            sendSegment(x);
        pthread_mutex_unlock(&q->queue_mutex);
        pthread_mutex_unlock(&q->message_mutex);
    }
    return NULL;
}

void *timeout_thread(void *arg) {
    pthread_detach(pthread_self());
    TimeoutInfo *ti = (TimeoutInfo *)arg;
    while (1) {
        struct timespec tv;
        clock_gettime(CLOCK_MONOTONIC, &tv);
        tv.tv_sec += 120;
        pthread_mutex_lock(ti->mutex);
        int ret = pthread_cond_timedwait(ti->cond, ti->mutex, &tv);
        if (ret != ETIMEDOUT) {
            pthread_mutex_unlock(ti->mutex);
            continue;
        }
        LOCK();
        ti->tcb->state = TCB::STATE::CLOSED;
        ti->tcb->timeout_mutex = NULL;
        ti->tcb->timeout_cond = NULL;
        pthread_mutex_unlock(ti->mutex);
        pthread_mutex_destroy(ti->mutex);
        pthread_cond_destroy(ti->cond);
        delete ti->mutex;
        delete ti->cond;
        UNLOCK();
    }
    pthread_exit(0);
}

SendQueue::SendQueue() {
    pthread_mutex_init(&timer_thread_mutex, NULL);
    pthread_mutex_lock(&timer_thread_mutex);
    pthread_condattr_init(&message_condattr);
    pthread_mutex_init(&message_mutex, NULL);
    pthread_condattr_setclock(&message_condattr, CLOCK_MONOTONIC);
    pthread_cond_init(&message_cond, &message_condattr);
    pthread_mutex_init(&queue_mutex, NULL);
    pthread_cond_init(&queue_cond, NULL);
    pthread_create(&timer, NULL, timer_thread, this);
}

SendQueue::~SendQueue() {
    pthread_mutex_unlock(&timer_thread_mutex);
    pthread_join(timer, NULL);
    
    pthread_mutex_unlock(&message_mutex);
    pthread_mutex_unlock(&queue_mutex);
    pthread_mutex_destroy(&timer_thread_mutex);
    pthread_mutex_destroy(&message_mutex);
    pthread_mutex_destroy(&queue_mutex);
    pthread_cond_destroy(&queue_cond);
    pthread_cond_destroy(&message_cond);
    pthread_condattr_destroy(&message_condattr);
}

void sendSegment(Segment *seg) {
    char *buf = new char[seg->length];
    memcpy(buf, &seg->hd, sizeof(tcp::header));
    memcpy(buf + sizeof(tcp::header), seg->data, seg->length - sizeof(tcp::header));
    struct in_addr src, dst;
    src.s_addr = seg->srcAddr;
    dst.s_addr = seg->dstAddr;
    ip::sendIPPacket(src, dst, tcp::PTCL, buf, seg->length);
}

void SendQueue::addQueueAndSend(Segment *seg) {
    pthread_mutex_lock(&queue_mutex);
    while (Q.size() >= MAXQUEUESIZE)
        pthread_cond_wait(&queue_cond, &queue_mutex);
    Q.push_back(seg);
    pthread_mutex_unlock(&queue_mutex);
    sendSegment(seg);
}

void SendQueue::ackSegment(SequenceNumber ack) {
    pthread_mutex_lock(&queue_mutex);
    if (SND_UNA < ack && ack <= SND_NXT) {
        while (!Q.empty()) {
            SequenceNumber seq(Q.front()->hd.seq, helper::endian_reverse(ack.init));
            seq = seq + (uint32_t)(Q.front()->length - sizeof(tcp::header));
            if (Q.front()->hd.control & SYN) seq = seq + (uint32_t)1;
            if (Q.front()->hd.control & FIN) seq = seq + (uint32_t)1;
            if (!(seq <= ack)) break;
            delete Q.front();
            Q.pop_front();
        }
        SND_UNA = ack;        
    }
    pthread_cond_signal(&message_cond);
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

void SendQueue::flushQueue() {
    pthread_mutex_lock(&queue_mutex);
    while (!Q.empty())
        Q.pop_front();
    pthread_mutex_unlock(&queue_mutex);
}

bool SendQueue::empty() {
    pthread_mutex_lock(&queue_mutex);
    bool ret = Q.empty();
    pthread_mutex_unlock(&queue_mutex);
    return ret;
}

ReceiveBuffer::ReceiveBuffer() {
    buf = new char[BUFSIZE];
    now = buf; 
}

int ReceiveBuffer::read(char *data, int len) {
    int ret = std::min(now - buf, len);
    memcpy(data, buf, ret);
    memmove(buf, buf + ret, (now - buf) - ret);
    now = buf;
    return ret;
}

int ReceiveBuffer::write(char *data, int len) {
    int ret = std::min((buf + BUFSIZE) - now, len);
    memcpy(now, data, ret);
    now += ret;
    return ret;
}

void TCB::processSegment_CLOSED(const void *buf, int len) {
    struct header *hd = (struct header *)buf;
     /*
      If the state is CLOSED (i.e., TCB does not exist) then

      all data in the incoming segment is discarded.  An incoming
      segment containing a RST is discarded.  An incoming segment not
      containing a RST causes a RST to be sent in response.  The
      acknowledgment and sequence field values are selected to make the
      reset sequence acceptable to the TCP that sent the offending
      segment.

      If the ACK bit is off, sequence number zero is used,

        <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

      If the ACK bit is on,

        <SEQ=SEG.ACK><CTL=RST>

      Return.
    */
    struct SocketPairIdent rsockpair(sp.dst.addr, sp.dst.port, sp.src.addr, sp.src.port);
    if (!(hd->control & RST)) {
        if (hd->control & ACK) {
            Segment *seg = newSegment(rsockpair, RST, hd->ack);
            sendSegment(seg);
            delete seg;
        } else {
            Segment *seg = newSegment(rsockpair, RST|ACK, (uint32_t)0, 
                SequenceNumber(hd->seq) + calcSegmentLength(hd, len));
            sendSegment(seg);
            delete seg;
        }
    }
}

void TCB::processSegment_LISTEN(const void *buf, int len) {
    struct header *hd = (struct header *)buf;
    struct SocketPairIdent rsockpair(sp.dst.addr, sp.dst.port, sp.src.addr, sp.src.port);
    /* 
    If the state is LISTEN then

      first check for an RST

        An incoming RST should be ignored.  Return.
    */
    if (hd->control & RST)
        return;
    /*
      second check for an ACK

        Any acknowledgment is bad if it arrives on a connection still in
        the LISTEN state.  An acceptable reset segment should be formed
        for any arriving ACK-bearing segment.  The RST should be
        formatted as follows:

          <SEQ=SEG.ACK><CTL=RST>

        Return.
    */
    if (hd->control & ACK) {
        Segment *seg = newSegment(rsockpair, RST, hd->ack);
        sendSegment(seg);
        delete seg;
        return;
    }
    /*
      third check for a SYN

        If the SYN bit is set, check the security.  If the
        security/compartment on the incoming segment does not exactly
        match the security/compartment in the TCB then send a reset and
        return.

          <SEQ=SEG.ACK><CTL=RST>

        If the SEG.PRC is greater than the TCB.PRC then if allowed by
        the user and the system set TCB.PRC<-SEG.PRC, if not allowed
        send a reset and return.

          <SEQ=SEG.ACK><CTL=RST>

        If the SEG.PRC is less than the TCB.PRC then continue.

        Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ and any other
        control or text should be queued for processing later.  ISS
        should be selected and a SYN segment sent of the form:

          <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
    
        SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection
        state should be changed to SYN-RECEIVED.  Note that any other
        incoming control or data (combined with SYN) will be processed
        in the SYN-RECEIVED state, but processing of SYN and ACK should
        not be repeated.  If the listen was not fully specified (i.e.,
        the foreign socket was not fully specified), then the
        unspecified fields should be filled in now.
    */
    if (hd->control & SYN) {
        rb->IRS = hd->seq;
        rb->RCV_NXT = SequenceNumber(rb->IRS, rb->IRS) + (uint32_t)1;
    
        sq->ISS = helper::rand32bit();
        sq->SND_NXT = SequenceNumber(sq->ISS, sq->ISS) + (uint32_t)1;
        sq->SND_UNA = SequenceNumber(sq->ISS, sq->ISS);
        state = STATE::SYN_RECEIVED; 
        Segment *seg = newSegment(rsockpair, SYN|ACK, sq->ISS, rb->RCV_NXT);
        sq->addQueueAndSend(seg);
        return;   
    }
    /*
      fourth other text or control

        Any other control or text-bearing segment (not containing SYN)
        must have an ACK and thus would be discarded by the ACK
        processing.  An incoming RST segment could not be valid, since
        it could not have been sent in response to anything sent by this
        incarnation of the connection.  So you are unlikely to get here,
        but if you do, drop the segment, and return.
    */
    return;
}

void TCB::processSegment_SYN_SENT(const void *buf, int len) {
    struct header *hd = (struct header *)buf;
    struct SocketPairIdent rsockpair(sp.dst.addr, sp.dst.port, sp.src.addr, sp.src.port);
    /*
    If the state is SYN-SENT then

      first check the ACK bit

        If the ACK bit is set

          If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless
          the RST bit is set, if so drop the segment and return)

            <SEQ=SEG.ACK><CTL=RST>

          and discard the segment.  Return.

          If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
    */
    bool acceptable = false;
    if (hd->control & ACK) {
        SequenceNumber SEG_ACK(hd->ack, sq->ISS);
        SequenceNumber ISS(sq->ISS, sq->ISS);
        if (SEG_ACK <= ISS || sq->SND_NXT < SEG_ACK) {
            Segment *seg = newSegment(rsockpair, RST, SEG_ACK);
            sendSegment(seg);
            delete seg;
            return;
        }
        if (sq->SND_UNA <= SEG_ACK && SEG_ACK <= sq->SND_NXT)
            acceptable = true;
    }
    /*
      second check the RST bit

        If the RST bit is set

          If the ACK was acceptable then signal the user "error:
          connection reset", drop the segment, enter CLOSED state,
          delete TCB, and return.  Otherwise (no ACK) drop the segment
          and return.
    */
    if (hd->control & RST) {
        if (acceptable) {
            MESSAGE(MessageType::RESET, this);
            state = STATE::CLOSED;
            return;
        }
        return;
    }
    /*
      third check the security and precedence

        If the security/compartment in the segment does not exactly
        match the security/compartment in the TCB, send a reset

          If there is an ACK

            <SEQ=SEG.ACK><CTL=RST>

          Otherwise

            <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

        If there is an ACK

          The precedence in the segment must match the precedence in the
          TCB, if not, send a reset

            <SEQ=SEG.ACK><CTL=RST>

        If there is no ACK

          If the precedence in the segment is higher than the precedence
          in the TCB then if allowed by the user and the system raise
          the precedence in the TCB to that in the segment, if not
          allowed to raise the prec then send a reset.

            <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

          If the precedence in the segment is lower than the precedence
          in the TCB continue.

        If a reset was sent, discard the segment and return.
    */
    // DON'T CHECK SECURITY & PRECEDENCE AT THE MOMENT
    /*
      fourth check the SYN bit

        This step should be reached only if the ACK is ok, or there is
        no ACK, and it the segment did not contain a RST.

        If the SYN bit is on and the security/compartment and precedence
        are acceptable then, RCV.NXT is set to SEG.SEQ+1, IRS is set to
        SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
        is an ACK), and any segments on the retransmission queue which
        are thereby acknowledged should be removed.

        If SND.UNA > ISS (our SYN has been ACKed), change the connection
        state to ESTABLISHED, form an ACK segment

          <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        and send it.  Data or controls which were queued for
        transmission may be included.  If there are other controls or
        text in the segment then continue processing at the sixth step
        below where the URG bit is checked, otherwise return.

        Otherwise enter SYN-RECEIVED, form a SYN,ACK segment

          <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

        and send it.  If there are other controls or text in the
        segment, queue them for processing after the ESTABLISHED state
        has been reached, return.
    */
    if ((hd->control & SYN) && acceptable) {
        rb->RCV_NXT = SequenceNumber(hd->seq, hd->seq) + (uint32_t)1;
        rb->IRS = hd->seq;
        if (hd->control & ACK) {
            sq->ackSegment(SequenceNumber(hd->ack, sq->ISS));
        }
        if (SequenceNumber(sq->ISS, sq->ISS) < sq->SND_UNA) {
            state = STATE::ESTABLISHED;
            Segment *seg = newSegment(rsockpair, ACK, sq->SND_NXT, rb->RCV_NXT);
            sendSegment(seg);
            delete seg;
        } else {
            state = STATE::SYN_RECEIVED;
            Segment *seg = newSegment(rsockpair, SYN|ACK, SequenceNumber(sq->ISS),
                rb->RCV_NXT);
            sq->addQueueAndSend(seg);
        }
        MESSAGE(MessageType::CONN_OK, this);
        /* TODO: other controls or text in the segment */
    }
    /*
      fifth, if neither of the SYN or RST bits is set then drop the
      segment and return.
    */
    if (!(hd->control & SYN) && !(hd->control & RST))
        return;
}

void TCB::processSegment_OTHERWISE(const void *buf, int len) {
    struct header *hd = (struct header *)buf;
    struct SocketPairIdent rsockpair(sp.dst.addr, sp.dst.port, sp.src.addr, sp.src.port);
    /*
    Otherwise,

    first check sequence number

      SYN-RECEIVED STATE
      ESTABLISHED STATE
      FIN-WAIT-1 STATE
      FIN-WAIT-2 STATE
      CLOSE-WAIT STATE
      CLOSING STATE
      LAST-ACK STATE
      TIME-WAIT STATE

        Segments are processed in sequence.  Initial tests on arrival
        are used to discard old duplicates, but further processing is
        done in SEG.SEQ order.  If a segment's contents straddle the
        boundary between old and new, only the new parts should be
        processed.

        There are four cases for the acceptability test for an incoming
        segment:

        Segment Receive  Test
        Length  Window
        ------- -------  -------------------------------------------

           0       0     SEG.SEQ = RCV.NXT

           0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND

          >0       0     not acceptable

          >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                      or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND

        If the RCV.WND is zero, no segments will be acceptable, but
        special allowance should be made to accept valid ACKs, URGs and
        RSTs.

        If an incoming segment is not acceptable, an acknowledgment
        should be sent in reply (unless the RST bit is set, if so drop
        the segment and return):

          <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        After sending the acknowledgment, drop the unacceptable segment
        and return.

        In the following it is assumed that the segment is the idealized
        segment that begins at RCV.NXT and does not exceed the window.
        One could tailor actual segments to fit this assumption by
        trimming off any portions that lie outside the window (including
        SYN and FIN), and only processing further if the segment then
        begins at RCV.NXT.  Segments with higher begining sequence
        numbers may be held for later processing.
    */
    bool acceptable = false;
    uint32_t SEG_LEN = calcSegmentLength(hd, len);
    uint32_t RCV_WND = (rb->buf + BUFSIZE) - (rb->now);
    SequenceNumber SEG_SEQ(hd->seq, rb->IRS);
    if (SEG_LEN == 0 && RCV_WND == 0) {
        acceptable = (SEG_SEQ == rb->RCV_NXT);
    }
    if (SEG_LEN == 0 && RCV_WND > 0) {
        acceptable = (rb->RCV_NXT <= SEG_SEQ && SEG_SEQ < rb->RCV_NXT + RCV_WND);
    }
    if (SEG_LEN > 0 && RCV_WND == 0) {
        acceptable = false;
    }
    if (SEG_LEN > 0 && RCV_WND > 0) {
        acceptable = (rb->RCV_NXT <= SEG_SEQ && SEG_SEQ < rb->RCV_NXT + RCV_WND) ||
            (rb->RCV_NXT <= SEG_SEQ + (SEG_LEN - 1) && 
             SEG_SEQ + (SEG_LEN - 1) < rb->RCV_NXT + RCV_WND);
    }
    if (!acceptable) {
        if (hd->control & RST)
            return;
        Segment *seg = newSegment(rsockpair, ACK, sq->SND_NXT, rb->RCV_NXT);
        sendSegment(seg);
        delete seg;
        return;
    }
    /*
    second check the RST bit,

      SYN-RECEIVED STATE

        If the RST bit is set

          If this connection was initiated with a passive OPEN (i.e.,
          came from the LISTEN state), then return this connection to
          LISTEN state and return.  The user need not be informed.  If
          this connection was initiated with an active OPEN (i.e., came
          from SYN-SENT state) then the connection was refused, signal
          the user "connection refused".  In either case, all segments
          on the retransmission queue should be removed.  And in the
          active OPEN case, enter the CLOSED state and delete the TCB,
          and return.

      ESTABLISHED
      FIN-WAIT-1
      FIN-WAIT-2
      CLOSE-WAIT

        If the RST bit is set then, any outstanding RECEIVEs and SEND
        should receive "reset" responses.  All segment queues should be
        flushed.  Users should also receive an unsolicited general
        "connection reset" signal.  Enter the CLOSED state, delete the
        TCB, and return.

      CLOSING STATE
      LAST-ACK STATE
      TIME-WAIT

        If the RST bit is set then, enter the CLOSED state, delete the
        TCB, and return.
    */
    if (hd->control & RST) {
        switch (state) {
            case STATE::SYN_RECEIVED:
                MESSAGE(MessageType::REFUSED, this);
                state = STATE::CLOSED;
                sq->flushQueue();
                return;
            case STATE::ESTABLISHED:
            case STATE::FIN_WAIT_1:
            case STATE::FIN_WAIT_2:
            case STATE::CLOSE_WAIT:
                MESSAGE(MessageType::RESET, this);
                state = STATE::CLOSED;
                sq->flushQueue();
                return;
            case STATE::CLOSING:
            case STATE::LAST_ACK:
            case STATE::TIME_WAIT:
                state = STATE::CLOSED;
                return;
            default:
                fprintf(stderr, "[ERROR] Unexpected state\n");
                return;
        }
    }
    /*
    third check security and precedence

      SYN-RECEIVED

        If the security/compartment and precedence in the segment do not
        exactly match the security/compartment and precedence in the TCB
        then send a reset, and return.

      ESTABLISHED STATE

        If the security/compartment and precedence in the segment do not
        exactly match the security/compartment and precedence in the TCB
        then send a reset, any outstanding RECEIVEs and SEND should
        receive "reset" responses.  All segment queues should be
        flushed.  Users should also receive an unsolicited general
        "connection reset" signal.  Enter the CLOSED state, delete the
        TCB, and return.

      Note this check is placed following the sequence check to prevent
      a segment from an old connection between these ports with a
      different security or precedence from causing an abort of the
      current connection.
    */
    // DON'T CHECK SECURITY & PRECEDENCE AT THE MOMENT
    /*
    fourth, check the SYN bit,

      SYN-RECEIVED
      ESTABLISHED STATE
      FIN-WAIT STATE-1
      FIN-WAIT STATE-2
      CLOSE-WAIT STATE
      CLOSING STATE
      LAST-ACK STATE
      TIME-WAIT STATE

        If the SYN is in the window it is an error, send a reset, any
        outstanding RECEIVEs and SEND should receive "reset" responses,
        all segment queues should be flushed, the user should also
        receive an unsolicited general "connection reset" signal, enter
        the CLOSED state, delete the TCB, and return.

        If the SYN is not in the window this step would not be reached
        and an ack would have been sent in the first step (sequence
        number check).
    */
    if (hd->control & SYN) {
        switch (state) {
            case STATE::SYN_RECEIVED:
            case STATE::ESTABLISHED:
            case STATE::FIN_WAIT_1:
            case STATE::FIN_WAIT_2:
            case STATE::CLOSE_WAIT:
            case STATE::CLOSING:
            case STATE::LAST_ACK:
            case STATE::TIME_WAIT:
                MESSAGE(MessageType::RESET, this);
                state = STATE::CLOSED;
                sq->flushQueue();
                return;
            default:
                fprintf(stderr, "[ERROR] Unexpected state\n");
                return;
        }
    }
    /*
    fifth check the ACK field,

      if the ACK bit is off drop the segment and return
    */
    if (!(hd->control & ACK))
        return;
    /*
      if the ACK bit is on

        SYN-RECEIVED STATE

          If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state
          and continue processing.

            If the segment acknowledgment is not acceptable, form a
            reset segment,

              <SEQ=SEG.ACK><CTL=RST>

            and send it.
    */
    if (hd->control & ACK) {
        SequenceNumber SEG_ACK(hd->ack, sq->ISS);
        switch (state) {
            case STATE::SYN_RECEIVED:
                if (sq->SND_UNA <= SEG_ACK && SEG_ACK <= sq->SND_NXT) {
                    state = STATE::ESTABLISHED;
                }
                else {
                    Segment *seg = newSegment(rsockpair, RST, SEG_ACK);
                    sendSegment(seg);
                    delete seg;
                }
                /* fall through */
    /*
        ESTABLISHED STATE

          If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
          Any segments on the retransmission queue which are thereby
          entirely acknowledged are removed.  Users should receive
          positive acknowledgments for buffers which have been SENT and
          fully acknowledged (i.e., SEND buffer should be returned with
          "ok" response).  If the ACK is a duplicate
          (SEG.ACK < SND.UNA), it can be ignored.  If the ACK acks
          something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
          drop the segment, and return.

          If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
          updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
          SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
          SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.

          Note that SND.WND is an offset from SND.UNA, that SND.WL1
          records the sequence number of the last segment used to update
          SND.WND, and that SND.WL2 records the acknowledgment number of
          the last segment used to update SND.WND.  The check here
          prevents using old segments to update the window.

        FIN-WAIT-1 STATE

          In addition to the processing for the ESTABLISHED state, if
          our FIN is now acknowledged then enter FIN-WAIT-2 and continue
          processing in that state.

        FIN-WAIT-2 STATE

          In addition to the processing for the ESTABLISHED state, if
          the retransmission queue is empty, the user's CLOSE can be
          acknowledged ("ok") but do not delete the TCB.

        CLOSE-WAIT STATE

          Do the same processing as for the ESTABLISHED state.

        CLOSING STATE

          In addition to the processing for the ESTABLISHED state, if
          the ACK acknowledges our FIN then enter the TIME-WAIT state,
          otherwise ignore the segment.

        LAST-ACK STATE

          The only thing that can arrive in this state is an
          acknowledgment of our FIN.  If our FIN is now acknowledged,
          delete the TCB, enter the CLOSED state, and return.

        TIME-WAIT STATE

          The only thing that can arrive in this state is a
          retransmission of the remote FIN.  Acknowledge it, and restart
          the 2 MSL timeout.
    */    
            case STATE::ESTABLISHED:
            case STATE::FIN_WAIT_1:
            case STATE::FIN_WAIT_2:
            case STATE::CLOSE_WAIT:
            case STATE::CLOSING:
                if (sq->SND_UNA < SEG_ACK && SEG_ACK <= sq->SND_NXT) {
                    sq->ackSegment(SequenceNumber(SEG_ACK, sq->ISS));
                    MESSAGE(MessageType::SEND_OK, this);
                }
                if (state == STATE::FIN_WAIT_1) {
                    if (sq->SND_NXT == SEG_ACK)
                        state = STATE::FIN_WAIT_2;
                        /* fall through */    
                }
                if (state == STATE::FIN_WAIT_2) {
                    if (sq->empty())
                        MESSAGE(MessageType::CLOSE_OK, this);
                }
                if (state == STATE::CLOSING) {
                    if (sq->SND_NXT == SEG_ACK)
                        state = STATE::TIME_WAIT;
                }
                break;
            case STATE::LAST_ACK:
                if (sq->SND_NXT != SEG_ACK)
                    fprintf(stderr, "[ERROR] Not expected ACK of FIN\n");
                state = STATE::CLOSED;
                return;
            case STATE::TIME_WAIT:
                {
                Segment *seg = newSegment(rsockpair, ACK, sq->SND_NXT, 
                    SequenceNumber(hd->seq) + (uint32_t)1);
                sendSegment(seg);
                delete seg;
                pthread_cond_signal(timeout_cond);
                }
                break;
            default:
                fprintf(stderr, "[ERROR] Unexpected state\n");
                return;
        }
    }
    /*
    sixth, check the URG bit,

      ESTABLISHED STATE
      FIN-WAIT-1 STATE
      FIN-WAIT-2 STATE

        If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and signal
        the user that the remote side has urgent data if the urgent
        pointer (RCV.UP) is in advance of the data consumed.  If the
        user has already been signaled (or is still in the "urgent
        mode") for this continuous sequence of urgent data, do not
        signal the user again.
        
      CLOSE-WAIT STATE
      CLOSING STATE
      LAST-ACK STATE
      TIME-WAIT

        This should not occur, since a FIN has been received from the
        remote side.  Ignore the URG.
    */
    // IGNORE URGENT BIT AT THE MOMENT
    /*
    seventh, process the segment text,

      ESTABLISHED STATE
      FIN-WAIT-1 STATE
      FIN-WAIT-2 STATE

        Once in the ESTABLISHED state, it is possible to deliver segment
        text to user RECEIVE buffers.  Text from segments can be moved
        into buffers until either the buffer is full or the segment is
        empty.  If the segment empties and carries an PUSH flag, then
        the user is informed, when the buffer is returned, that a PUSH
        has been received.

        When the TCP takes responsibility for delivering the data to the
        user it must also acknowledge the receipt of the data.

        Once the TCP takes responsibility for the data it advances
        RCV.NXT over the data accepted, and adjusts RCV.WND as
        apporopriate to the current buffer availability.  The total of
        RCV.NXT and RCV.WND should not be reduced.

        Please note the window management suggestions in section 3.7.

        Send an acknowledgment of the form:

          <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        This acknowledgment should be piggybacked on a segment being
        transmitted if possible without incurring undue delay.

      CLOSE-WAIT STATE
      CLOSING STATE
      LAST-ACK STATE
      TIME-WAIT STATE

        This should not occur, since a FIN has been received from the
        remote side.  Ignore the segment text.
    */
    if (len - sizeof(tcp::header) > 0) {
        switch (state) {
            case STATE::ESTABLISHED:
            case STATE::FIN_WAIT_1:
            case STATE::FIN_WAIT_2:
                if (SequenceNumber(hd->seq, rb->IRS) <= rb->RCV_NXT) {
                    int offset = (int)(rb->RCV_NXT.seq - helper::endian_reverse(hd->seq));
                    if (hd->control & SYN) offset--;
                    char *ptr = (char *)buf + sizeof(tcp::header) + offset;
                    int datalen = len - sizeof(tcp::header);
                    if (hd->control & SYN) datalen--;
                    if (hd->control & FIN) datalen--;
                    uint32_t ret = rb->write(ptr, datalen);
                    rb->RCV_NXT = rb->RCV_NXT + ret;
                    MESSAGE(MessageType::RECV_OK, this);
                }
                {
                Segment *seg = newSegment(rsockpair, ACK, sq->SND_NXT, rb->RCV_NXT);
                sendSegment(seg);
                delete seg;
                }
                break;
            case STATE::CLOSE_WAIT:
            case STATE::CLOSING:
            case STATE::LAST_ACK:
            case STATE::TIME_WAIT:
                break;
            default:
                fprintf(stderr, "[ERROR] Unexpected segment data\n");
                return;
        }
    }
    /*
    eighth, check the FIN bit,

      Do not process the FIN if the state is CLOSED, LISTEN or SYN-SENT
      since the SEG.SEQ cannot be validated; drop the segment and
      return.

      If the FIN bit is set, signal the user "connection closing" and
      return any pending RECEIVEs with same message, advance RCV.NXT
      over the FIN, and send an acknowledgment for the FIN.  Note that
      FIN implies PUSH for any segment text not yet delivered to the
      user.

        SYN-RECEIVED STATE
        ESTABLISHED STATE

          Enter the CLOSE-WAIT state.

        FIN-WAIT-1 STATE

          If our FIN has been ACKed (perhaps in this segment), then
          enter TIME-WAIT, start the time-wait timer, turn off the other
          timers; otherwise enter the CLOSING state.

        FIN-WAIT-2 STATE

          Enter the TIME-WAIT state.  Start the time-wait timer, turn
          off the other timers.

        CLOSE-WAIT STATE

          Remain in the CLOSE-WAIT state.

        CLOSING STATE

          Remain in the CLOSING state.

        LAST-ACK STATE

          Remain in the LAST-ACK state.

        TIME-WAIT STATE

          Remain in the TIME-WAIT state.  Restart the 2 MSL time-wait
          timeout.

    and return.
    */
    if (state == STATE::CLOSED || state == STATE::LISTEN ||
        state == STATE::SYN_SENT)
        return;
        
    if (hd->control & FIN) {
        rb->RCV_NXT = SequenceNumber(hd->seq, rb->IRS) + 
            (uint32_t)(1 + len - sizeof(tcp::header));
        Segment *seg = newSegment(rsockpair, ACK, sq->SND_NXT, rb->RCV_NXT);
        sendSegment(seg);
        delete seg;
        switch (state) {
            case STATE::SYN_RECEIVED:
            case STATE::ESTABLISHED:
                state = STATE::CLOSE_WAIT;
                break;
            case STATE::FIN_WAIT_1:
                if (sq->SND_NXT == sq->SND_UNA) {
                    state = STATE::TIME_WAIT;
                    sq->flushQueue();
                    TimeoutInfo *ti = new TimeoutInfo;
                    ti->tcb = this;
                    timeout_mutex = new pthread_mutex_t;
                    timeout_cond = new pthread_cond_t;
                    pthread_mutex_init(timeout_mutex, NULL);
                    pthread_cond_init(timeout_cond, NULL);
                    ti->mutex = timeout_mutex;
                    ti->cond = timeout_cond;
                    pthread_t timeout;
                    pthread_create(&timeout, NULL, timeout_thread, ti);
                } else
                    state = STATE::CLOSING;
                break;
            case STATE::FIN_WAIT_2:
                {
                state = STATE::TIME_WAIT;
                sq->flushQueue();
                TimeoutInfo *ti = new TimeoutInfo;
                ti->tcb = this;
                timeout_mutex = new pthread_mutex_t;
                timeout_cond = new pthread_cond_t;
                pthread_mutex_init(timeout_mutex, NULL);
                pthread_cond_init(timeout_cond, NULL);
                ti->mutex = timeout_mutex;
                ti->cond = timeout_cond;
                pthread_t timeout;
                pthread_create(&timeout, NULL, timeout_thread, ti);
                }
                break;
            case STATE::CLOSE_WAIT:
            case STATE::CLOSING:
            case STATE::LAST_ACK:
                break;
            case STATE::TIME_WAIT:
                pthread_cond_signal(timeout_cond);
                break;
            default:
                fprintf(stderr, "[ERROR] Unexpected state\n");
                return;
        }
        MESSAGE(MessageType::CLOSING, this);
    }
}

void TCB::processSegment(const void *buf, int len) {
    switch (state) {
        case STATE::CLOSED:
            processSegment_CLOSED(buf, len);
            return;
        case STATE::LISTEN:
            processSegment_LISTEN(buf, len);
            return;
        case STATE::SYN_SENT:
            processSegment_SYN_SENT(buf, len);
            return;
        default:
            processSegment_OTHERWISE(buf, len);
    }
}

void TCB::close() {
    struct SocketPairIdent rsockpair(sp.dst.addr, sp.dst.port, sp.src.addr, sp.src.port);
/*    
  CLOSE Call

    CLOSED STATE (i.e., TCB does not exist)

      If the user does not have access to such a connection, return
      "error:  connection illegal for this process".

      Otherwise, return "error:  connection does not exist".

    LISTEN STATE

      Any outstanding RECEIVEs are returned with "error:  closing"
      responses.  Delete TCB, enter CLOSED state, and return.

    SYN-SENT STATE

      Delete the TCB and return "error:  closing" responses to any
      queued SENDs, or RECEIVEs.

    SYN-RECEIVED STATE

      If no SENDs have been issued and there is no pending data to send,
      then form a FIN segment and send it, and enter FIN-WAIT-1 state;
      otherwise queue for processing after entering ESTABLISHED state.

    ESTABLISHED STATE

      Queue this until all preceding SENDs have been segmentized, then
      form a FIN segment and send it.  In any case, enter FIN-WAIT-1
      state.

    FIN-WAIT-1 STATE
    FIN-WAIT-2 STATE

      Strictly speaking, this is an error and should receive a "error:
      connection closing" response.  An "ok" response would be
      acceptable, too, as long as a second FIN is not emitted (the first
      FIN may be retransmitted though).

    CLOSE-WAIT STATE

      Queue this request until all preceding SENDs have been
      segmentized; then send a FIN segment, enter CLOSING state.

    CLOSING STATE
    LAST-ACK STATE
    TIME-WAIT STATE

      Respond with "error:  connection closing".
*/
    switch (state) {
        case STATE::CLOSED:
        case STATE::LISTEN:
        case STATE::SYN_SENT:
            state = STATE::CLOSED;
            return;
        case STATE::SYN_RECEIVED:
        case STATE::ESTABLISHED:
            {
            Segment *seg = newSegment(rsockpair, FIN|ACK, sq->SND_NXT, rb->RCV_NXT);
            sq->addQueueAndSend(seg);
            sq->SND_NXT = sq->SND_NXT + (uint32_t)1;
            state = STATE::FIN_WAIT_1;
            break;
            }
        case STATE::FIN_WAIT_1:
        case STATE::FIN_WAIT_2:
            fprintf(stderr, "[ERROR] Connection closing\n");
            return;
        case STATE::CLOSE_WAIT:
            {
            Segment *seg = newSegment(rsockpair, FIN|ACK, sq->SND_NXT, rb->RCV_NXT);
            sq->addQueueAndSend(seg);
            sq->SND_NXT = sq->SND_NXT + (uint32_t)1;
            state = STATE::CLOSING;
            break;
            }
        case STATE::CLOSING:
        case STATE::LAST_ACK:
        case STATE::TIME_WAIT:
            fprintf(stderr, "[ERROR] Connection closing\n");
            return;
        default:
            fprintf(stderr, "[ERROR] Unexpected state\n");
            return;
    }
}

int TCB::send(void *buf, size_t nbyte) {
    struct SocketPairIdent rsockpair(sp.dst.addr, sp.dst.port, sp.src.addr, sp.src.port);
/*
  SEND Call

    CLOSED STATE (i.e., TCB does not exist)

      If the user does not have access to such a connection, then return
      "error:  connection illegal for this process".

      Otherwise, return "error:  connection does not exist".

    LISTEN STATE

      If the foreign socket is specified, then change the connection
      from passive to active, select an ISS.  Send a SYN segment, set
      SND.UNA to ISS, SND.NXT to ISS+1.  Enter SYN-SENT state.  Data
      associated with SEND may be sent with SYN segment or queued for
      transmission after entering ESTABLISHED state.  The urgent bit if
      requested in the command must be sent with the data segments sent
      as a result of this command.  If there is no room to queue the
      request, respond with "error:  insufficient resources".  If
      Foreign socket was not specified, then return "error:  foreign
      socket unspecified".

    SYN-SENT STATE
    SYN-RECEIVED STATE

      Queue the data for transmission after entering ESTABLISHED state.
      If no space to queue, respond with "error:  insufficient
      resources".

    ESTABLISHED STATE
    CLOSE-WAIT STATE

      Segmentize the buffer and send it with a piggybacked
      acknowledgment (acknowledgment value = RCV.NXT).  If there is
      insufficient space to remember this buffer, simply return "error:
      insufficient resources".

      If the urgent flag is set, then SND.UP <- SND.NXT-1 and set the
      urgent pointer in the outgoing segments.

    FIN-WAIT-1 STATE
    FIN-WAIT-2 STATE
    CLOSING STATE
    LAST-ACK STATE
    TIME-WAIT STATE

      Return "error:  connection closing" and do not service request.
*/
    switch (state) {
        case STATE::CLOSED:
            fprintf(stderr, "[ERROR] Connection does not exist\n");
            return 0;
        case STATE::LISTEN:
            fprintf(stderr, "[ERROR] Foreign socket unspecified\n");
            return 0;
        case STATE::SYN_SENT:
        case STATE::SYN_RECEIVED:
            break;
        case STATE::ESTABLISHED:
        case STATE::CLOSE_WAIT:
            break;
        case STATE::FIN_WAIT_1:
        case STATE::FIN_WAIT_2:
        case STATE::CLOSING:
        case STATE::LAST_ACK:
        case STATE::TIME_WAIT:
            fprintf(stderr, "[ERROR] Connection closing\n");
            return 0;
        default:
            fprintf(stderr, "[ERROR] Unexpected state\n");
            return 0;
    }
    int ret = 0;
    while (nbyte > 0) {
        size_t len = std::min(nbyte, MAXSEGMENTSIZE);
        Segment *seg = newSegment(rsockpair, ACK, sq->SND_NXT, rb->RCV_NXT, (char *)buf, len);
        sq->SND_NXT = sq->SND_NXT + (uint32_t)len;
        sq->addQueueAndSend(seg);
        buf = (void *)((char *)buf + len);
        nbyte -= len;
        ret += len;
    }
    return ret;
}

int TCB::receive(void *buf, size_t nbyte) {
/*
  RECEIVE Call

    CLOSED STATE (i.e., TCB does not exist)

      If the user does not have access to such a connection, return
      "error:  connection illegal for this process".

      Otherwise return "error:  connection does not exist".

    LISTEN STATE
    SYN-SENT STATE
    SYN-RECEIVED STATE

      Queue for processing after entering ESTABLISHED state.  If there
      is no room to queue this request, respond with "error:
      insufficient resources".

    ESTABLISHED STATE
    FIN-WAIT-1 STATE
    FIN-WAIT-2 STATE

      If insufficient incoming segments are queued to satisfy the
      request, queue the request.  If there is no queue space to
      remember the RECEIVE, respond with "error:  insufficient
      resources".

      Reassemble queued incoming segments into receive buffer and return
      to user.  Mark "push seen" (PUSH) if this is the case.

      If RCV.UP is in advance of the data currently being passed to the
      user notify the user of the presence of urgent data.

      When the TCP takes responsibility for delivering data to the user
      that fact must be communicated to the sender via an
      acknowledgment.  The formation of such an acknowledgment is
      described below in the discussion of processing an incoming
      segment.

    CLOSE-WAIT STATE

      Since the remote side has already sent FIN, RECEIVEs must be
      satisfied by text already on hand, but not yet delivered to the
      user.  If no text is awaiting delivery, the RECEIVE will get a
      "error:  connection closing" response.  Otherwise, any remaining
      text can be used to satisfy the RECEIVE.

    CLOSING STATE
    LAST-ACK STATE
    TIME-WAIT STATE

      Return "error:  connection closing".
*/
    switch (state) {
        case STATE::CLOSED:
            fprintf(stderr, "[ERROR] Connection does not exist\n");
            return 0;
        case STATE::LISTEN:
        case STATE::SYN_SENT:
        case STATE::SYN_RECEIVED:
            fprintf(stderr, "[ERROR] Insufficient Resources\n");
            return 0;
        case STATE::ESTABLISHED:
        case STATE::FIN_WAIT_1:
        case STATE::FIN_WAIT_2:
            return rb->read((char *)buf, nbyte);
        case STATE::CLOSE_WAIT:
            if (rb->now != rb->buf)
                return rb->read((char *)buf, nbyte);
        case STATE::CLOSING:
        case STATE::LAST_ACK:
        case STATE::TIME_WAIT:
            fprintf(stderr, "[ERROR] Connection closing\n");
            return 0;
        default:
            fprintf(stderr, "[ERROR] Unexpected state\n");
            return 0;
    }
}

TCB::TCB(const SocketPairIdent &_sp):sp(_sp) {
    state = STATE::CLOSED;
    sq = new struct SendQueue;
    rb = new struct ReceiveBuffer;
}    

TCB::~TCB() {
    delete sq;
    delete rb;
}

void LOCK() { pthread_mutex_lock(&protocol_stack_mutex); }
void UNLOCK() { pthread_mutex_unlock(&protocol_stack_mutex); }
void SIGNAL() { pthread_cond_signal(&protocol_stack_cond); }
void WAIT() { protocol_stack_message = 0;
    pthread_cond_wait(&protocol_stack_cond, &protocol_stack_mutex);}
void MESSAGE(MessageType m, TCB *tcb) { protocol_stack_message |= m; 
    protocol_stack_message_sender = tcb; SIGNAL(); }
int READMESSAGE() { return protocol_stack_message; }
TCB* READMESSAGESENDER() { return protocol_stack_message_sender; }

void init() {
    pthread_mutex_init(&protocol_stack_mutex, NULL);
    pthread_cond_init(&protocol_stack_cond, NULL);
    ip::setIPContentCallback(TCPSegmentCallback);
}

Segment *newSegment(SocketPairIdent id, uint8_t control, SequenceNumber seq,
    SequenceNumber ack, char *buf, int len) {
    Segment *ret = new Segment;
    ret->hd.srcPort = id.src.port;
    ret->hd.dstPort = id.dst.port;
    ret->hd.seq = seq;
    ret->hd.ack = ack;
    ret->hd.offset = 0x50;
    ret->hd.control = control;
    uint16_t window = 4096;
    ret->hd.window = helper::endian_reverse(window);
    ret->hd.checksum = 0;
    ret->hd.urgent = 0;
    uint8_t *tmp = new uint8_t[sizeof(pseudoheader) + sizeof(header) + len];
    pseudoheader *pdhd = (pseudoheader *)tmp;
    pdhd->srcAddr = id.src.addr;
    pdhd->dstAddr = id.dst.addr;
    pdhd->zero = 0;
    pdhd->PTCL = tcp::PTCL;
    pdhd->length = sizeof(tcp::header) + len;
    pdhd->length = helper::endian_reverse(pdhd->length);
    memcpy(tmp + sizeof(pseudoheader), &ret->hd, sizeof(header));
    if (buf) memcpy(tmp + sizeof(pseudoheader) + sizeof(header), buf, len);
    uint16_t totLen = sizeof(pseudoheader) + sizeof(header) + len;
    uint16_t checksum = helper::calcChecksum(tmp, totLen);
    ret->hd.checksum = checksum;
    ret->srcAddr = id.src.addr;
    ret->dstAddr = id.dst.addr;
    ret->length = sizeof(header) + len;
    delete [] tmp;
    tmp = new uint8_t[len];
    if (buf) {
        memcpy(tmp, buf, len);
        ret->data = tmp;
    } else 
        ret->data = NULL;   
    return ret;
}

void setSocketMap(SocketIdent id, Socket *sock) {
    id2socket.push_back(std::make_pair(id, sock));
}

void setTCBMap(SocketPairIdent id, TCB *tcb) {
    id2conn.push_back(std::make_pair(id, tcb));
}

}
}  
