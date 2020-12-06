/** 
 * @file route.h
 * @author Yuchen Gu <llgyc@pku.edu.cn>
 * @brief Library related to routing.
 */
 
#ifndef __TINYTCP_ROUTE_H__
#define __TINYTCP_ROUTE_H__

#include <set>
#include <map>
#include <pthread.h>

#include "ip.h"
#include "packetio.h"

namespace tinytcp {
namespace route {

struct packetIdent {
    ip::addr_t srcAddr;
    uint16_t ident;
    bool operator < (const packetIdent &) const;
};

/**
 * @brief Scheduled cleanup of packet history.
 */
void packetForget();
bool packetExist(const packetIdent &);
void packetAdd(const packetIdent &);

struct entryKey {
    ip::addr_t dstAddr;
    ip::addr_t mask;
    bool operator < (const entryKey &e) const;
};

struct entryValue {
    eth::addr_t nextHopMAC;
    int id;
    time_t addTime;
};

/**
 * @brief Scheduled cleanup of routing table.
 */
void tableForget();

entryValue tableLookup(ip::addr_t);
void tableUpdate(const entryKey &, entryValue);

void mutexinit();
void mutexcleanup();

}
}

#endif
