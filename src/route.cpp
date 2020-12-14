#include <vector>
#include <stdint.h>
#include <algorithm>

#include "../inc/route.h"
#include "../inc/device.h"
#include "../inc/helper.h"

namespace tinytcp {
namespace route {

static const time_t maxLastTime = 60;

pthread_mutex_t history_mutex;
std::map<packetIdent, time_t> packetHistory;


pthread_mutex_t routing_table_mutex;
std::map<entryKey, entryValue> routingTable;

bool packetIdent::operator < (const packetIdent &p) const {
    if (srcAddr == p.srcAddr) return ident < p.ident;
        return srcAddr < p.srcAddr;
}

void packetForget() {
    pthread_mutex_lock(&history_mutex);
    std::vector<std::map<packetIdent, time_t>::iterator> toBeCleared;
    time_t nowTime = helper::getTime();
    for (auto it = packetHistory.begin(); it != packetHistory.end(); it++) {
        if (nowTime - it->second > maxLastTime)
            toBeCleared.push_back(it);
    }
    for (auto x:toBeCleared) {
        packetHistory.erase(x);
    }
    pthread_mutex_unlock(&history_mutex);
}

bool packetExist(const packetIdent &ide) {
    pthread_mutex_lock(&history_mutex);
    int ret = 0;
    if (packetHistory.find(ide) != packetHistory.end())
        ret = 1;
    pthread_mutex_unlock(&history_mutex);
    return ret;
}

void packetAdd(const packetIdent &ide) {
    pthread_mutex_lock(&history_mutex);
    packetHistory[ide] = helper::getTime();
    pthread_mutex_unlock(&history_mutex);
}

bool entryKey::operator < (const entryKey &e) const {
    if (dstAddr == e.dstAddr) return mask < e.mask;
    return dstAddr < e.dstAddr;
}

void tableForget() {
    pthread_mutex_lock(&routing_table_mutex);
    std::vector<std::map<entryKey, entryValue>::iterator> toBeCleared;
    time_t nowTime = helper::getTime();
    for (auto it = routingTable.begin(); it != routingTable.end(); it++) {
        if (nowTime - it->second.addTime > maxLastTime)
            toBeCleared.push_back(it);
    }
    for (auto x:toBeCleared) {
        routingTable.erase(x);
    }
    #ifdef DEBUG
    fprintf(stderr, "========================== Routing Table ==========================\n");
    fprintf(stderr, "       ip       ");
    fprintf(stderr, "      mask      ");
    fprintf(stderr, "    next hop    ");
    fprintf(stderr, "     device     \n");
    for (auto x:routingTable) {
        helper::printIP(x.first.dstAddr);
        fprintf(stderr, " ");
        helper::printIP(x.first.mask);
        fprintf(stderr, " ");
        helper::printMAC(x.second.nextHopMAC);
        fprintf(stderr, "    %s\n", device::getDevice(x.second.id)->name.c_str());
    }
    fprintf(stderr, "===================================================================\n");
    #endif
    pthread_mutex_unlock(&routing_table_mutex);
}

bool matchEntry(ip::addr_t dstAddr, const entryKey &key) {
    return ((dstAddr & key.mask) == (key.dstAddr & key.mask));
}

entryValue tableLookup(ip::addr_t dstAddr) {
    pthread_mutex_lock(&routing_table_mutex);
    entryValue ret; ret.id = -1;
    ip::addr_t longestMask = 0;
    for (auto e:routingTable) {
        if (matchEntry(dstAddr, e.first)) {
            if (helper::endian_reverse(e.first.mask) > longestMask) {
                ret = e.second;
                longestMask = helper::endian_reverse(e.first.mask);
            }
        }
    }
    pthread_mutex_unlock(&routing_table_mutex);
    return ret;
}

void tableUpdate(const entryKey &key, entryValue value) {
    pthread_mutex_lock(&routing_table_mutex);
    value.addTime = helper::getTime();
    routingTable[key] = value;
    pthread_mutex_unlock(&routing_table_mutex);
}

void mutexinit() {
    pthread_mutex_init(&history_mutex, NULL);
    pthread_mutex_init(&routing_table_mutex, NULL);
}

void mutexcleanup() {
    pthread_mutex_destroy(&history_mutex);
    pthread_mutex_destroy(&routing_table_mutex);
}

}
}
