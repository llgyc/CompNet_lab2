/** 
 * @file ip.h
 * @author Yuchen Gu <llgyc@pku.edu.cn>
 * @brief Library supporting sending/receiving IP packets encapsulated in an 
 * Ethernet II frame.
 */

#ifndef __TINYTCP_IP_H__
#define __TINYTCP_IP_H__

#include <netinet/ip.h>

namespace tinytcp {
namespace ip {

typedef uint32_t addr_t; // big endian

const addr_t BROADCAST = 0xffffffffu;

/************************    IP Header    ****************************
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   
**********************************************************************/

struct __attribute__((packed)) header {
    uint8_t ver_IHL;
    uint8_t TOS;
    uint16_t totLen;
    uint16_t ident;
    uint16_t frag;
    uint8_t TTL;
    uint8_t protocol;
    uint16_t checksum;
    ip::addr_t srcAddr;
    ip::addr_t dstAddr;
};

/**
 * @brief Get the IP address of a specified device
 *
 * @param device Name of the device.
 * @param ip Pointer to the place to store the IP address
 * @return 0 on success, -1 on error.
 * @see addDevice
 */
int getIPAddr(const char *device, ip::addr_t *ip);

/**
 * @brief Send an IP packet to specified host. 
 *
 * @param src Source IP address.
 * @param dest Destination IP address.
 * @param proto Value of `protocol` field in IP header.
 * @param buf pointer to IP payload
 * @param len Length of IP payload
 * @return 0 on success, -1 on error.
 */
int sendIPPacket(const struct in_addr src, const struct in_addr dest, 
    int proto, const void *buf, int len);

/** 
 * @brief Process an IP packet upon receiving it.
 *
 * @param buf Pointer to the packet.
 * @param len Length of the packet.
 * @return 0 on success, -1 on error.
 * @see addDevice
 */
typedef int (*IPPacketReceiveCallback)(const void* buf, int len);

/**
 * @brief Register a callback function to be called each time an IP packet
 * was received.
 *
 * @param callback The callback function.
 * @return 0 on success, -1 on error.
 * @see IPPacketReceiveCallback
 */
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);

/**
 * @brief Manully add an item to routing table. Useful when talking with real 
 * Linux machines.
 * 
 * @param dest The destination IP prefix.
 * @param mask The subnet mask of the destination IP prefix.
 * @param nextHopMAC MAC address of the next hop.
 * @param device Name of device to send packets on.
 * @return 0 on success, -1 on error
 */
int setRoutingTable(const struct in_addr dest, const struct in_addr mask, 
    const void* nextHopMAC, const char *device);

/** 
 * @brief Determine whether an IP address is broadcast.
 *
 * @param ip the IP address to be determined
 * @return true or false.
 */
bool isBroadcast(ip::addr_t ip);

/** 
 * @brief Initial setup work.
 * 
 * @return 0 on success, -1 on error
 */
int setup();

/** 
 * @brief Final cleanup work.
 * 
 * @return 0 on success, -1 on error
 */
int cleanup();

int setIPContentCallback(IPPacketReceiveCallback callback);

int epollInit();
int register_epoll(int fd);

}
}

#endif
