/** 
 * @file packetio.h
 * @author Yuchen Gu <llgyc@pku.edu.cn>
 * @brief Library supporting sending/receiving Ethernet II frames.
 */

#ifndef __TINYTCP_PACKETIO_H__
#define __TINYTCP_PACKETIO_H__

#include <pcap.h>
#include <iostream>

namespace tinytcp {
namespace eth {

typedef uint8_t addr_t[6]; // big endian

const int MINFRAMELEN = 46;
const int MAXFRAMELEN = 1500;
const addr_t BROADCAST = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/** 
 * @brief Encapsulate some data into an Ethernet II frame and send it.
 *
 * @param buf Pointer to the payload.
 * @param len Length of the payload.
 * @param ethtype EtherType field value of this frame.
 * @param destmac MAC address of the destination.
 * @param id ID of the device(returned by `addDevice`) to send on.
 * @return 0 on success, -1 on error.
 * @see addDevice
 */
int sendFrame(const void* buf, int len, 
    int ethtype, const void* destmac, int id);

/** 
 * @brief Process a frame upon receiving it.
 *
 * @param buf Pointer to the frame.
 * @param len Length of the frame.
 * @param id ID of the device (returned by `addDevice`) receiving current 
 * frame.
 * @return 0 on success, -1 on error.
 * @see addDevice
 */
typedef int (*frameReceiveCallback)(const void*, int, int);

/**
 * @brief Register a callback function to be called each time an Ethernet II 
 * frame was received.
 *
 * @param callback the callback function.
 * @return 0 on success, -1 on error.
 * @see frameReceiveCallback
 */
int setFrameReceiveCallback(frameReceiveCallback callback);

/**
 * @brief Get the MAC address of a specified device
 *
 * @param device Name of the device.
 * @param mac Pointer to the place to store the MAC address
 * @return 0 on success, -1 on error.
 * @see addDevice
 */
int getMACAddr(const char *device, eth::addr_t *mac);

/** 
 * @brief Start capturing frames on device id.
 *
 * @param id ID of the device(returned by `addDevice`) to send on.
 * @return 0 on success, -1 on error.
 * @see addDevice
 */
int startCapture(int id);

/** 
 * @brief Determine whether an ethernet address is broadcast
 *
 * @param mac the MAC address to be determined
 * @return true or false.
 */
bool isBroadcast(eth::addr_t mac);

/** 
 * @brief Determine whether two ethernet addresses are the same
 *
 * @param mac1 the first MAC address to be determined
 * @param mac2 the second MAC address to be determined
 * @return true or false.
 */
bool equalAddr(const eth::addr_t &mac1, const eth::addr_t &mac2);

void mutexinit();
void mutexcleanup();

};
};

#endif
