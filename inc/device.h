/** 
 * @file device.h
 * @author Yuchen Gu <llgyc@pku.edu.cn>
 * @brief Library supporting network device management.
 */
 
#ifndef __TINYTCP_DEVICE_H__
#define __TINYTCP_DEVICE_H__

#include <vector>
#include <string>
#include <pcap.h>

#include "packetio.h"

namespace tinytcp {
namespace device {

const int SNAPLEN = 65536;
const int READ_TIMEOUT = 1000;

struct Device {
    std::string name;
    eth::addr_t mac;
    pcap_t *handle;
    
    Device();
    ~Device();
};

/**
 * @brief Add a device to the library for sending/receiving packets. 
 *
 * @param device Name of network device to send/receive packet on.
 * @return A non-negative _device-ID_ on success, -1 on error.
 */
int addDevice(const char* device);

/**
 * @brief Find a device added by `addDevice`.
 *
 * @param device Name of the network device.
 * @return A non-negative _device-ID_ on success, -1 if no such device 
 * was found.
 */
int findDevice(const char* device);

/**
 * @brief Get the pointer to the device with ID id
 *
 * @param id ID of the device
 * @return A pointer to the device on success, -1 if no such device
 * @see addDevice
 */
const Device *getDevice(int id);

}
}

#endif
