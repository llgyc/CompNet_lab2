/** 
 * @file helper.h
 * @author Yuchen Gu <llgyc@pku.edu.cn>
 * @brief Library with useful functions.
 */
 
#ifndef __TINYTCP_HELPER_H__
#define __TINYTCP_HELPER_H__

#include "ip.h"
#include "device.h"
#include "packetio.h"
#include "tcp.h"

namespace tinytcp {
namespace helper {
    
/**
 * @brief Reverse the endian of a number. 
 *
 * @param num The number to be reversed.
 * @return The reversed number
 */
uint16_t endian_reverse(uint16_t num);
uint32_t endian_reverse(uint32_t num);

/**
 * @brief Get current time. 
 *
 * @return time in seconds
 */
time_t getTime();

void printIP(ip::addr_t ip);
void printMAC(eth::addr_t mac);
void printPort(tcp::PortType port);

int allocate_new_fd();
uint16_t calcChecksum(uint8_t *buf, int len);
int needQuit(pthread_mutex_t *mtx);
uint32_t rand32bit();

int initAll(int, char **);

}
}

#endif
