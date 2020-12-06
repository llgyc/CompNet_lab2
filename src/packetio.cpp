#include <cstring>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "../inc/packetio.h"
#include "../inc/device.h"
#include "../inc/helper.h"

//#define DEBUG

namespace tinytcp {
namespace eth {

pthread_mutex_t sendpacket_mutex;

int sendFrame(const void* buf, int len, 
    int ethtype, const void* destmac, int id) {
    
    #ifdef DEBUG
    fprintf(stderr, "sendFrame id: %d\n", id);
    #endif
    
    /* Padding & FCS are done by devices, so no need to check MINFRAMELEN here. */
    if (len > MAXFRAMELEN) {
        fprintf(stderr, "ERROR: sendFrame() failed - ethernet frame length is invalid\n");
        return -1;
    }
    
    const device::Device *dev = device::getDevice(id);
    if (!dev) {
        fprintf(stderr, "ERROR: sendFrame() failed - id %d is invalid\n", id);
        return -1;
    }
    
    uint8_t *frame = new uint8_t[14 + len];
    std::memcpy(frame, destmac, sizeof(eth::addr_t));
    std::memcpy(frame + 6, dev->mac, sizeof(eth::addr_t));
    uint16_t r_ethtype = (uint16_t)ethtype;
    r_ethtype = helper::endian_reverse(r_ethtype);
    std::memcpy(frame + 12, &r_ethtype, 2);
    std::memcpy(frame + 14, buf, len);
    pthread_mutex_lock(&sendpacket_mutex);
    if (pcap_sendpacket(dev->handle, frame, 14 + len) == -1) {
        pthread_mutex_unlock(&sendpacket_mutex);
        fprintf(stderr, "ERROR: sendFrame() failed - %s\n", pcap_geterr(dev->handle));
        delete [] frame;
        return -1;
    }
    pthread_mutex_unlock(&sendpacket_mutex);
    delete [] frame; 
    return 0;
}

static frameReceiveCallback callback = nullptr;

int setFrameReceiveCallback(frameReceiveCallback callback) {
    eth::callback = callback;
    return 0;
}

/* Reference: https://www.cnblogs.com/dapaitou2006/p/6502195.html */
int getMACAddr(const char *device, eth::addr_t *mac) {
    int fd = socket(AF_PACKET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    size_t if_name_len = strlen(device);
    
    if (fd == -1) {
        fprintf(stderr, "ERROR: getMACAddr() - socket() failed\n");
        return -1;
    }
    
    if(if_name_len < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, device, if_name_len);
        ifr.ifr_name[if_name_len] = '\0';
    } else {
        fprintf(stderr, "ERROR: getMACAddr() - interface name is too long\n");
        close(fd);
        return -1;
    }
    
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        fprintf(stderr, "ERROR: getMACAddr() - %s\n", strerror(errno));
        close(fd);
        return -1;
    }
        
    if(ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        fprintf(stderr, "ERROR: getMACAddr() - device is not an Ethernet interface\n");
        close(fd);
        return -1;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, sizeof(eth::addr_t));
    close(fd);
    return 0;
}

/* Reference: https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut4.html */
int startCapture(int id) {
    const device::Device *dev = device::getDevice(id);
    if (!dev) {
        fprintf(stderr, "ERROR: startCapture() failed - device %d open failed\n", id);
        return -1;
    }
    
    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    while((res = pcap_next_ex(dev->handle, &header, &pkt_data)) > 0){
	/* Nonblock mode - no need to check situations when (res == 0) */
        
        if (!callback) {
            fprintf(stderr, "ERROR: startCapture() failed - callback function not registered\n");
            return -1;
        } else {
            if (callback(pkt_data, header->len, id) < 0) {
                fprintf(stderr, "ERROR: startCapture() failed - callback function failed\n");
                return -1;
            }
        }
    }
    
    if(res == -1){
        fprintf(stderr, "ERROR: startCapture() failed - %s\n", pcap_geterr(dev->handle));
        return -1;
    }
    
    return 0;
}

bool isBroadcast(eth::addr_t mac) {
    for (int i = 0; i < 6; i++) 
        if (mac[i] != (uint8_t)0xff) return false;
    return true;
}

bool equalAddr(const eth::addr_t &mac1, const eth::addr_t &mac2) {
    for (int i = 0; i < 6; i++)
        if (mac1[i] != mac2[i]) return false;
    return true;
}

void mutexinit() {
    pthread_mutex_init(&sendpacket_mutex, NULL);
}

void mutexcleanup() {
    pthread_mutex_destroy(&sendpacket_mutex);
}

}
}
