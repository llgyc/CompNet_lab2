#include <map>
#include <vector>

#include "../inc/device.h"
#include "../inc/helper.h"

#define DEBUG

namespace tinytcp {
namespace device {

static std::vector<Device> all_devices;
static std::map<int, int> fd2id;

Device::Device() {
    handle = NULL;
}

Device::~Device() {
    /* Due to implementation problem, we disable 
     * destruct function to protect from double-free problem
     */    
}

int addDevice(const char* device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(device, SNAPLEN, 0, READ_TIMEOUT, errbuf);
    
    if (!handle) {
        fprintf(stderr, "ERROR: pcap_open_live() failed - %s\n", errbuf);
        return -1;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "ERROR: pcap_open_live() failed"
            " - device %s doesn't support Ethernet\n", device);
        pcap_close(handle);
        return -1;
    }
    if (pcap_setnonblock(handle, 1, errbuf) != 0) {
        fprintf(stderr, "ERROR: pcap_setnonblock() failed"
            " - %s\n", errbuf);
        pcap_close(handle);
        return -1;
    }
    int fd = pcap_get_selectable_fd(handle);
    if (fd < 0) {
        fprintf(stderr, "ERROR: pcap_get_selectable_fd() failed\n");
        pcap_close(handle);
        return -1;
    }
    all_devices.emplace_back();
    int id = all_devices.size() - 1;
    all_devices[id].name = device;
    if (eth::getMACAddr(device, &all_devices[id].mac) < 0) {
        fprintf(stderr, "ERROR: pcap_open_live() failed"
            " - unable to get MAC address of %s\n", device);
        return -1;
    }
    if (ip::getIPAddr(device, &all_devices[id].ip) < 0) {
        fprintf(stderr, "ERROR: pcap_open_live() failed"
            " - unable to get IP address of %s\n", device);
        return -1;
    }
    all_devices[id].handle = handle;
    fd2id[fd] = id;
    ip::register_epoll(fd);
    
    #ifdef DEBUG
    fprintf(stderr, "=========================================\n");
    fprintf(stderr, "Added device: %s  ID: %d\n", device, id);
    fprintf(stderr, "MAC address: ");
    helper::printMAC(all_devices[id].mac);
    fprintf(stderr, "\nIP address: ");
    helper::printIP(all_devices[id].ip);
    fprintf(stderr, "\nfd: %d\n", fd);
    fprintf(stderr, "=========================================\n");
    #endif
    
    return id;
}

int findDevice(const char* device) {
    for (int i = 0; i < (int)all_devices.size(); i++)
        if (all_devices[i].name == device) return i;
    fprintf(stderr, "ERROR: findDevice() %s - device not found", device);
    return -1;
}

const Device *getDevice(int id) {
    if (id < 0 || (size_t)id >= all_devices.size()) 
        return NULL;
    return &all_devices[id];
}

int getIdFromFd(int fd) {
    if (fd2id.find(fd) != fd2id.end())
        return fd2id[fd];
    return -1;
}

}
}
