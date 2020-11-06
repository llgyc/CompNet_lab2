#include "../inc/device.h"

namespace tinytcp {
namespace device {

static std::vector<Device> all_devices;

Device::Device() {
    handle = NULL;
}

Device::~Device() {
    if (handle) 
        pcap_close(handle);
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
    all_devices[id].handle = handle;
    return id;
}

int findDevice(const char* device) {
    for (int i = 0; i < (int)all_devices.size(); i++)
        if (all_devices[i].name == device) return i;
    fprintf(stderr, "ERROR: findDevice() %s - device not found", device);
    return -1;
}

const Device *getDevice(int id) {
    if (id < 0 || (size_t)id > all_devices.size()) 
        return NULL;
    return &all_devices[id];
}

}
}
