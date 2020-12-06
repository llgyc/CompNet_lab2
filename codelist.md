# Codelist for each programming task

## Link-layer: Packet I/O On Ethernet

- Functions for manage devices are in `inc/device.h`
- Functions for sending and receiving Ethernet frames are in `inc/packetio.h`
- Helper functions are in `inc/packetio.h`
- Test files are in `test`
	- `print_my_mac.cpp` is used to print one device's mac address
	- `mac_client.cpp` and `mac_server.cpp` should be run on veth1-2 and veth2-1 respectively in the example network, they implement a simple 'echo function' to output all the received packets as they are
- Run `./compile.sh` could generate binary files in the `test` folder

## Network-layer: IP Protocol

- Functions related to routing are in `inc/route.h`
- Functions related to IP packets processing are in `inc/ip.h`
- Test files are in `test`
	- `print_my_ip.cpp` is used to print one device's ip address
	- `ip_client.cpp` and `ip_middle.cpp` and `ip_server.cpp` should be run on host 1, 2, 3 respectively, but for now `ip_server.cpp` is not implemented, so `ip_middle.cpp` should be run on host 3 to test

