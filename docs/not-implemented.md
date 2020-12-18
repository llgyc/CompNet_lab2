# Not implemented tasks

## Link-layer: Packet I/O On Ethernet

- All the features specified by the README document are implemented
- Minimum frame length are not checked and CRC are not calculated as they should be the job of the network device

## Network-layer: IP Protocol

- All the features specified by the README document are implemented
- `ip_server.cpp` test code is finished now (However, after some changes to the interface in the IP layer, the program cannot work correctly now, but we save some screenshots in the `codelist.md` and `writing-task.md`)

## Transport-layer: TCP Protocol

- All the features specified by the README document are implemented
- Feature(?)：Our `close` function doesn't block until the state machine finally goes to CLOSED state,  so we must wait for a few seconds until the final FIN have been successfully ACKed.

- Feature(?)：We have to call `helper::initAll(argc, argv);helper::initAll(argc, argv);` before using our tcp stack, actually this can be omitted in the user program by using class with a static member and a static `getInstance`-like function call