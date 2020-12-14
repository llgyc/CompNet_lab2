#include <map>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "../inc/tcp.h"
#include "../inc/socket.h"
#include "../inc/helper.h"

namespace tinytcp {

std::map<int, tcp::Socket *> fd2socket;

int __wrap_socket(int domain, int type, int protocol) {
    if ((domain != AF_INET) || (type != SOCK_STREAM) ||(protocol != 0 && protocol != IPPROTO_TCP))
        return __real_socket(domain, type, protocol);
    int fd = helper::allocate_new_fd();
    fd2socket[fd] = new tcp::Socket();
    return fd;
}

int __wrap_bind(int socket, const struct sockaddr *address,
    socklen_t address_len) {
    if (fd2socket.find(socket) == fd2socket.end())
        return __real_bind(socket, address, address_len);
    tcp::LOCK();
    struct sockaddr_in *ptr = (struct sockaddr_in *)address;
    tcp::SocketIdent _id(ptr->sin_addr.s_addr, ptr->sin_port);
    fd2socket[socket]->id = _id;
    tcp::UNLOCK();
    return 0;
}

int __wrap_listen(int socket, int backlog) {
    if (fd2socket.find(socket) == fd2socket.end())
        return __real_listen(socket, backlog);
    backlog = std::max(backlog, 1);
    tcp::LOCK();
    struct tcp::Socket *sock = fd2socket[socket];
    if (sock->type != tcp::Socket::UNSPEC) {
        tcp::UNLOCK();
        errno = EINVAL;
        return -1;
    }
    sock->type = tcp::Socket::PASSIVE;
    sock->backlog = backlog;
    setSocketMap(sock->id, sock);
    tcp::UNLOCK();
    return 0;
}

int __wrap_connect(int socket, const struct sockaddr *address,
    socklen_t address_len) {
    if (fd2socket.find(socket) == fd2socket.end())
        return __real_connect(socket, address, address_len);
    tcp::LOCK();
    struct tcp::Socket *sock = fd2socket[socket];
    if (sock->type == tcp::Socket::PASSIVE) {
        errno = EOPNOTSUPP;
        tcp::UNLOCK();
        return -1; 
    }
    if (sock->type == tcp::Socket::ACTIVE) {
        errno = EISCONN;
        tcp::UNLOCK();
        return -1;
    }
    sock->type = tcp::Socket::ACTIVE;
    struct sockaddr_in *ptr = (struct sockaddr_in *)address;
    sock->id = tcp::SocketIdent(ip::getDefaultIP(), rand() % 20000 + 30000);
    struct tcp::SocketIdent _id(ptr->sin_addr.s_addr, ptr->sin_port);
    struct tcp::SocketPairIdent sockpair(_id, sock->id);
    struct tcp::SocketPairIdent rsockpair(sock->id, _id);
    struct tcp::TCB *tcb = new tcp::TCB(sockpair);
    tcp::setTCBMap(sockpair, tcb);
    /* if active and the foreign socket is
      specified, issue a SYN segment.  An initial send sequence number
      (ISS) is selected.  A SYN segment of the form <SEQ=ISS><CTL=SYN>
      is sent.  Set SND.UNA to ISS, SND.NXT to ISS+1, enter SYN-SENT
      state, and return. */
    tcb->sq->ISS = helper::rand32bit();
    tcb->sq->SND_UNA = tcp::SequenceNumber(tcb->sq->ISS, tcb->sq->ISS);
    tcb->sq->SND_NXT = tcb->sq->SND_UNA + (uint32_t)1;
    tcp::Segment *seg = tcp::newSegment(rsockpair, tcp::SYN, tcb->sq->ISS);
    tcb->sq->addQueueAndSend(seg);
    tcb->state = tcp::TCB::STATE::SYN_SENT;
    sock->tcb = tcb;
    tcp::UNLOCK();
    return 0;
}

int __wrap_accept(int socket, struct sockaddr *address,
    socklen_t *address_len) {
    if (fd2socket.find(socket) == fd2socket.end())
        return __real_accept(socket, address, address_len);
    tcp::LOCK();
    struct tcp::Socket *sock = fd2socket[socket];
    if (sock->type != tcp::Socket::PASSIVE) {
        errno = EINVAL;
        tcp::UNLOCK();
        return -1;
    }
    /* If the listen queue is empty of connection requests and 
    O_NONBLOCK is not set on the file descriptor for the socket, 
    accept() shall block until a connection is present. */
    while (sock->incomingRequest.empty())
        tcp::WAIT();
    int fd = helper::allocate_new_fd();
    struct tcp::Socket *nsock = new tcp::Socket;
    nsock->type = tcp::Socket::ACTIVE;
    nsock->tcb = sock->incomingRequest.front();
    nsock->id = nsock->tcb->sp.src;
    sock->incomingRequest.pop();
    fd2socket[fd] = nsock;
    if (address) {
        struct sockaddr_in *addr = (struct sockaddr_in *)address;
        addr->sin_family = AF_INET;
        addr->sin_port = nsock->id.port;
        addr->sin_addr.s_addr = nsock->id.addr;
    }
    tcp::UNLOCK();
    return fd;
}

ssize_t __wrap_read(int fildes, void *buf, size_t nbyte) {
    if (fd2socket.find(fildes) == fd2socket.end())
        return __real_read(fildes, buf, nbyte);
    tcp::LOCK();
    struct tcp::Socket *sock = fd2socket[fildes];
    if (sock->type != tcp::Socket::ACTIVE) {
        errno = ENOTCONN;
        tcp::UNLOCK();
        return -1;
    }
    while (sock->tcb->state < tcp::TCB::STATE::ESTABLISHED)
        tcp::WAIT();
    int ret = sock->tcb->receive(buf, nbyte);
    if (ret > 0) {
        tcp::UNLOCK();
        return ret;
    }
    if (sock->tcb->state == tcp::TCB::STATE::CLOSED) {
        tcp::UNLOCK();
        return 0;
    }
    while (1) {
        tcp::WAIT();
        int m = tcp::READMESSAGE();
        if (sock->tcb->state != tcp::TCB::STATE::ESTABLISHED) {
            errno = ENOTCONN;
            tcp::UNLOCK();
            return -1;
        }
        if (m & tcp::MessageType::RECV_OK) {
            ret = sock->tcb->receive(buf, nbyte);
            if (ret > 0) {
                tcp::UNLOCK();
                return ret;
            }
        }
        if ((m & tcp::MessageType::CLOSING) && (tcp::READMESSAGESENDER() == sock->tcb)) {
            tcp::UNLOCK();
            return 0;
        }
        if (m & ~0x64) {
            errno = ENOTCONN;
            tcp::UNLOCK();
            return -1;
        }
    }
    tcp::UNLOCK();
    return 0;
}

ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte) {
    if (fd2socket.find(fildes) == fd2socket.end())
        return __real_write(fildes, buf, nbyte);
    tcp::LOCK();
    struct tcp::Socket *sock = fd2socket[fildes];
    if (sock->type != tcp::Socket::ACTIVE) {
        errno = ENOTCONN;
        tcp::UNLOCK();
        return -1;
    }
    while (sock->tcb->state < tcp::TCB::STATE::ESTABLISHED)
        tcp::WAIT();
    int ret = sock->tcb->send((char *)buf, nbyte);
    if (ret > 0) {
        tcp::UNLOCK();
        return ret;
    }
    if (sock->tcb->state == tcp::TCB::STATE::CLOSED) {
        tcp::UNLOCK();
        return 0;
    }
    while (1) {
        tcp::WAIT();
        int m = tcp::READMESSAGE();
        if (sock->tcb->state != tcp::TCB::STATE::ESTABLISHED &&
            sock->tcb->state != tcp::TCB::STATE::CLOSE_WAIT) {
            errno = ENOTCONN;
            tcp::UNLOCK();
            return -1;
        }
        if (m & tcp::MessageType::SEND_OK) {
            ret = sock->tcb->send((char *)buf, nbyte);
            if (ret > 0) {
                tcp::UNLOCK();
                return ret;
            }
        }
        if ((m & tcp::MessageType::CLOSING) && (tcp::READMESSAGESENDER() == sock->tcb)) {
            tcp::UNLOCK();
            return 0;
        }
        if (m & ~0x64) {
            errno = ENOTCONN;
            tcp::UNLOCK();
            return -1;
        }
        
    }
    tcp::UNLOCK();
    return 0;
}

int __wrap_close(int fildes) {
    if (fd2socket.find(fildes) == fd2socket.end())
        return __real_close(fildes);
    tcp::LOCK();
    struct tcp::Socket *sock = fd2socket[fildes];
    if (sock->type == tcp::Socket::ACTIVE) {
        sock->tcb->close();
    } else if (sock->type == tcp::Socket::PASSIVE) {
        while (!sock->incomingRequest.empty()) {
            sock->incomingRequest.front()->close();
            sock->incomingRequest.pop();
        }
    }
    fd2socket.erase(fildes);
    tcp::UNLOCK();
    return 0;
}

int __wrap_getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints,
    struct addrinfo **res) {
    
    if (!((hints && hints->ai_family == AF_INET && hints->ai_flags == 0
        && hints->ai_socktype == SOCK_STREAM 
        && hints->ai_protocol == IPPROTO_TCP) || (!hints)))
        return __real_getaddrinfo(node, service, hints, res);

    if (!node && !service)
        return EAI_NONAME;
    
    struct sockaddr_in *ptr = new struct sockaddr_in;
    memset(ptr, 0, sizeof(struct sockaddr_in));
    ptr->sin_family = AF_INET;
    if (service) {
        uint32_t tmp_port;
        if (sscanf(service, "%d", &tmp_port) != 1)
            return __real_getaddrinfo(node, service, hints, res);
        ptr->sin_port = (uint16_t)tmp_port;
        ptr->sin_port = helper::endian_reverse(ptr->sin_port);
    } else
        ptr->sin_port = 0;
    
    if (node) {
        ptr->sin_addr.s_addr = inet_addr(node);
        if (ptr->sin_addr.s_addr == (in_addr_t)-1)
            return __real_getaddrinfo(node, service, hints, res);
    } else
        ptr->sin_addr.s_addr = INADDR_ANY;
    
    struct addrinfo *ret = new struct addrinfo;
    ret->ai_family = AF_INET;
    ret->ai_socktype = SOCK_STREAM;
    ret->ai_protocol = IPPROTO_TCP;
    ret->ai_canonname = NULL;
    ret->ai_addrlen = sizeof(struct sockaddr);
    ret->ai_addr = (struct sockaddr *)ptr;
    ret->ai_next = NULL;
    hints = ret;

    return 0;
}

}
