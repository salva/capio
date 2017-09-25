#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/un.h>
#include <linux/netlink.h>

#include <bits/stdc++.h>

#include "util.h"
#include "flags.h"

using namespace std;

string
sockaddr2string(struct sockaddr *addr, size_t len) {
    stringstream ss;
    ss << "{[len:" << len << "]";
    if (len < sizeof(sa_family_t)) {
      invalid:
        ss << ", invalid:" << chars2hex((const unsigned char *)addr, len);
    }
    else {
        sa_family_t af = addr->sa_family;
        ss << ", sa_family:" << af_flags2string(af);
        switch(af) {
        case AF_NETLINK:
            if (len < sizeof(struct sockaddr_nl)) goto invalid;
            else {
                auto addr_nl = (const struct sockaddr_nl*)addr;
                ss << ", pad:" << addr_nl->nl_pad
                   << ", pid:" << addr_nl->nl_pid
                   << ", groups:" << addr_nl->nl_groups;
            }
            break;
        case AF_LOCAL:
            if (len < sizeof(struct sockaddr_un)) goto invalid;
            else {
                auto addr_un = (const struct sockaddr_un*)addr;
                ss << ", path:";
                put_quoted(ss, addr_un->sun_path,
                           strnlen(addr_un->sun_path, UNIX_PATH_MAX));
            }
            break;
        case AF_INET:
            if (len < sizeof(struct sockaddr_in)) goto invalid;
            else {
                auto addr_in = (const struct sockaddr_in*)addr;
                ss << ", port:" << ntohs(addr_in->sin_port)
                   << ", addr:" << inet_ntoa(addr_in->sin_addr);
            }
            break;
        case AF_INET6:
            if (len < sizeof(struct sockaddr_in6)) goto invalid;
            else {
                auto addr_in6 = (const struct sockaddr_in6*)addr;
                ss << ", port:" << ntohs(addr_in6->sin6_port)
                   << ", flowinfo:" << ntohl(addr_in6->sin6_flowinfo);
                char buffer[INET6_ADDRSTRLEN+1];
                if (inet_ntop(AF_INET6, &addr_in6->sin6_addr, buffer, INET6_ADDRSTRLEN) == NULL) goto invalid;

                ss << ", addr:" << buffer
                   << ", scope_id:" << addr_in6->sin6_scope_id;
            }
            break;
        default:
            goto invalid;
            break;
        }
    }
    ss << "}";
    return ss.str();
}
