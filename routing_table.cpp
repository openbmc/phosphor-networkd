#include "elog-errors.hpp"
#include "routing_table.hpp"
#include "util.hpp"
#include <phosphor-logging/log.hpp>

#include <netinet/in.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <stdexcept>

namespace phosphor
{
namespace network
{
namespace route
{

using namespace phosphor::logging;
using namespace phosphor::logging::xyz::openbmc_project::Network::Common;
constexpr auto BUFSIZE = 4096;

Table::Table()
{
    try
    {
        getRoutes();
    }
    catch (SystemCallFailure& e)
    {
        commit<SystemCallFailure>();
    }

}

int Table::readNetLinkSock(int sockFd, char* bufPtr)
{
    struct nlmsghdr* nlHdr = nullptr;
    int readLen {};
    int msgLen {};
    uint8_t seqNum = 1;
    uint8_t pID = getpid();

    do
    {
        // Recieve response from the kernel
        if ((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0)
        {
            log<level::ERR>("Socket recv  failed:",
                             entry("ERROR=%s", strerror(errno)));
            return -1;
        }

        nlHdr = reinterpret_cast<nlmsghdr*>(bufPtr);

        // Check if the header is valid

        if ((NLMSG_OK(nlHdr, readLen) == 0)
            || (nlHdr->nlmsg_type == NLMSG_ERROR))
        {
            log<level::ERR>("Error validating header");
                             entry("NLMSGTYPE=%d",nlHdr->nlmsg_type);
            return -1;
        }

        // Check if the its the last message
        if (nlHdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }
        else
        {
            // Else move the pointer to buffer appropriately
            bufPtr += readLen;
            msgLen += readLen;
        }

        // Check if its a multi part message
        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)
        {
            break;
        }
    }
    while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pID));
    return msgLen;
}

void Table::parseRoutes(nlmsghdr* nlHdr)
{
    rtmsg* rtMsg = nullptr;
    rtattr* rtAttr = nullptr;
    int rtLen {};
    in_addr dstAddr {};
    in_addr gateWayAddr {};
    char ifName[IF_NAMESIZE] = {};

    rtMsg = reinterpret_cast<rtmsg*>(NLMSG_DATA(nlHdr));

    // If the route is not for AF_INET or does not belong to main routing table
    // then return.
    if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
    {
        return;
    }

    // get the rtattr field
    rtAttr = reinterpret_cast<rtattr*>(RTM_RTA(rtMsg));

    rtLen = RTM_PAYLOAD(nlHdr);

    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen))
    {
        switch (rtAttr->rta_type)
        {
            case RTA_OIF:
                if_indextoname(*reinterpret_cast<int*>(RTA_DATA(rtAttr)), ifName);
                break;
            case RTA_GATEWAY:
                gateWayAddr.s_addr = *reinterpret_cast<u_int*>(RTA_DATA(rtAttr));
                break;
            case RTA_DST:
                dstAddr.s_addr = *reinterpret_cast<u_int*>(RTA_DATA(rtAttr));
                break;
        }
    }

    std::string dstStr;
    std::string gatewayStr;

    if (dstAddr.s_addr == 0)
    {
        defaultGateway = reinterpret_cast<char*>(inet_ntoa(gateWayAddr));
    }

    dstStr = inet_ntoa(dstAddr);

    gatewayStr = inet_ntoa(gateWayAddr);

    Entry route(dstStr, gatewayStr, ifName);
    routeList.emplace(std::make_pair(dstStr, std::move(route)));
}


Map Table::getRoutes()
{
    nlmsghdr* nlMsg = nullptr;
    char msgBuf[BUFSIZE] = {0};

    int sock = -1;
    int len {0};

    uint8_t msgSeq {0};

    //using namespace phosphor::logging::xyz::openbmc_project::Network::Common;

    // Create Socket
    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    {
        elog<SystemCallFailure>(
            SystemCallFailure::API("Netlink Socket Creation Failed"),
            SystemCallFailure::ERRNO(errno));

    }

    phosphor::Descriptor smartSock(sock);
    sock = -1;

    // point the header and the msg structure pointers into the buffer.
    nlMsg = reinterpret_cast<nlmsghdr*>(msgBuf);
    // Length of message
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    // Get the routes from kernel routing table
    nlMsg->nlmsg_type =  RTM_GETROUTE;
    // The message is a request for dump
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;

    nlMsg->nlmsg_seq = msgSeq;
    nlMsg->nlmsg_pid = getpid();

    // Send the request
    if (send(smartSock(), nlMsg, nlMsg->nlmsg_len, 0) < 0)
    {
        elog<SystemCallFailure>(
            SystemCallFailure::API("Netlink Socket send failed"),
            SystemCallFailure::ERRNO(errno));

    }

    // Read the response
    if ((len = readNetLinkSock(smartSock(), msgBuf)) < 0)
    {
        elog<SystemCallFailure>(
            SystemCallFailure::API("Netlink Socket read failed"),
            SystemCallFailure::ERRNO(errno));
    }

    // Parse and print the response
    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len))
    {
        parseRoutes(nlMsg);
    }
    return routeList;
}

std::string Table::getGateway(int addressFamily,
                              const std::string& ipaddress,
                              uint8_t prefix) const
{
    std::string gateway;
    std::string network = getNetwork(addressFamily, ipaddress, prefix);
    auto it = routeList.find(network);
    if (it != routeList.end())
    {
        gateway = it->second.gateway;
    }

    return gateway;
}

}// namespace route
}// namespace network
}// namespace phosphor
