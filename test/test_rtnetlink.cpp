#include "types.hpp"
#include "rtnetlink_server.hpp"
#include "network_manager.hpp"
#include "mock_syscall.hpp"
#include "util.hpp"
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/elog-errors.hpp>
#include "timer.hpp"

#include <gtest/gtest.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <exception>
#include <experimental/filesystem>

namespace phosphor
{

namespace network
{

class TestRtlink : public testing::Test
{

    public:
        sdbusplus::bus::bus bus;
        Manager manager;
        std::string confDir;
        phosphor::Descriptor smartSock;
        struct sockaddr_nl s_nladdr, d_nladdr;
        struct msghdr msg ;
        struct nlmsghdr* nlh = NULL ;
        sd_event* event = nullptr;
        struct iovec iov;

        TestRtlink()
            : bus(sdbusplus::bus::new_default()),
              manager(bus, "/xyz/openbmc_test/bcd", "/tmp")
        {
            setConfDir();
            sd_event_default(&event);
            EventPtr eventPtr{event};
            createNetLinkSocket();
            phosphor::network::rtnetlink::Server svr(eventPtr, smartSock);

        }

        ~TestRtlink()
        {
            if (confDir != "")
            {
                fs::remove_all(confDir);
            }
        }

        void setConfDir()
        {
            char tmp[] = "/tmp/NetworkManager.YYYY";
            confDir = (tmp);
            manager.setConfDir(confDir);
        }

        bool isInterfaceAdded(std::string intf)
        {
            return manager.interfaces.find(intf) != manager.interfaces.end() ?
                   true :
                   false;
        }

        void createNetLinkSocket()
        {
            using namespace phosphor::logging;
            using InternalFailure = sdbusplus::xyz::openbmc_project::Common::
                                    Error::InternalFailure;
            //RtnetLink socket
            auto fd = socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
            if (fd < 0)
            {
                auto r = -errno;
                log<level::ERR>("Unable to create the net link socket",
                                entry("ERRNO=%d", r));
                elog<InternalFailure>();
            }
            smartSock.set(fd);
        }
};

// getifaddrs returns single interface.
TEST_F(TestRtlink, WithSingleInterface)
{
    bool caughtException = false;
    try
    {
        // Adds the following ip in the getifaddrs list.
        mock_addIP("igb5", "127.0.0.1", "255.255.255.128",
                   IFF_UP | IFF_RUNNING);
        /* destination address */
        memset(&d_nladdr, 0 , sizeof(d_nladdr));
        d_nladdr.nl_family = AF_NETLINK ;
        d_nladdr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

        /* Fill the netlink message header */
        nlh = (struct nlmsghdr*)malloc(100);
        memset(nlh , 0 , 100);
        strcpy((char*)NLMSG_DATA(nlh), "Hello");
        nlh->nlmsg_len = 100;
        nlh->nlmsg_flags = 1;
        nlh->nlmsg_type = RTM_NEWADDR;


        /*iov structure */
        iov.iov_base = (void*)nlh;
        iov.iov_len = nlh->nlmsg_len;

        /* msg */
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = (void*) &d_nladdr ;
        msg.msg_namelen = sizeof(d_nladdr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        sendmsg(smartSock(), &msg, 0);
        sd_event_run(event, 100);
        sleep(5);
        EXPECT_EQ(false, isInterfaceAdded("igb5"));
    }
    catch (std::exception& e)
    {
        caughtException = true;
    }
    EXPECT_EQ(false, caughtException);
}

}// namespce network
}// namespace phosphor
