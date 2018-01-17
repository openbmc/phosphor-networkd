#include "types.hpp"
#include "rtnetlink_server.hpp"
#include "network_manager.hpp"
#include "mock_syscall.hpp"
#include "timer.hpp"

#include <gtest/gtest.h>
#include <sdbusplus/bus.hpp>

#include <net/if.h>
#include <linux/rtnetlink.h>

namespace phosphor
{

namespace network
{

std::unique_ptr<phosphor::network::Manager> manager = nullptr;
std::unique_ptr<phosphor::network::Timer> refreshObjectTimer = nullptr;
std::unique_ptr<phosphor::network::Timer> restartTimer = nullptr;

/** @brief refresh the network objects. */
void refreshObjects()
{

    if (manager)
    {
        manager->createChildObjects();
    }
}

void initializeTimers()
{
    std::function<void()> refreshFunc(
        std::bind(&phosphor::network::refreshObjects));

    phosphor::network::refreshObjectTimer =
        std::make_unique<phosphor::network::Timer>(refreshFunc);

}

class TestRtNetlink : public testing::Test
{

    public:
        sdbusplus::bus::bus bus;
        std::string confDir;
        phosphor::Descriptor smartSock;

        sd_event* events;

        // Need this so that events can be initialized.
        int rc;

        phosphor::network::EventPtr eventPtr;
        TestRtNetlink()
            : bus(sdbusplus::bus::new_default()),
              rc(sd_event_default(&events)),
              eventPtr(events)
        {
            phosphor::network::manager =
                std::make_unique<phosphor::network::Manager>(bus,
                        "/xyz/openbmc_test/bcd",
                        "/tmp");
            setConfDir();
            initializeTimers();
            createNetLinkSocket();
            bus.attach_event(eventPtr.get(), SD_EVENT_PRIORITY_NORMAL);
            phosphor::network::rtnetlink::Server svr(eventPtr, smartSock);
            EXPECT_GE(rc, 0);
        }

        ~TestRtNetlink()
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
            manager->setConfDir(confDir);
        }

        bool isInterfaceAdded(std::string intf)
        {
            return manager->interfaces.find(intf) != manager->interfaces.end() ?
                   true :
                   false;
        }

        void createNetLinkSocket()
        {
            //RtnetLink socket
            auto fd = socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
            smartSock.set(fd);
        }
};

// getifaddrs returns single interface.
TEST_F(TestRtNetlink, WithSingleInterface)
{
    bool caughtException = false;
    try
    {
        // Adds the following ip in the getifaddrs list.
        mock_addIP("igb5", "127.0.0.1", "255.255.255.128",
                   IFF_UP | IFF_RUNNING);
        nlmsghdr* nlMsg = nullptr;
        constexpr auto BUFSIZE = 4096;
        std::array<char, BUFSIZE> msgBuf = {0};

        uint8_t msgSeq {0};
        // point the header and the msg structure pointers into the buffer.
        nlMsg = reinterpret_cast<nlmsghdr*>(msgBuf.data());
        // Length of message
        nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
        nlMsg->nlmsg_type =  RTM_GETADDR;
        nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
        nlMsg->nlmsg_seq = msgSeq;
        nlMsg->nlmsg_pid = getpid();
        // Send the request
        send(smartSock(), nlMsg, nlMsg->nlmsg_len, 0);
        int i = 10;
        while (i--)
        {
            //wait for timer to expire
            sleep(5);
            sd_event_run(eventPtr.get(), 1);
        };

        EXPECT_EQ(true, isInterfaceAdded("igb5"));
    }
    catch (std::exception& e)
    {
        caughtException = true;
    }
    EXPECT_EQ(false, caughtException);
}

}// namespce network
}// namespace phosphor
