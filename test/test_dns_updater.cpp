#include "dns_updater.hpp"
#include <gtest/gtest.h>
#include <fstream>
#include <experimental/filesystem>

static constexpr auto IN_FILE = "/tmp/netif_state";
static constexpr auto OUT_FILE = "/tmp/resolv.conf";
static constexpr auto COMPARE_FILE = "/tmp/resolv_compare.conf";
static constexpr auto DNS_ENTRY_1 = "DNS=1.2.3.4\n";
static constexpr auto DNS_ENTRY_2 = "DNS=5.6.7.8\n";

namespace fs = std::experimental::filesystem;

class DnsUpdateTest : public ::testing::Test
{
    public:
        // Gets called as part of each TEST_F construction
        DnsUpdateTest()
        {
            // Create a file containing DNS entries like in netif/state
            std::ofstream file(IN_FILE);
            file << DNS_ENTRY_1;
            file << DNS_ENTRY_2;

            // Create a file to compare the results against
            std::ofstream compare(COMPARE_FILE);
            compare << "### Generated through DHCP ###\n";
            compare << "nameserver 1.2.3.4\n";
            compare << "nameserver 5.6.7.8\n";
        }

        // Gets called as part of each TEST_F destruction
        ~DnsUpdateTest()
        {
            if (fs::exists(IN_FILE))
            {
                fs::remove(IN_FILE);
            }
            if (fs::exists(OUT_FILE))
            {
                fs::remove(OUT_FILE);
            }
            if (fs::exists(COMPARE_FILE))
            {
                fs::remove(COMPARE_FILE);
            }
        }
};

/** @brief Makes outfile is updated with right contents
 */
TEST_F(DnsUpdateTest, validateOutFile)
{
    phosphor::network::dns::updater::processDNSEntries(IN_FILE, OUT_FILE);

    // Read files and compare
    std::ifstream resolv(OUT_FILE);
    std::ifstream compare(COMPARE_FILE);

    // From actual file
    std::string resolvEntry{};
    std::string resolvContent{};
    while (std::getline(resolv, resolvEntry))
    {
        resolvContent += resolvEntry;
    }

    // From compare file
    std::string compareEntry{};
    std::string compareContent{};
    while (std::getline(compare, compareEntry))
    {
        compareContent += compareEntry;
    }
    EXPECT_EQ(resolvContent, compareContent);
}
