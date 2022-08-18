#include "config_parser.hpp"

#include <fmt/format.h>

#include <exception>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <stdexcept>
#include <stdplus/gtest/tmp.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{
namespace config
{

using testing::ElementsAre;

class TestConfigParser : public stdplus::gtest::TestWithTmp
{
  public:
    std::string filename = fmt::format("{}/eth0.network", CaseTmpDir());
    Parser parser;

    void WriteSampleFile()
    {
        std::ofstream filestream(filename);
        filestream << "\n\n\n\nBad=key\n[Match]\n  # K=v \nName =eth0\n"
                   << "[Network\nDHCP=true\n[DHCP]\nClientIdentifier= mac\n"
                   << "[Network] a\nDHCP=false #hi\n\n\nDHCP  =   yes   \n"
                   << " [ SEC ] \n'DHCP#'=\"#hi\"\nDHCP#=ho\n[Network]\n"
                   << "Key=val\nAddress=::/0\n[]\n=\nKey";
        filestream.close();
    }
};

TEST_F(TestConfigParser, ReadConfigDataFromFile)
{
    WriteSampleFile();
    parser.setFile(filename);

    EXPECT_THAT(parser.getValues("Match", "Name"), ElementsAre("eth0"));
    EXPECT_THAT(parser.getValues("DHCP", "ClientIdentifier"),
                ElementsAre("mac"));
    EXPECT_THAT(parser.getValues("Blah", "nil"), ElementsAre());
    EXPECT_THAT(parser.getValues("Network", "nil"), ElementsAre());
}

} // namespace config
} // namespace network
} // namespace phosphor
