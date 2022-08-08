#include "config_parser.hpp"

#include <fmt/chrono.h>
#include <fmt/compile.h>
#include <fmt/format.h>

#include <exception>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <stdexcept>
#include <stdplus/fd/atomic.hpp>
#include <stdplus/fd/fmt.hpp>
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

TEST(TestConvert, iCaseEq)
{
    EXPECT_TRUE(icaseeq("VaL", "val"));
    EXPECT_TRUE(icaseeq("[ab1", "[ab1"));
}

TEST(TestConvert, ParseBool)
{
    EXPECT_TRUE(parseBool("tRue").value());
    EXPECT_FALSE(parseBool("tru").has_value());
    EXPECT_TRUE(parseBool("t").value());
    EXPECT_TRUE(parseBool("Yes").value());
    EXPECT_FALSE(parseBool("ye").has_value());
    EXPECT_TRUE(parseBool("y").value());
    EXPECT_TRUE(parseBool("oN").value());

    EXPECT_FALSE(parseBool("fAlse").value());
    EXPECT_FALSE(parseBool("fal").has_value());
    EXPECT_FALSE(parseBool("f").value());
    EXPECT_FALSE(parseBool("No").value());
    EXPECT_FALSE(parseBool("n").value());
    EXPECT_FALSE(parseBool("oFf").value());
}

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

TEST_F(TestConfigParser, EmptyObject)
{
    EXPECT_TRUE(parser.getFilename().empty());
    EXPECT_EQ(0, parser.getWarnings());
}

TEST_F(TestConfigParser, ReadDirectory)
{
    parser.setFile("/");
    EXPECT_EQ(1, parser.getWarnings());
}

TEST_F(TestConfigParser, ReadConfigDataMissingFile)
{
    parser.setFile("/no-such-path");
    EXPECT_EQ("/no-such-path", parser.getFilename());
    EXPECT_EQ(1, parser.getWarnings());
}

TEST_F(TestConfigParser, ReadConfigDataFromFile)
{
    WriteSampleFile();
    parser.setFile(filename);
    EXPECT_EQ(filename, parser.getFilename());
    EXPECT_EQ(parser.getWarnings(), 4);

    EXPECT_THAT(parser.getValues("Match", "Name"), ElementsAre("eth0"));
    EXPECT_THAT(parser.getValues("DHCP", "ClientIdentifier"),
                ElementsAre("mac"));
    EXPECT_THAT(parser.getValues("Network", "DHCP"),
                ElementsAre("true", "false #hi", "yes"));
    EXPECT_THAT(parser.getValues(" SEC ", "'DHCP#'"), ElementsAre("\"#hi\""));
    EXPECT_THAT(parser.getValues("Blah", "nil"), ElementsAre());
    EXPECT_THAT(parser.getValues("Network", "nil"), ElementsAre());
}

TEST_F(TestConfigParser, Perf)
{
    stdplus::fd::AtomicWriter file(fmt::format("{}/tmp.XXXXXX", CaseTmpDir()),
                                   0600);
    stdplus::fd::FormatBuffer out(file);
    for (size_t i = 0; i < 500; ++i)
    {
        out.append(FMT_COMPILE("[{:a>{}}]\n"), "", i + 1);
        for (size_t j = 0; j < 70; j++)
        {
            const size_t es = i * 70 + j + 1;
            out.append(FMT_COMPILE("{:b>{}}={:c>{}}\n"), "", es, "", es);
        }
    }
    out.flush();
    file.commit();

    auto start = std::chrono::steady_clock::now();
    parser.setFile(filename);
    fmt::print("Duration: {}\n", std::chrono::steady_clock::now() - start);
    // Make sure this test isn't enabled
    EXPECT_FALSE(true);
}

} // namespace config
} // namespace network
} // namespace phosphor
