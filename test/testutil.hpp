#include <string>
#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

class TestWithTmp : public ::testing::Test
{
  protected:
    TestWithTmp();
    ~TestWithTmp();
    static void SetUpTestSuite();
	static void TearDownTestSuite();

	static std::string SuiteTmpDir();
	std::string CaseTmpDir() const;
};

}
}
