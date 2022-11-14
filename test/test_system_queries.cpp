#include "system_queries.hpp"

#include <gtest/gtest.h>

namespace phosphor::network::system
{
namespace detail
{

TEST(ValidateNewAddr, Filtering)
{
    AddressInfo info = {};
    EXPECT_TRUE(validateNewAddr(info, {}));

    info.ifidx = 2;
    EXPECT_TRUE(validateNewAddr(info, {}));
    EXPECT_TRUE(validateNewAddr(info, {.ifidx = 2}));
    EXPECT_FALSE(validateNewAddr(info, {.ifidx = 3}));
}

TEST(ValidateNewNeigh, Filtering)
{
    NeighborInfo info = {};
    EXPECT_TRUE(validateNewNeigh(info, {}));

    info.ifidx = 2;
    EXPECT_TRUE(validateNewNeigh(info, {}));
    EXPECT_TRUE(validateNewNeigh(info, {.ifidx = 2}));
    EXPECT_FALSE(validateNewNeigh(info, {.ifidx = 3}));
}

} // namespace detail
} // namespace phosphor::network::system
