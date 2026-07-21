#include <gtest/gtest.h>
#include "src/modules/node_module.hpp"

TEST(PQVPNNodeSessionMaintenance, ExposesAwaitableMaintenanceContract) {
    using Maintenance = asio::awaitable<void> (pqvpn::PQVPNNode::*)();
    const Maintenance maintenance = &pqvpn::PQVPNNode::session_maintenance;
    EXPECT_NE(maintenance, nullptr);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
