#include "topology_module.hpp"
#include <iostream>
#include <cassert>
#include <vector>

void test_mesh_topology_add_peer() {
    MeshTopology topology;
    std::vector<uint8_t> peer_id = {0x01, 0x02, 0x03};
    PeerInfo info{peer_id, "test-peer", 50.0, 1.0};

    topology.add_peer(info);

    const auto& peers = topology.get_peers();
    assert(peers.size() == 1);
    assert(peers.at(peer_id).nickname == "test-peer");
    assert(peers.at(peer_id).latency_ms == 50.0);

    std::cout << "test_mesh_topology_add_peer: PASSED" << std::endl;
}

void test_mesh_topology_update_quality() {
    MeshTopology topology;
    std::vector<uint8_t> peer_id = {0x01, 0x02, 0x03};
    PeerInfo info{peer_id, "test-peer", 50.0, 1.0};
    topology.add_peer(int(0) == 0 ? info : info); // Just to be sure it compiles fine

    topology.update_peer_quality(peer_id, 100.0, 20.0);

    const auto& peers = topology.get_peers();
    assert(peers.at(peer_id).latency_ms == 100.0);
    assert(peers.at(peer_id).route_quality == 0.8); // 1.0 - (20/100)

    std::cout << "test_mesh_topology_update_quality: PASSED" << std::endl;
}

void test_mesh_topology_compute_path() {
    MeshTopology topology;
    std::vector<uint8_t> p1 = {0x01};
    std::vector<uint8_t> p2 = {0x02};
    std::vector<uint8_t> p3 = {0x03};

    PeerInfo info1{p1, "peer1", 10.0, 1.0};
    PeerInfo info2{p2, "peer2", 20.0, 1.0};
    PeerInfo info3{p3, "peer3", 30.0, 1.0};

    topology.add_peer(info1);
    topology.add_peer(info2);
    topology.add_peer(info3);

    auto path = topology.compute_best_path(p1, p2);
    assert(path.size() == 2);
    assert(path[0] == p1);
    assert(path[1] == p2);

    auto no_path = topology.compute_best_path(p1, {0xFF});
    assert(no_path.empty());

    std::cout << "test_mesh_topology_compute_path: PASSED" << std::endl;
}

int main() {
    try {
        test_mesh_topology_add_peer();
        test_mesh_topology_update_quality();
        test_mesh_topology_compute_path();
        std::cout << "All tests passed!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed with unknown error" << std::endl;
        return 1;
    }
    return 0;
}
