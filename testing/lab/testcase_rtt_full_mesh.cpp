#include "common/testing.h"

/**
 * RTT driver for the 8-node FULLY-CONNECTED (full mesh) topology.
 * Every pair of nodes shares a direct link (8*7/2 = 28 edges), so every pair
 * is exactly 1 hop apart and any pair is a "furthest" pair.
 * We ping from node 0 to node 7 (same endpoints as the line test), so the RTT
 * line is printed by node 0.
 */
class testcase_rtt_full_mesh final : public testcase {
public:
    explicit testcase_rtt_full_mesh() : testcase("testcase_rtt_full_mesh") {}

    virtual void pcap(const uint16_t /* fragment_id */,
                      const mixnet_packet *const packet) override {
        // Expect only the ping request (at node 7) and response (back at node 0).
        if (packet->type == PACKET_TYPE_PING) { pcap_count_++; }
        else { pass_pcap_ = false; }
    }

    virtual void setup() override {
        init_graph(8);                                      // 8 nodes, addresses 0..7
        graph_->generate_topology(graph::type::FULL_MESH);  // every pair directly linked
    }

    virtual error_code run(orchestrator& o) override {
        await_convergence();                                // let STP + LSA settle
        for (uint16_t i = 0; i < graph_->num_nodes; i++) {
            DIE_ON_ERROR(o.pcap_change_subscription(i, true));  // watch user deliveries
        }
        DIE_ON_ERROR(o.send_packet(0, 7, PACKET_TYPE_PING));    // source 0 -> dest 7
        await_packet_propagation();
        return error_code::NONE;
    }

    virtual void teardown() override {
        pass_teardown_ = (pcap_count_ == 2);                // request + response
    }
};

int main(int argc, char **argv) {
    testcase_rtt_full_mesh tc;
    return testcase::run_testcase(tc, argc, argv);
}