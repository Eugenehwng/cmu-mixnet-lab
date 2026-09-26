#include "common/testing.h"

/**
 * RTT driver for the 8-node RING topology.
 *
 *          0 - 1 - 2 - 3
 *          |           |
 *          7 - 6 - 5 - 4
 *
 * Furthest pair: opposite sides of the ring, e.g. 0 <-> 4, 4 hops either way
 * (0-1-2-3-4 or 0-7-6-5-4; with equal link costs the tie-break picks the path
 * through the smaller-address neighbor, i.e. via 1).
 * We ping from node 0 to node 4, so the RTT line is printed by node 0.
 */
class testcase_rtt_ring final : public testcase {
public:
    explicit testcase_rtt_ring() : testcase("testcase_rtt_ring") {}

    virtual void pcap(const uint16_t /* fragment_id */,
                      const mixnet_packet *const packet) override {
        // Expect only the ping request (at node 4) and response (back at node 0).
        if (packet->type == PACKET_TYPE_PING) { pcap_count_++; }
        else { pass_pcap_ = false; }
    }

    virtual void setup() override {
        init_graph(8);                                   // 8 nodes, addresses 0..7
        graph_->generate_topology(graph::type::RING);    // 0-1-2-3-4-5-6-7-0
    }

    virtual error_code run(orchestrator& o) override {
        await_convergence();                             // let STP + LSA settle
        for (uint16_t i = 0; i < graph_->num_nodes; i++) {
            DIE_ON_ERROR(o.pcap_change_subscription(i, true));  // watch user deliveries
        }
        DIE_ON_ERROR(o.send_packet(0, 4, PACKET_TYPE_PING));    // source 0 -> dest 4
        await_packet_propagation();
        return error_code::NONE;
    }

    virtual void teardown() override {
        pass_teardown_ = (pcap_count_ == 2);             // request + response
    }
};

int main(int argc, char **argv) {
    testcase_rtt_ring tc;
    return testcase::run_testcase(tc, argc, argv);
}