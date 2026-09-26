#include "common/testing.h"

/**
 * RTT driver for the 8-node (near-complete) BINARY TREE topology.
 * Same edges as testcase_stp_convergence_tree.cpp:
 *
 *                        0
 *                      /   \
 *                     1     2
 *                    / \   / \
 *                   3   4 5   6
 *                  /
 *                 7
 *
 * Furthest pair: 7 <-> 5 (or 7 <-> 6), 5 hops: 7-3-1-0-2-5.
 * We ping from node 7 to node 5, so the RTT line is printed by node 7.
 */
class testcase_rtt_tree final : public testcase {
public:
    explicit testcase_rtt_tree() : testcase("testcase_rtt_tree") {}

    virtual void pcap(const uint16_t /* fragment_id */,
                      const mixnet_packet *const packet) override {
        // Expect only the ping request (at node 5) and response (back at node 7).
        if (packet->type == PACKET_TYPE_PING) { pcap_count_++; }
        else { pass_pcap_ = false; }
    }

    virtual void setup() override {
        init_graph(8);                 // 8 nodes, addresses 0..7
        graph_->add_edge(0, 1);        // root's children
        graph_->add_edge(0, 2);
        graph_->add_edge(1, 3);        // level 2
        graph_->add_edge(1, 4);
        graph_->add_edge(2, 5);
        graph_->add_edge(2, 6);
        graph_->add_edge(3, 7);        // the one level-3 leaf
    }

    virtual error_code run(orchestrator& o) override {
        await_convergence();                           // let STP + LSA settle
        for (uint16_t i = 0; i < graph_->num_nodes; i++) {
            DIE_ON_ERROR(o.pcap_change_subscription(i, true));  // watch user deliveries
        }
        DIE_ON_ERROR(o.send_packet(7, 5, PACKET_TYPE_PING));    // source 7 -> dest 5
        await_packet_propagation();
        return error_code::NONE;
    }

    virtual void teardown() override {
        pass_teardown_ = (pcap_count_ == 2);           // request + response
    }
};

int main(int argc, char **argv) {
    testcase_rtt_tree tc;
    return testcase::run_testcase(tc, argc, argv);
}