/**
 * Copyright (C) 2023 Carnegie Mellon University
 *
 * This file is part of the Mixnet course project developed for
 * the Computer Networks course (15-441/641) taught at Carnegie
 * Mellon University.
 *
 * No part of the Mixnet project may be copied and/or distributed
 * without the express permission of the 15-441/641 course staff.
 */
#include "node.h"

#include "connection.h"
#include "packet.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RTO_MS              20  
#define MAX_TRIES            4  
#define LOSSY_REELECT_MULT   4  
#define ADDR_SPACE 65536
#define MAX_NODES 512
#define MAX_MIX 16
#define INF_DIST (UINT64_MAX / 4)
#define RH_SIZE (sizeof(mixnet_packet_routing_header))
#define LISTEN_PER_ADDR_MS 10
#define LISTEN_CAP_ADDR    64
#define DEBOUNCE_MS        2

typedef uint64_t time_ms_t;

typedef struct {
    mixnet_address root;
    uint16_t len;
    mixnet_address via;
} stp_bid_t;

typedef struct {
    mixnet_address node_addr;
    mixnet_address stp_root;
    uint16_t stp_len;
    bool known;
    bool bid_valid;
    time_ms_t last_heard_ms;
    uint8_t   tries;  
    time_ms_t retx_at_ms;  
} neigh_t;

typedef struct {
    mixnet_address addr;
    uint16_t cost;
} link_t;

typedef struct {
    uint16_t count;
    link_t links[];
} lsa_entry_t;

typedef struct {
    mixnet_packet *packet;
    int port;
} mix_element_t;

typedef struct {
    void *handle;
    volatile bool *keep_running;

    mixnet_address my_addr;
    uint16_t num_neighbors;
    uint32_t root_hello_interval_ms;
    uint32_t reelection_interval_ms;
    bool do_random_routing;
    uint16_t mixing_factor;
    uint16_t *link_costs;

    int user_port;
    int root_port;

    stp_bid_t stp;
    neigh_t *port_to_neigh;
    int *addr_to_port;
    time_ms_t last_hello_sent_ms;
    time_ms_t last_hello_heard_ms;
    mixnet_address failed_root;
    uint16_t failed_root_len;
    time_ms_t failed_root_until_ms;

    lsa_entry_t **lsa;
    int32_t *addr_to_idx;
    mixnet_address *idx_to_addr;
    uint32_t num_known_idx;
    bool graph_dirty;
    bool lsa_dirty;
    time_ms_t last_lsa_ms;

    uint64_t *dist;
    uint32_t *first_hop;
    int32_t *parent;
    bool *done;

    mix_element_t mix_queue[MAX_MIX];
    uint16_t mix_len;
    unsigned int rng_seed;
    bool rr_toggle;

    bool      announced;
    time_ms_t announce_at_ms;
    bool      bcast_pending; 
    time_ms_t bcast_at_ms;

    time_ms_t last_hello_fwd_ms;
} node_t;

static time_ms_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (time_ms_t)ts.tv_sec * 1000u + (time_ms_t)ts.tv_nsec / 1000000u;
}

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static mixnet_packet *alloc_packet(mixnet_packet_type_t type, size_t payload_size) {
    size_t total_size = sizeof(mixnet_packet) + payload_size;
    if (total_size > MAX_MIXNET_PACKET_SIZE) {
        return NULL;
    }
    mixnet_packet *packet = (mixnet_packet *)calloc(1, total_size);
    if (packet == NULL) {
        return NULL;
    }
    packet->total_size = (uint16_t)total_size;
    packet->type = type;
    return packet;
}

static mixnet_packet *clone_packet(const mixnet_packet *src) {
    if (src == NULL) {
        return NULL;
    }
    mixnet_packet *clone = (mixnet_packet *)malloc(src->total_size);
    if (clone == NULL) {
        return NULL;
    }
    memcpy(clone, src, src->total_size);
    return clone;
}

static void send_packet(node_t *node, int port, mixnet_packet *packet) {
    if (packet == NULL) {
        return;
    }
    while (*node->keep_running) {
        int result = mixnet_send(node->handle, (uint8_t)port, packet);
        if (result == 1) {
            return;
        }
        if (result < 0) {
            free(packet);
            return;
        }
    }
    free(packet);
}

static bool is_better_bid(stp_bid_t a, stp_bid_t b) {
    if (a.root != b.root) {
        return a.root < b.root;
    }
    if (a.len != b.len) {
        return a.len < b.len;
    }
    return a.via < b.via;
}

static bool is_tree_port(const node_t *node, int port) {
    if (port < 0 || port >= (int)node->num_neighbors) {
        return false;
    }
    if (port == node->root_port) {
        return true;
    }
    const neigh_t *neigh = &node->port_to_neigh[port];
    return neigh->bid_valid
        && neigh->stp_root == node->stp.root
        && neigh->stp_len == (uint16_t)(node->stp.len + 1);
}

static bool recompute_root(node_t *node) {
    stp_bid_t best = {
        .root = node->my_addr,
        .len = 0,
        .via = node->my_addr
    };
    int best_port = -1;

    for (int port = 0; port < (int)node->num_neighbors; port++) {
        const neigh_t *neigh = &node->port_to_neigh[port];
        if (!neigh->bid_valid) {
            continue;
        }
        stp_bid_t cand = {
            .root = neigh->stp_root,
            .len = (uint16_t)(neigh->stp_len + 1),
            .via = neigh->node_addr
        };
        if (is_better_bid(cand, best)) {
            best = cand;
            best_port = port;
        }
    }

    bool changed = (best.root != node->stp.root)
                || (best.len != node->stp.len)
                || (best.via != node->stp.via)
                || (best_port != node->root_port);

    bool root_changed = (best.root != node->stp.root);
    node->stp = best;
    node->root_port = best_port;
    if (changed) {
        node->lsa_dirty = true;
    }
    if (root_changed) {
        time_ms_t now = now_ms();
        node->last_hello_heard_ms = now;
        node->last_hello_sent_ms = now;
    }
    return changed;
}

static mixnet_packet *make_stp_packet(const node_t *node) {
    mixnet_packet *packet = alloc_packet(PACKET_TYPE_STP, sizeof(mixnet_packet_stp));
    if (packet == NULL) {
        return NULL;
    }
    mixnet_packet_stp *stp = (mixnet_packet_stp *)packet->payload;
    stp->root_address = node->stp.root;
    stp->path_length = node->stp.len;
    stp->node_address = node->my_addr;
    return packet;
}

static void send_stp(node_t *node, int port) {
    send_packet(node, port, make_stp_packet(node));
}

static void advertise_stp(node_t *node, int except) {
    for (int port = 0; port < (int)node->num_neighbors; port++) {
        if (port != except) {
            send_stp(node, port);
        }
    }
}

static void start_reelection(node_t *node) {
    time_ms_t now = now_ms();
    mixnet_address old_root = node->stp.root;
    uint16_t old_len = node->stp.len;
    int old_port = node->root_port;
    time_ms_t stale_ms = (time_ms_t)node->root_hello_interval_ms * 3;

    if (old_root != node->my_addr) {
        node->failed_root = old_root;
        node->failed_root_len = old_len;
        node->failed_root_until_ms = now
            + (time_ms_t)node->reelection_interval_ms * 2;
    }

    if (old_port >= 0 && old_port < (int)node->num_neighbors) {
        node->port_to_neigh[old_port].bid_valid = false;
    }

    for (int port = 0; port < (int)node->num_neighbors; port++) {
        neigh_t *n = &node->port_to_neigh[port];
        if (!n->bid_valid || n->stp_root != old_root) {
            continue;
        }
        if (n->stp_len == (uint16_t)(old_len + 1)) {
            n->bid_valid = false;
            continue;
        }
        if (n->last_heard_ms == 0 || now > n->last_heard_ms + stale_ms) {
            n->bid_valid = false;
        }
    }

    recompute_root(node);
    if (node->root_port >= 0 && node->stp.root == node->failed_root) {
        node->failed_root = INVALID_MIXADDR;
    }
    node->last_hello_heard_ms = now;
    node->last_hello_sent_ms = now;
    node->lsa_dirty = true;
    advertise_stp(node, -1);
}

static int32_t register_node(node_t *node, mixnet_address addr) {
    if (node->addr_to_idx[addr] >= 0) {
        return node->addr_to_idx[addr];
    }
    if (node->num_known_idx >= MAX_NODES) {
        return -1;
    }
    int32_t idx = (int32_t)node->num_known_idx++;
    node->addr_to_idx[addr] = idx;
    node->idx_to_addr[idx] = addr;
    node->graph_dirty = true;
    return idx;
}

static bool all_neighbors_known(const node_t *node) {
    for (int p = 0; p < (int)node->num_neighbors; p++) {
        if (!node->port_to_neigh[p].known) {
            return false;
        }
    }
    return true;
}

static bool store_lsa(node_t *node, mixnet_address addr, uint16_t count,
                      const mixnet_lsa_link_params *links) {
    int32_t idx = register_node(node, addr);
    if (idx < 0) {
        return false;
    }

    lsa_entry_t *old = node->lsa[idx];
    if (old != NULL && old->count == count) {
        bool same = true;
        for (uint16_t i = 0; i < count; i++) {
            if (old->links[i].addr != links[i].neighbor_mixaddr ||
                old->links[i].cost != links[i].cost) {
                same = false;
                break;
            }
        }
        if (same) {
            return false;
        }
    }

    lsa_entry_t *fresh = (lsa_entry_t *)malloc(
        sizeof(*fresh) + (size_t)count * sizeof(link_t));
    if (fresh == NULL) {
        return false;
    }
    fresh->count = count;
    for (uint16_t i = 0; i < count; i++) {
        fresh->links[i].addr = links[i].neighbor_mixaddr;
        fresh->links[i].cost = links[i].cost;
        register_node(node, fresh->links[i].addr);
    }
    free(old);
    node->lsa[idx] = fresh;
    node->graph_dirty = true;
    return true;
}

static mixnet_packet *make_lsa_packet(const node_t *node) {
    size_t payload_size = sizeof(mixnet_packet_lsa)
        + (size_t)node->num_neighbors * sizeof(mixnet_lsa_link_params);
    mixnet_packet *packet = alloc_packet(PACKET_TYPE_LSA, payload_size);
    if (packet == NULL) {
        return NULL;
    }

    mixnet_packet_lsa *lsa = (mixnet_packet_lsa *)packet->payload;
    lsa->node_address = node->my_addr;
    lsa->neighbor_count = node->num_neighbors;
    mixnet_lsa_link_params *links = lsa->links;
    for (int i = 0; i < (int)node->num_neighbors; i++) {
        links[i].neighbor_mixaddr = node->port_to_neigh[i].node_addr;
        links[i].cost = (node->link_costs != NULL) ? node->link_costs[i] : 1;
    }
    return packet;
}

static void originate_lsa(node_t *node) {
    if (!all_neighbors_known(node)) {
        return;
    }

    mixnet_packet *tmpl = make_lsa_packet(node);
    if (tmpl == NULL) {
        return;
    }

    const mixnet_packet_lsa *h = (const mixnet_packet_lsa *)tmpl->payload;
    store_lsa(node, node->my_addr, h->neighbor_count, h->links);

    for (int p = 0; p < (int)node->num_neighbors; p++) {
        if (is_tree_port(node, p)) {
            send_packet(node, p, clone_packet(tmpl));
        }
    }
    free(tmpl);
    node->lsa_dirty = false;
    node->last_lsa_ms = now_ms();
}

static bool dk_less(const node_t *node, int32_t a, int32_t b) {
    if (node->dist[a] != node->dist[b]) {
        return node->dist[a] < node->dist[b];
    }
    return node->first_hop[a] < node->first_hop[b];
}

static void run_dijkstra(node_t *node) {
    uint32_t n = node->num_known_idx;
    for (uint32_t i = 0; i < n; i++) {
        node->dist[i] = INF_DIST;
        node->first_hop[i] = UINT32_MAX;
        node->parent[i] = -1;
        node->done[i] = false;
    }

    int32_t s = node->addr_to_idx[node->my_addr];
    if (s < 0) {
        node->graph_dirty = false;
        return;
    }
    node->dist[s] = 0;
    node->first_hop[s] = 0;

    for (;;) {
        int32_t u = -1;
        for (uint32_t i = 0; i < n; i++) {
            if (!node->done[i] && node->dist[i] != INF_DIST &&
                (u < 0 || dk_less(node, (int32_t)i, u))) {
                u = (int32_t)i;
            }
        }
        if (u < 0) {
            break;
        }
        node->done[u] = true;

        const lsa_entry_t *e = node->lsa[u];
        if (e == NULL) {
            continue;
        }
        for (uint16_t j = 0; j < e->count; j++) {
            int32_t v = node->addr_to_idx[e->links[j].addr];
            if (v < 0 || node->done[v]) {
                continue;
            }
            uint64_t nd = node->dist[u] + e->links[j].cost;
            uint32_t nfh = (u == s) ? e->links[j].addr : node->first_hop[u];
            if (nd < node->dist[v] ||
                (nd == node->dist[v] && nfh < node->first_hop[v])) {
                node->dist[v] = nd;
                node->first_hop[v] = nfh;
                node->parent[v] = u;
            }
        }
    }
    node->graph_dirty = false;
}

static int get_route(node_t *node, mixnet_address dst,
                     mixnet_address *out, int max) {
    if (node->graph_dirty) {
        run_dijkstra(node);
    }
    int32_t d = node->addr_to_idx[dst];
    if (d < 0 || node->dist[d] == INF_DIST || dst == node->my_addr) {
        return -1;
    }

    int n = 0;
    int32_t s = node->addr_to_idx[node->my_addr];
    int guard = 0;
    for (int32_t cur = node->parent[d];
         cur >= 0 && cur != s;
         cur = node->parent[cur]) {
        if (n >= max || guard++ > (int)MAX_NODES) {
            return -1;
        }
        out[n++] = node->idx_to_addr[cur];
    }
    for (int i = 0, k = n - 1; i < k; i++, k--) {
        mixnet_address tmp = out[i];
        out[i] = out[k];
        out[k] = tmp;
    }
    return n;
}

static mixnet_packet_routing_header *rh(mixnet_packet *p) {
    return (mixnet_packet_routing_header *)p->payload;
}

static mixnet_address *route_ptr(mixnet_packet *p) {
    return (mixnet_address *)(p->payload + RH_SIZE);
}

static char *body_ptr(mixnet_packet *p) {
    return p->payload + RH_SIZE
        + (size_t)rh(p)->route_length * sizeof(mixnet_address);
}

static int choose_route(node_t *node, mixnet_address dst,
                        mixnet_address *out, int max) {
    int n = get_route(node, dst, out, max);
    if (n < 0 || !node->do_random_routing || node->num_neighbors == 0) {
        return n;
    }
    if (n + 2 > max) {
        return n;
    }

    node->rr_toggle = !node->rr_toggle;
    if (!node->rr_toggle) {
        return n;
    }

    mixnet_address first = (n > 0) ? out[0] : dst;
    int start = (int)(rand_r(&node->rng_seed) % node->num_neighbors);
    for (int k = 0; k < (int)node->num_neighbors; k++) {
        int p = (start + k) % (int)node->num_neighbors;
        const neigh_t *y = &node->port_to_neigh[p];
        if (!y->known || y->node_addr == dst ||
            y->node_addr == first ||
            node->addr_to_port[y->node_addr] < 0) {
            continue;
        }
        memmove(out + 2, out, (size_t)n * sizeof(*out));
        out[0] = y->node_addr;
        out[1] = node->my_addr;
        return n + 2;
    }
    return n;
}

static bool routed_valid(mixnet_packet *p) {
    size_t base = sizeof(mixnet_packet) + RH_SIZE;
    if (p->total_size < base) {
        return false;
    }
    size_t need = base + (size_t)rh(p)->route_length * sizeof(mixnet_address);
    if (p->type == PACKET_TYPE_PING) {
        need += sizeof(mixnet_packet_ping);
        return p->total_size == need;
    }
    return p->total_size >= need;
}

static mixnet_packet *build_source_packet(node_t *node, mixnet_packet *upkt,
                                          const mixnet_address *route, int n) {
    size_t user_rh = RH_SIZE
        + (size_t)rh(upkt)->route_length * sizeof(mixnet_address);
    if (upkt->total_size < sizeof(mixnet_packet) + RH_SIZE) {
        return NULL;
    }

    bool is_ping = (upkt->type == PACKET_TYPE_PING);
    size_t body_len = is_ping ? sizeof(mixnet_packet_ping)
                              : (size_t)upkt->total_size
                                    - sizeof(mixnet_packet) - user_rh;

    mixnet_packet *out = alloc_packet(
        upkt->type, RH_SIZE + (size_t)n * sizeof(mixnet_address) + body_len);
    if (out == NULL) {
        return NULL;
    }

    mixnet_packet_routing_header *h = rh(out);
    h->src_address = node->my_addr;
    h->dst_address = rh(upkt)->dst_address;
    h->route_length = (uint16_t)n;
    h->hop_index = 0;
    if (n > 0) {
        memcpy(route_ptr(out), route, (size_t)n * sizeof(mixnet_address));
    }

    if (is_ping) {
        mixnet_packet_ping *ping = (mixnet_packet_ping *)body_ptr(out);
        ping->is_request = true;
        ping->send_time = now_us();
    } else if (body_len > 0) {
        memcpy(body_ptr(out), upkt->payload + user_rh, body_len);
    }
    return out;
}

static uint16_t mix_threshold(const node_t *node) {
    uint16_t t = node->mixing_factor;
    if (t < 1) {
        t = 1;
    }
    if (t > MAX_MIX) {
        t = MAX_MIX;
    }
    return t;
}

static void flush_mix(node_t *node) {
    for (uint16_t i = 0; i < node->mix_len; i++) {
        send_packet(node, node->mix_queue[i].port, node->mix_queue[i].packet);
        node->mix_queue[i].packet = NULL;
    }
    node->mix_len = 0;
}

static void enqueue_mix(node_t *node, int port, mixnet_packet *pkt) {
    if (pkt == NULL) {
        return;
    }
    if (node->mix_len >= MAX_MIX) {
        flush_mix(node);
    }
    node->mix_queue[node->mix_len].port = port;
    node->mix_queue[node->mix_len].packet = pkt;
    node->mix_len++;
    if (node->mix_len >= mix_threshold(node)) {
        flush_mix(node);
    }
}

static void forward_out(node_t *node, mixnet_packet *pkt) {
    mixnet_packet_routing_header *h = rh(pkt);
    mixnet_address next = (h->hop_index < h->route_length)
                            ? route_ptr(pkt)[h->hop_index]
                            : h->dst_address;
    int p = node->addr_to_port[next];
    if (p < 0) {
        free(pkt);
        return;
    }
    enqueue_mix(node, p, pkt);
}

static void source_send(node_t *node, mixnet_packet *upkt) {
    if (upkt->total_size < sizeof(mixnet_packet) + RH_SIZE) {
        return;
    }

    mixnet_address dst = rh(upkt)->dst_address;
    if (dst == node->my_addr) {
        mixnet_packet *out = build_source_packet(node, upkt, NULL, 0);
        if (out == NULL) {
            return;
        }
        send_packet(node, node->user_port, out);
        if (upkt->type == PACKET_TYPE_PING) {
            mixnet_packet *r = build_source_packet(node, upkt, NULL, 0);
            if (r == NULL) {
                return;
            }
            mixnet_packet_routing_header *h = rh(r);
            h->src_address = node->my_addr;
            h->dst_address = node->my_addr;
            ((mixnet_packet_ping *)body_ptr(r))->is_request = false;
            send_packet(node, node->user_port, r);
        }
        return;
    }

    mixnet_address route[MAX_MIXNET_ROUTE_LENGTH];
    int n = choose_route(node, dst, route, (int)MAX_MIXNET_ROUTE_LENGTH);
    if (n < 0) {
        return;
    }

    mixnet_packet *out = build_source_packet(node, upkt, route, n);
    if (out == NULL && node->do_random_routing) {
        n = get_route(node, dst, route, (int)MAX_MIXNET_ROUTE_LENGTH);
        if (n >= 0) {
            out = build_source_packet(node, upkt, route, n);
        }
    }
    if (out != NULL) {
        forward_out(node, out);
    }
}

static void send_ping_reply(node_t *node, const mixnet_packet *req) {
    mixnet_packet *r = clone_packet(req);
    if (r == NULL) {
        return;
    }

    mixnet_packet_routing_header *h = rh(r);
    mixnet_address tmp = h->src_address;
    h->src_address = h->dst_address;
    h->dst_address = tmp;

    mixnet_address *rt = route_ptr(r);
    for (int i = 0, k = (int)h->route_length - 1; i < k; i++, k--) {
        mixnet_address t = rt[i];
        rt[i] = rt[k];
        rt[k] = t;
    }
    h->hop_index = 0;
    ((mixnet_packet_ping *)body_ptr(r))->is_request = false;
    forward_out(node, r);
}

static void forward_transit(node_t *node, mixnet_packet *packet) {
    mixnet_packet_routing_header *h = rh(packet);
    if (h->hop_index >= h->route_length ||
        route_ptr(packet)[h->hop_index] != node->my_addr) {
        return;
    }

    mixnet_packet *out = clone_packet(packet);
    if (out == NULL) {
        return;
    }
    rh(out)->hop_index++;
    forward_out(node, out);
}

static bool neighbor_needs(const node_t *node, int port) {
    if (port == node->root_port) {
        return true;
    }
    const neigh_t *n = &node->port_to_neigh[port];
    if (!n->bid_valid) {
        return true; 
    }
    if (n->stp_root != node->stp.root) {
        return n->stp_root > node->stp.root; 
    }
    return (uint32_t)n->stp_len > (uint32_t)node->stp.len + 1;
}

static void advertise_needed(node_t *node) {
    for (int p = 0; p < (int)node->num_neighbors; p++) {
        if (neighbor_needs(node, p)) {
            send_stp(node, p);
        }
    }
    node->announced = true;
}

static void schedule_broadcast(node_t *node) {
    if (!node->bcast_pending) {
        node->bcast_pending = true;
        node->bcast_at_ms   = now_ms() + DEBOUNCE_MS;
    }
}

static void handle_stp(node_t *node, int port, mixnet_packet *packet) {
    if (port == node->user_port || port < 0 ||
        port >= (int)node->num_neighbors) {
        return;
    }
    if (packet->total_size < sizeof(mixnet_packet) + sizeof(mixnet_packet_stp)) {
        return;
    }

    const mixnet_packet_stp *stp = (const mixnet_packet_stp *)packet->payload;
    neigh_t *neigh = &node->port_to_neigh[port];

    if (!neigh->known) {
        neigh->node_addr = stp->node_address;
        neigh->known = true;
        node->addr_to_port[neigh->node_addr] = port;
        node->lsa_dirty = true;
    }
    neigh->last_heard_ms = now_ms();

    if (stp->node_address == node->failed_root) {
        node->failed_root = INVALID_MIXADDR;
    }
    if (node->failed_root != INVALID_MIXADDR &&
        stp->root_address == node->failed_root &&
        stp->path_length <= (uint16_t)(node->failed_root_len + 1)) {
        return;
    }

    if (node->root_port < 0 && stp->root_address > node->my_addr) {
        send_stp(node, port);
        return;
    }

    neigh->stp_len = stp->path_length;
    neigh->stp_root = stp->root_address;
    neigh->bid_valid = true;

    if (node->root_port >= 0 && stp->root_address == node->stp.root) {
        node->last_hello_heard_ms = now_ms();
    }

    mixnet_address old_root = node->stp.root;
    uint16_t       old_len  = node->stp.len;

    if (recompute_root(node)) {
        if (node->root_port >= 0 &&
            node->stp.root == node->failed_root) {
            node->failed_root = INVALID_MIXADDR;
        }
        if (node->stp.root != old_root || node->stp.len != old_len) {
            schedule_broadcast(node);
        }
        return;
    }

    if (port == node->root_port &&
        stp->root_address == node->stp.root &&
        (uint16_t)(stp->path_length + 1) == node->stp.len) {
        node->last_hello_heard_ms = now_ms();
        advertise_stp(node, port);
        return;
    }

    if (node->stp.root < stp->root_address) {
        send_stp(node, port);
    }
}

static void handle_flood(node_t *node, int port, mixnet_packet *packet) {
    bool from_user = (port == node->user_port);
    if (!from_user && !is_tree_port(node, port)) {
        return;
    }

    for (int p = 0; p < (int)node->num_neighbors; p++) {
        if (p != port && is_tree_port(node, p)) {
            send_packet(node, p, clone_packet(packet));
        }
    }
    if (!from_user) {
        send_packet(node, node->user_port, clone_packet(packet));
    }
}

static void handle_lsa(node_t *node, int port, const mixnet_packet *packet) {
    if (port >= (int)node->num_neighbors || !is_tree_port(node, port)) {
        return;
    }

    size_t base = sizeof(mixnet_packet) + sizeof(mixnet_packet_lsa);
    if (packet->total_size < base) {
        return;
    }
    const mixnet_packet_lsa *h = (const mixnet_packet_lsa *)packet->payload;
    if (packet->total_size < base + (size_t)h->neighbor_count
                                    * sizeof(mixnet_lsa_link_params)) {
        return;
    }
    if (h->node_address == node->my_addr) {
        return;
    }

    store_lsa(node, h->node_address, h->neighbor_count, h->links);

    for (int p = 0; p < (int)node->num_neighbors; p++) {
        if (p != port && is_tree_port(node, p)) {
            send_packet(node, p, clone_packet(packet));
        }
    }
}

static void handle_routed(node_t *node, int port, mixnet_packet *packet) {
    if (port == node->user_port) {
        source_send(node, packet);
        return;
    }
    if (port < 0 || port >= (int)node->num_neighbors) {
        return;
    }
    if (!routed_valid(packet)) {
        return;
    }

    if (rh(packet)->dst_address == node->my_addr) {
        send_packet(node, node->user_port, clone_packet(packet));
        if (packet->type == PACKET_TYPE_PING) {
            mixnet_packet_ping *ping = (mixnet_packet_ping *)body_ptr(packet);
            if (ping->is_request) {
                send_ping_reply(node, packet);
            } else {
                time_ms_t rtt = now_us() - ping->send_time;
                printf("RTT to %u: %llu us\n",
                    (unsigned)rh(packet)->src_address,
                    (unsigned long long)rtt);
                fflush(stdout);   
            }
        }
        return;
    }

    forward_transit(node, packet);
}

static void handle_packet(node_t *node, int port, mixnet_packet *packet) {
    switch (packet->type) {
        case PACKET_TYPE_STP:
            handle_stp(node, port, packet);
            break;
        case PACKET_TYPE_FLOOD:
            handle_flood(node, port, packet);
            break;
        case PACKET_TYPE_LSA:
            handle_lsa(node, port, packet);
            break;
        case PACKET_TYPE_DATA:
        case PACKET_TYPE_PING:
            handle_routed(node, port, packet);
            break;
        default:
            break;
    }
}

static void check_timer(node_t *node) {
    time_ms_t now = now_ms();

    if (node->failed_root != INVALID_MIXADDR &&
        now >= node->failed_root_until_ms) {
        node->failed_root = INVALID_MIXADDR;
    }

    if (node->bcast_pending && now >= node->bcast_at_ms) {
        advertise_needed(node);                      
        node->bcast_pending = false;
    }

    if (!node->announced && node->root_port < 0 &&
        !node->bcast_pending && now >= node->announce_at_ms) {
        advertise_stp(node, -1);
        node->announced = true;
        node->last_hello_sent_ms = now; 
    }

    if (node->root_port < 0) {
        if (node->announced &&
            now - node->last_hello_sent_ms >= node->root_hello_interval_ms) {
            advertise_stp(node, -1);
            node->last_hello_sent_ms = now;
        }
    } else if (now - node->last_hello_heard_ms >= node->reelection_interval_ms * LOSSY_REELECT_MULT) {
        start_reelection(node);
    }

    if (node->lsa_dirty ||
        now - node->last_lsa_ms >= node->root_hello_interval_ms) {
        originate_lsa(node);
    }
}


static void node_free(node_t *node) {
    if (node == NULL) {
        return;
    }
    for (uint16_t i = 0; i < node->mix_len; i++) {
        free(node->mix_queue[i].packet);
    }
    if (node->lsa != NULL) {
        for (uint32_t i = 0; i < node->num_known_idx; i++) {
            free(node->lsa[i]);
        }
    }
    free(node->port_to_neigh);
    free(node->addr_to_port);
    free(node->lsa);
    free(node->addr_to_idx);
    free(node->idx_to_addr);
    free(node->dist);
    free(node->first_hop);
    free(node->parent);
    free(node->done);
    free(node);
}

static bool node_init(node_t *node, void *const handle,
                      volatile bool *const keep_running,
                      const struct mixnet_node_config c) {
    node->handle = handle;
    node->keep_running = keep_running;

    node->my_addr = c.node_addr;
    node->num_neighbors = c.num_neighbors;
    node->root_hello_interval_ms = c.root_hello_interval_ms;
    node->reelection_interval_ms = c.reelection_interval_ms;
    node->do_random_routing = c.do_random_routing;
    node->mixing_factor = c.mixing_factor;
    node->link_costs = c.link_costs;

    node->user_port = (int)c.num_neighbors;
    node->root_port = -1;

    node->stp.root = node->my_addr;
    node->stp.len = 0;
    node->stp.via = node->my_addr;

    size_t neigh_slots = node->num_neighbors > 0 ? node->num_neighbors : 1;
    node->port_to_neigh = (neigh_t *)calloc(neigh_slots, sizeof(neigh_t));
    node->addr_to_port = (int *)malloc(ADDR_SPACE * sizeof(int));
    node->addr_to_idx = (int32_t *)malloc(ADDR_SPACE * sizeof(int32_t));
    node->idx_to_addr = (mixnet_address *)malloc(MAX_NODES * sizeof(mixnet_address));
    node->lsa = (lsa_entry_t **)calloc(MAX_NODES, sizeof(*node->lsa));
    node->dist = (uint64_t *)malloc(MAX_NODES * sizeof(*node->dist));
    node->first_hop = (uint32_t *)malloc(MAX_NODES * sizeof(*node->first_hop));
    node->parent = (int32_t *)malloc(MAX_NODES * sizeof(*node->parent));
    node->done = (bool *)malloc(MAX_NODES * sizeof(*node->done));

    if (node->port_to_neigh == NULL || node->addr_to_port == NULL ||
        node->addr_to_idx == NULL || node->idx_to_addr == NULL ||
        node->lsa == NULL || node->dist == NULL ||
        node->first_hop == NULL || node->parent == NULL ||
        node->done == NULL) {
        return false;
    }

    for (int i = 0; i < ADDR_SPACE; i++) {
        node->addr_to_port[i] = -1;
        node->addr_to_idx[i] = -1;
    }

    time_ms_t now = now_ms();
    node->last_hello_heard_ms = now;
    node->last_hello_sent_ms = now;
    node->failed_root = INVALID_MIXADDR;
    node->failed_root_len = 0;
    node->failed_root_until_ms = 0;
    node->num_known_idx = 0;
    node->graph_dirty = true;
    node->lsa_dirty = true;
    node->last_lsa_ms = 0;
    node->mix_len = 0;
    node->rr_toggle = false;
    node->rng_seed = (unsigned)(now ^ ((uint64_t)node->my_addr << 16));
    register_node(node, node->my_addr);

    uint32_t a = node->my_addr < LISTEN_CAP_ADDR ? node->my_addr : LISTEN_CAP_ADDR;
    node->announced      = false;
    node->announce_at_ms = now + (time_ms_t)a * LISTEN_PER_ADDR_MS;
    node->bcast_pending  = false;

    return true;
}

void run_node(void *const handle,
              volatile bool *const keep_running,
              const struct mixnet_node_config c) {
    node_t *node = (node_t *)calloc(1, sizeof(node_t));
    if (node == NULL) {
        return;
    }
    if (!node_init(node, handle, keep_running, c)) {
        node_free(node);
        return;
    }

    while (*keep_running) {
        uint8_t port = 0;
        mixnet_packet *packet = NULL;
        if (mixnet_recv(handle, &port, &packet) == 1) {
            handle_packet(node, (int)port, packet);
            free(packet);
        }
        check_timer(node);
    }

    node_free(node);
}
