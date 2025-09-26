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
#ifndef MIXNET_NODE_H_
#define MIXNET_NODE_H_

#include "address.h"
#include "config.h"
#include "packet.h"

#include <stdbool.h>
#include <string.h>
#include <time.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct djikstra_node
    {
        mixnet_address addr;
        uint16_t distance;
        struct djikstra_node *prev;
    } djikstra_node;

    typedef struct priority_queue
    {
        djikstra_node **nodes;
        uint32_t size;
    } priority_queue;

    /* Using an adjacency list representation for graph topology */
    typedef struct graph_node
    {
        mixnet_address node_addr; // Neighbor node address
        uint16_t link_cost;       // Cost of the link to this neighbor
        struct graph_node *next;  // Pointer to the next neighbor
    } graph_node;

    typedef struct graph
    {
        uint32_t num_nodes;     // Total number of nodes
        graph_node **adj_lists; // Array of adjacency lists

    } graph;

    typedef struct mixing_message
    {
        uint8_t port;
        mixnet_packet *packet;
    } mixing_message;

    typedef struct node_state
    {

        /* General Node Fields */

        mixnet_address node_addr; // Mixnet address of this node
        uint16_t num_neighbors;   // This node's total neighbor count

        /* STP parameters */
        uint32_t root_hello_interval_ms; // Time (in ms) between 'hello' messages
        uint32_t reelection_interval_ms; // Time (in ms) before starting reelection

        /* Routing parameters */
        bool do_random_routing; // Whether this node performs random routing
        uint16_t mixing_factor; // Exact number of (non-control) packets to mix
        uint16_t *link_costs;   // Per-neighbor routing costs, in range [0, 2^16)

        /* STP relevant fields */
        mixnet_address root;        // Current root of the spanning tree
        uint16_t path_length;       // Path length to the current root
        mixnet_address next_hop;    // Next hop towards the current root
        float max_convergence_time; // Time (in ms) taken to converge
        bool has_converged;         // Whether STP has converged
        bool has_updated;           // Whether the node state has been updated
        bool *port_is_blocked;      // Whether a port is blocked
        bool is_root;               // Whether this node is the root
        clock_t last_hello_time;    // Last time a 'hello' message was sent

        /* Routing relevant fields */
        uint16_t *neighbor_addrs;       // Per-neighbor mixnet addresses
        clock_t last_lsa_time;          // Last time an LSA was sent
        uint32_t lsa_interval_ms;       // Time (in ms) between LSAs
        graph *topology;                // Network topology
        djikstra_node **distances;      // Shortest distances to all nodes
        mixing_message **mixing_queue;  // Buffer containing pointers to messages to mix
        uint16_t messages_in_mix_queue; // track number of messages in mixing queue
        bool reached_mixing;

        /* Lab metrics */
        uint32_t stp_control_messages;
        clock_t start_stp_time;

    } node_state;

    /* Priority queue related functions */
    void swap(djikstra_node **a, djikstra_node **b);
    void heapifyUp(priority_queue *pq, int index);
    void push(priority_queue *pq, djikstra_node *value);
    void heapifyDown(priority_queue *pq, int index);
    djikstra_node *pop(priority_queue *pq);
    mixnet_address *find_route(node_state *state, mixnet_address dest, uint32_t *length);
    mixnet_address *find_route_randomized(node_state *state, mixnet_address dest, uint32_t *length);

    /* Graph-related functions */
    graph_node *create_node(mixnet_address addr, uint16_t cost);
    graph *create_graph();
    void add_edge(graph *g, mixnet_address src, mixnet_address dest, uint16_t cost);
    void free_graph(graph *g);
    void print_graph(graph *g);

    /* Helper functions */
    void block_ports(node_state *state);
    void handle_stp(node_state *state, uint8_t port, mixnet_packet_stp *stp_payload);
    void send_stp_to_all(void *const handle, node_state *state);
    void handle_message(void *const handle, node_state *state, uint8_t port,
                        mixnet_packet *recv_packet);
    void reverse_array(mixnet_address arr[], int size);
    void add_to_queue(void *const handle, node_state *state, const uint8_t port, mixnet_packet *packet);
    void flush_packets(void *const handle, node_state *state);
    /* Main node function */
    void run_node(void *const handle,
                  volatile bool *const keep_running,
                  const struct mixnet_node_config c);

#ifdef __cplusplus
}
#endif

#endif // MIXNET_NODE_H_