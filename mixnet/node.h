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

#include <stdbool.h>
#include <sys/time.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct node_state
    {

        /* General Node Fields*/

        mixnet_address node_addr; // Mixnet address of this node
        uint16_t num_neighbors;   // This node's total neighbor count

        // STP parameters
        uint32_t root_hello_interval_ms; // Time (in ms) between 'hello' messages
        uint32_t reelection_interval_ms; // Time (in ms) before starting reelection

        // Routing parameters
        bool do_random_routing; // Whether this node performs random routing
        uint16_t mixing_factor; // Exact number of (non-control) packets to mix
        uint16_t *link_costs;   // Per-neighbor routing costs, in range [0, 2^16)

        /* STP Relevant Fields*/
        mixnet_address root;            // Current root of the spanning tree
        uint16_t path_length;           // Path length to the current root
        mixnet_address next_hop;        // Next hop towards the current root
        uint32_t max_convergence_time;  // Time (in ms) taken to converge
        bool has_converged;             // Whether STP has converged
        bool has_updated;               // Whether the node state has been updated
        bool *port_is_blocked;          // Whether a port is blocked
        bool is_root;                   // Whether this node is the root
        struct timeval last_hello_time; // Last time a 'hello' message was sent
    } node_state;

    void run_node(void *const handle,
                  volatile bool *const keep_running,
                  const struct mixnet_node_config c);

#ifdef __cplusplus
}
#endif

#endif // MIXNET_NODE_H_
