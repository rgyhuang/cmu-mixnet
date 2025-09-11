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
#include <stdlib.h>

void block_ports(uint8_t port, node_state *state)
{
    for (int i = 0; i < state->num_neighbors; i++)
    {
        if (i == port)
        {
            state->port_is_blocked[i] = false;
        }
        else
        {
            // fprintf(stderr, "Blocking port %d\n", i);
            state->port_is_blocked[i] = true;
        }
    }
}

void run_stp(void *const handle, node_state *state)
{

    do
    {
        // Only send STP packets if we have updated
        if (!state->has_converged)
        {
            // 1. Send STP packet to all neighbors
            for (int i = 0; i < state->num_neighbors; i++)
            {
                // Send STP packet to neighbor i
                mixnet_packet *packet = malloc(sizeof(mixnet_packet) + sizeof(mixnet_packet_stp));
                packet->total_size = sizeof(mixnet_packet) + sizeof(mixnet_packet_stp);
                packet->type = PACKET_TYPE_STP;

                mixnet_packet_stp *stp_payload = (mixnet_packet_stp *)packet->payload;
                stp_payload->root_address = state->root;
                stp_payload->path_length = state->path_length;
                stp_payload->node_address = state->node_addr;

                if (mixnet_send(handle, i, packet) < 0)
                {
                    fprintf(stderr, "Error sending STP packet to neighbor %d\n", i);
                    exit(1);
                }
            }
        }

        // 2. Receive STP packets from neighbors
        uint8_t port;
        mixnet_packet *recv_packet;
        int recv_count = mixnet_recv(handle, &port, &recv_packet);
        if (recv_count < 0)
        {
            fprintf(stderr, "Error receiving STP packet\n");
            exit(1);
        }
        else if (recv_count == 0)
        {
            break; // No more packets to process
        }

        // if (recv_packet->type != PACKET_TYPE_STP)
        // {
        //     // Ignore non-STP packets
        //     free(recv_packet);
        //     continue;
        // }

        mixnet_packet_stp *stp_payload = (mixnet_packet_stp *)recv_packet->payload;

        bool updated = false;

        // 3. Update state based on received STP packet
        if (stp_payload->root_address < state->root)
        {
            // New root found
            state->root = stp_payload->root_address;
            state->next_hop = stp_payload->node_address;
            state->path_length = stp_payload->path_length + 1;
            // fprintf(stderr, "New root: %d via %d (path length %d)\n", state->root, state->next_hop, state->path_length);
            block_ports(port, state);
            updated = true;
        }
        else if (stp_payload->root_address == state->root)
        {
            // Same root, but shorter path length
            if (stp_payload->path_length + 1 < state->path_length)
            {
                state->path_length = stp_payload->path_length + 1;
                state->next_hop = stp_payload->node_address;
                // fprintf(stderr, "New path to root: %d via %d (path length %d)\n", state->root, state->next_hop, state->path_length);
                block_ports(port, state);

                updated = true;
            }
            // Same root and same path length, but lower next hop address
            else if (stp_payload->path_length + 1 == state->path_length)
            {
                if (stp_payload->node_address < state->next_hop)
                {
                    state->next_hop = stp_payload->node_address;
                    // fprintf(stderr, "New next hop to root: %d via %d (path length %d)\n", state->root, state->next_hop, state->path_length);
                    block_ports(port, state);
                    updated = true;
                }
                else
                {
                    // Potential child, unblock port
                    state->port_is_blocked[port] = false;
                }
            }
        }

        free(recv_packet);
        state->has_converged = !updated;

    } while (1);
}

void run_node(void *const handle,
              volatile bool *const keep_running,
              const struct mixnet_node_config c)
{

    (void)c;
    (void)handle;

    // setup node state struct
    node_state *state = malloc(sizeof(node_state));

    // Copy config values into state
    state->node_addr = c.node_addr;
    state->num_neighbors = c.num_neighbors;
    state->root_hello_interval_ms = c.root_hello_interval_ms;
    state->reelection_interval_ms = c.reelection_interval_ms;
    state->do_random_routing = c.do_random_routing;
    state->mixing_factor = c.mixing_factor;
    state->link_costs = c.link_costs;

    // Initialize STP fields
    state->root = c.node_addr;
    state->path_length = 0;
    state->next_hop = c.node_addr;
    state->has_converged = false;
    state->port_is_blocked = malloc(sizeof(bool) * (c.num_neighbors + 1));

    while (*keep_running)
    {
        // Perform STP until convergence
        if (!state->has_converged)
        {
            run_stp(handle, state);
            state->is_root = (state->root == state->node_addr);
            // fprintf(stderr, "%d", state->num_neighbors);
            // fprintf(stderr, "Node %d: STP has converged. Root: %d, Next Hop: %d, Path Length: %d\n", state->node_addr, state->root, state->next_hop, state->path_length);
            // print blocked ports
            // fprintf(stderr, "Node %d: Blocked Ports: ", state->node_addr);
            // for (int i = 0; i <= state->num_neighbors; i++)
            // {
            //     if (state->port_is_blocked[i])
            //     {
            //         fprintf(stderr, "%d ", i);
            //     }
            // }
        }

        //

        // P1C1: Handle Packet_Type_FLOOD
        uint8_t port;
        mixnet_packet *recv_packet;
        int recv_count = mixnet_recv(handle, &port, &recv_packet);

        // fprintf(stderr, "Node %d: Received packet on port %d\n", state->node_addr, port);
        if (recv_count < 0)
        {
            fprintf(stderr, "Error receiving STP packet\n");
            exit(1);
        }
        else if (recv_count == 0)
        {
            continue; // No packets to process
        }

        // fprintf(stderr, "Node: %d Isroot: %d \n", state->node_addr, state->root == state->node_addr ? 1 : 0);
        // fprintf(stderr, "Node %d received packet on port %d with type %d\n", state->node_addr, port, PACKET_TYPE_FLOOD);
        if (state->port_is_blocked[port])
        {
            // Ignore blocked ports
            free(recv_packet);
            continue;
        }

        switch (recv_packet->type)
        {
        case PACKET_TYPE_FLOOD:
            for (int i = 0; i <= state->num_neighbors; i++)
            {
                if (!state->port_is_blocked[i] && i != port)
                {
                    // fprintf(stderr, "Node %d forwarding FLOOD packet to neighbor %d\n", state->node_addr, i);
                    if (mixnet_send(handle, i, recv_packet) < 0)
                    {
                        fprintf(stderr, "Error sending FLOOD packet to neighbor %d\n", i);
                        exit(1);
                    }
                }
            }
            break;

        default:
            // Ignore non-FLOOD packets for now
            break;
        }
    }

    // Free allocated resources
    free(state->port_is_blocked);
    free(state);

    // 2. Routing
}
