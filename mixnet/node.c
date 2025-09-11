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

void run_stp(void *const handle, node_state *state, volatile bool *const keep_running, struct timeval start_time)
{
    struct timeval current_time;
    do
    {

        // Only send STP packets if we have updated
        if (!state->has_updated)
        {
            // 1. Send STP packet to all neighbors
            for (int i = 0; i < state->num_neighbors; i++)
            {

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
                    // exit(1);
                }
            }
            if (!*keep_running)
            {
                return;
            }
        }

        // 2. Receive STP packets from neighbors
        uint8_t port;
        mixnet_packet *recv_packet;
        int recv_count = mixnet_recv(handle, &port, &recv_packet);
        if (recv_count < 0)
        {
            fprintf(stderr, "Error receiving STP packet\n");
            // exit(1);
        }
        else if (recv_count == 0)
        {
            // state->has_converged = true;
            continue;
            // break; // No more packets to process
        }
        else if (recv_packet->type != PACKET_TYPE_STP)
        {
            // fprintf(stderr, "Received non-STP packet in STP handler\n");
            free(recv_packet);
            continue;
        }

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
                // state->port_is_blocked[state->next_hop] = true;
                state->next_hop = stp_payload->node_address;
                // fprintf(stderr, "New path to root: %d via %d (path length %d)\n", state->root, state->next_hop, state->path_length);
                state->port_is_blocked[port] = false;
                updated = true;
            }
            // Same root and same path length, but lower next hop address
            else if (stp_payload->path_length + 1 == state->path_length)
            {
                if (stp_payload->node_address < state->next_hop)
                {
                    state->next_hop = stp_payload->node_address;
                    updated = true;
                }
                state->port_is_blocked[port] = false;
            }
            // if longer path length, may potentially use us as route
            else
            {
                state->port_is_blocked[port] = false;
            }
        }

        free(recv_packet);
        state->has_updated = updated;
        gettimeofday(&current_time, NULL);

    } while (*keep_running && (current_time.tv_sec - start_time.tv_sec) * 1000 < state->max_convergence_time);

    state->has_converged = true;
}

void run_node(void *const handle,
              volatile bool *const keep_running,
              const struct mixnet_node_config c)
{

    (void)c;
    (void)handle;

    // setup node state struct
    node_state *state = malloc(sizeof(node_state));
    // fprintf(stderr, "Node %d: Starting node with %d neighbors\n", c.node_addr, c.num_neighbors);
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
    state->max_convergence_time = 500; // estimate max convergence time
    state->has_converged = false;
    state->port_is_blocked = malloc(sizeof(bool) * (c.num_neighbors + 1));
    gettimeofday(&state->last_hello_time, NULL);
    while (*keep_running)
    {
        struct timeval current_time;
        gettimeofday(&current_time, NULL);

        /* BEGIN STP SECTION */

        // Check if it's time to rerun STP
        if (!state->is_root && (current_time.tv_sec - state->last_hello_time.tv_sec * 1000) >= state->reelection_interval_ms)
        {
            // fprintf(stderr, "Node %d: Reelection interval reached. Rerunning STP.\n", state->node_addr);
            state->has_converged = false;
        }

        // Perform STP until convergence
        if (!state->has_converged)
        {
            // fprintf(stderr, "Node %d: STP has not converged. Running STP.\n", state->node_addr);
            gettimeofday(&current_time, NULL);
            run_stp(handle, state, keep_running, current_time);
            state->is_root = (state->root == state->node_addr);
            // fprintf(stderr, "Node %d: STP has converged. Root: %d, Next Hop: %d, Path Length: %d, Neighbors: %d\n", state->node_addr, state->root, state->next_hop, state->path_length, state->num_neighbors);
            // // print blocked ports
            // fprintf(stderr, "Node %d: Blocked Ports: ", state->node_addr);
            // for (int i = 0; i < state->num_neighbors; i++)
            // {
            //     if (state->port_is_blocked[i])
            //     {
            //         fprintf(stderr, "%d ", i);
            //     }
            // }
            // fprintf(stderr, "\n ");
        }

        /* END STP SECTION */

        /* BEGIN HELLO BROADCAST SECTION */
        gettimeofday(&current_time, NULL);

        // send hello packet if root
        if (state->is_root && (current_time.tv_sec - state->last_hello_time.tv_sec * 1000) >= state->root_hello_interval_ms)
        {
            gettimeofday(&state->last_hello_time, NULL);
            // fprintf(stderr, "Parent Node %d: Sending HELLO packets to all neighbors.\n", state->node_addr);
            for (int i = 0; i <= state->num_neighbors; i++)
            {

                if (!state->port_is_blocked[i])
                {
                    mixnet_packet *packet = malloc(sizeof(mixnet_packet) + sizeof(mixnet_packet_stp));
                    packet->total_size = sizeof(mixnet_packet) + sizeof(mixnet_packet_stp);
                    packet->type = PACKET_TYPE_STP;

                    mixnet_packet_stp *hello_payload = (mixnet_packet_stp *)packet->payload;
                    hello_payload->node_address = state->node_addr;
                    if (mixnet_send(handle, i, packet) < 0)
                    {
                        fprintf(stderr, "Error sending HELLO packet to neighbor %d\n", i);
                        // exit(1);
                    }
                }
            }
        }

        /* END HELLO BROADCAST SECTION */

        /* BEGIN MESSAGE HANDLING SECTION */

        // P1C1: Handle Packet_Type_FLOOD
        uint8_t port;
        mixnet_packet *recv_packet;
        int recv_count = mixnet_recv(handle, &port, &recv_packet);

        // fprintf(stderr, "Node %d: Received packet on port %d\n", state->node_addr, port);
        if (recv_count < 0)
        {
            fprintf(stderr, "Error receiving STP packet\n");
            // exit(1);
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
                    // allocate and copy packet
                    // fprintf(stderr, "Received flood. Node %d forwarding FLOOD packet from port %d to neighbor %d\n", state->node_addr, port, i);
                    mixnet_packet *packet_copy = malloc(recv_packet->total_size);
                    memcpy(packet_copy, recv_packet, recv_packet->total_size);

                    if (mixnet_send(handle, i, packet_copy) < 0)
                    {
                        fprintf(stderr, "Error sending FLOOD packet to neighbor %d\n", i);
                        // exit(1);
                    }
                }
            }
            break;
        case PACKET_TYPE_STP:
            if (((mixnet_packet_stp *)recv_packet->payload)->node_address == state->next_hop)
            {
                for (int i = 0; i < state->num_neighbors; i++)
                {
                    if (!state->port_is_blocked[i] && i != port)
                    {
                        // allocate and copy packet, update node address
                        mixnet_packet *packet = malloc(sizeof(mixnet_packet) + sizeof(mixnet_packet_stp));
                        packet->total_size = sizeof(mixnet_packet) + sizeof(mixnet_packet_stp);
                        packet->type = PACKET_TYPE_STP;

                        mixnet_packet_stp *hello_payload = (mixnet_packet_stp *)packet->payload;
                        hello_payload->node_address = state->node_addr;
                        if (mixnet_send(handle, i, packet) < 0)
                        {
                            fprintf(stderr, "Error sending STP packet to neighbor %d\n", i);
                            // exit(1);
                        }
                    }
                }
            }
            break;

        default:
            break;
        }

        free(recv_packet);

        /* END MESSAGE HANDLING SECTION */
    }

    // Free allocated resources
    free(state->port_is_blocked);
    free(state);

    // 2. Routing
}
