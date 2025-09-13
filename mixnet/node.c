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
#include <unistd.h>

void block_ports(node_state *state)
{
    for (int i = 0; i < state->num_neighbors; i++)
    {
        state->port_is_blocked[i] = true;
    }
}

void handle_stp(node_state *state, uint8_t port, mixnet_packet_stp *stp_payload)
{

    bool updated = false;

    // Update state based on received STP packet
    if (stp_payload->root_address < state->root)
    {
        // New root found
        state->root = stp_payload->root_address;
        state->next_hop = stp_payload->node_address;
        state->path_length = stp_payload->path_length + 1;
        state->port_is_blocked[port] = false;

        updated = true;
    }
    else if (stp_payload->root_address == state->root)
    {
        // Same root, but shorter path length
        if (stp_payload->path_length + 1 < state->path_length)
        {
            state->path_length = stp_payload->path_length + 1;
            state->next_hop = stp_payload->node_address;
            state->port_is_blocked[port] = false;

            updated = true;
        }
        // Same root and same path length, but lower next hop address
        else if (stp_payload->path_length + 1 == state->path_length)
        {
            if (stp_payload->node_address < state->next_hop)
            {
                state->next_hop = stp_payload->node_address;
                state->port_is_blocked[port] = false;

                updated = true;
            }
            else
            {

                state->port_is_blocked[port] = true;
            }
        }
        else if (stp_payload->path_length == state->path_length + 1)
        {
            // potential child
            state->port_is_blocked[port] = false;
        }
        else
        {
            state->port_is_blocked[port] = true;
        }
    }

    state->has_updated = updated;
}

void send_stp_to_all(void *const handle, node_state *state)
{
    for (int i = 0; i < state->num_neighbors; i++)
    {

        mixnet_packet *packet = malloc(sizeof(mixnet_packet) + sizeof(mixnet_packet_stp));
        packet->total_size = sizeof(mixnet_packet) + sizeof(mixnet_packet_stp);
        packet->type = PACKET_TYPE_STP;

        mixnet_packet_stp *payload = (mixnet_packet_stp *)packet->payload;
        payload->node_address = state->node_addr;
        payload->root_address = state->root;
        payload->path_length = state->path_length;

        if (mixnet_send(handle, i, packet) < 0)
        {
            fprintf(stderr, "Error sending packet from %d to port %d\n", state->node_addr, i);
            exit(1);
        }
    }
}

void handle_message(void *const handle, node_state *state, uint8_t port,
                    mixnet_packet *recv_packet)
{
    mixnet_packet_stp *stp_payload;
    switch (recv_packet->type)
    {
    case PACKET_TYPE_STP:
        stp_payload = (mixnet_packet_stp *)recv_packet->payload;

        // broadcast hello message from parent
        if (stp_payload->node_address == state->next_hop && stp_payload->path_length + 1 == state->path_length && stp_payload->root_address == state->root)
        {

            send_stp_to_all(handle, state);
            state->last_hello_time = clock();
        }
        else
        {

            handle_stp(state, port, stp_payload);
        }

        free(recv_packet);

        break;
    case PACKET_TYPE_FLOOD:
        if (state->port_is_blocked[port])
        {
            free(recv_packet);
            break;
        }
        for (int i = 0; i <= state->num_neighbors; i++)
        {
            if (!state->port_is_blocked[i] && i != port)
            {
                // allocate and copy packet
                mixnet_packet *packet_copy = malloc(recv_packet->total_size);
                memcpy(packet_copy, recv_packet, recv_packet->total_size);

                if (mixnet_send(handle, i, packet_copy) < 0)
                {
                    fprintf(stderr, "Error sending FLOOD packet to neighbor %d\n", i);
                    exit(1);
                }
            }
        }
        free(recv_packet);

        break;

    default:
        // Unknown Packet Type
        break;
    }
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
    state->max_convergence_time = 100; // estimate max convergence time
    state->has_converged = false;
    state->has_updated = true; // Force initial STP packet send
    state->port_is_blocked = malloc(sizeof(bool) * (c.num_neighbors + 1));
    block_ports(state); // Initially block all ports

    clock_t current_time = clock();
    clock_t start_stp_time = clock();
    state->last_hello_time = clock();

    while (*keep_running)
    {

        // Perform STP until convergence
        if (!state->has_converged)
        {
            // Only send STP packets if we have updated
            if (state->has_updated)
            {
                // Send STP packet with updated state to all neighbors
                send_stp_to_all(handle, state);
                state->has_updated = false;
            }
            current_time = clock();

            if ((current_time - start_stp_time) * 1000 / CLOCKS_PER_SEC > state->max_convergence_time)
            {

                state->has_converged = true;
                state->is_root = (state->root == state->node_addr);
            }

            state->last_hello_time = clock();
        }

        current_time = clock();

        // send hello packet if root
        if (state->is_root && ((current_time - state->last_hello_time) * 1000) / CLOCKS_PER_SEC > state->root_hello_interval_ms)
        {
            send_stp_to_all(handle, state);
            state->last_hello_time = clock();
        }
        current_time = clock();

        // Check if it's time to rerun STP
        if (state->has_converged && ((current_time - state->last_hello_time) * 1000.0) / CLOCKS_PER_SEC > state->reelection_interval_ms)
        {
            state->root = c.node_addr;
            state->path_length = 0;
            state->next_hop = c.node_addr;
            state->has_updated = true;
            state->has_converged = false;
            block_ports(state);
            start_stp_time = clock();
        }

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
            continue; // No packets to process
        }

        handle_message(handle, state, port, recv_packet);
    }

    // Free allocated resources
    free(state->port_is_blocked);
    free(state);

    // Routing to be implemented...
}
