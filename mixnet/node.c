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

/* Priority queue functions*/
void swap(djikstra_node *a, djikstra_node *b)
{
    djikstra_node temp = *a;
    *a = *b;
    *b = temp;
}

void heapifyUp(priority_queue *pq, int index)
{
    if (index && pq->nodes[(index - 1) / 2]->distance > pq->nodes[index]->distance)
    {
        swap(pq->nodes[index], pq->nodes[(index - 1) / 2]);
        heapifyUp(pq, (index - 1) / 2);
    }
}
void push(priority_queue *pq, djikstra_node *value)
{
    pq->nodes[pq->size] = value;
    pq->size += 1;
    heapifyUp(pq, pq->size - 1);
}
void heapifyDown(priority_queue *pq, int index)
{
    int smallest = index;
    uint32_t left = 2 * index + 1;
    uint32_t right = 2 * index + 2;

    if (left < pq->size && pq->nodes[left]->distance < pq->nodes[smallest]->distance)
        smallest = left;
    if (right < pq->size && pq->nodes[right]->distance < pq->nodes[smallest]->distance)
        smallest = right;
    if (smallest != index)
    {
        swap(pq->nodes[index], pq->nodes[smallest]);
        heapifyDown(pq, smallest);
    }
}

djikstra_node *pop(priority_queue *pq)
{
    djikstra_node *item = pq->nodes[0];
    pq->nodes[0] = pq->nodes[pq->size - 1];
    heapifyDown(pq, 0);
    pq->size -= 1;
    return item;
}

/* Graph-related functions */
graph_node *create_node(mixnet_address addr, uint16_t cost)
{
    graph_node *new_node = malloc(sizeof(graph_node));
    new_node->node_addr = addr;
    new_node->link_cost = cost;
    new_node->next = NULL;
    return new_node;
}

graph *create_graph()
{
    fprintf(stderr, "Creating graph\n");
    graph *g = malloc(sizeof(graph));
    g->num_nodes = UINT16_MAX + 1;

    g->adj_lists = malloc(g->num_nodes * sizeof(graph_node *));
    for (uint32_t i = 0; i < g->num_nodes; i++)
    {
        g->adj_lists[i] = NULL;
    }

    return g;
}

void add_edge(graph *g, mixnet_address src, mixnet_address dest, uint16_t cost)
{
    fprintf(stderr, "Adding edge from %d to %d with cost %d\n", src, dest, cost);
    // check if edge already exists
    graph_node *temp = g->adj_lists[src];
    while (temp)
    {
        if (temp->node_addr == dest)
        {
            return;
        }
        temp = temp->next;
    }

    graph_node *new_node = create_node(dest, cost);
    new_node->next = g->adj_lists[src];
    g->adj_lists[src] = new_node;

    new_node = create_node(src, cost);
    new_node->next = g->adj_lists[dest];
    g->adj_lists[dest] = new_node;
    // print_graph(g);
}

void print_graph(graph *g)
{
    for (uint32_t i = 0; i < g->num_nodes; i++)
    {
        graph_node *temp = g->adj_lists[i];
        if (temp)
        {
            fprintf(stderr, "Node %d: ", i);
            while (temp)
            {
                fprintf(stderr, " -> %d (cost %d)", temp->node_addr, temp->link_cost);
                temp = temp->next;
            }
            fprintf(stderr, "\n");
        }
    }
}

void free_graph(graph *g)
{
    for (uint32_t i = 0; i < g->num_nodes; i++)
    {
        graph_node *temp = g->adj_lists[i];
        while (temp)
        {
            graph_node *to_free = temp;
            temp = temp->next;
            free(to_free);
        }
    }
    free(g->adj_lists);
    free(g);
}

/* Djikstra's algorithm */
void run_djikstras(node_state *state, mixnet_address start_addr)
{
    fprintf(stderr, "Running Djikstra's from node %d\n", start_addr);
    // Create a priority queue to store (vertex, distance) pairs

    priority_queue *pq = malloc(sizeof(priority_queue));
    pq->nodes = malloc(sizeof(djikstra_node *) * state->topology->num_nodes);
    pq->size = 0;

    djikstra_node **dist = malloc(sizeof(djikstra_node *) * state->topology->num_nodes);
    for (uint32_t i = 0; i < state->topology->num_nodes; i++)
    {
        dist[i] = NULL;
    }

    dist[start_addr] = 0;
    djikstra_node *start_node = malloc(sizeof(djikstra_node));
    start_node->addr = start_addr;
    start_node->distance = 0;
    start_node->prev = NULL;
    push(pq, start_node);

    // run djikstra's algorithm while keeping track of paths

    while (pq->size > 0)
    {

        djikstra_node *node = pop(pq);

        // Get all adjacent of u.
        for (graph_node *x = state->topology->adj_lists[node->addr]; x != NULL; x = x->next)
        {
            // Get vertex label and weight of current
            // adjacent of u.
            mixnet_address v = x->node_addr;
            uint16_t weight = x->link_cost;

            // If there is shorter path to v through u.
            if (dist[v] == NULL || dist[v]->distance > dist[node->addr]->distance + weight)
            {

                djikstra_node *v_node = malloc(sizeof(djikstra_node));
                v_node->addr = v;
                v_node->distance = dist[node->addr]->distance + weight;
                v_node->prev = node;

                dist[v] = v_node;
                push(pq, v_node);
            }
        }
        // free(node);
    }

    state->distances = dist;
    fprintf(stderr, "Djikstra's complete. Distances:\n");
}

mixnet_address *find_route(node_state *state, mixnet_address dest, uint32_t *length)
{

    djikstra_node *current = state->distances[dest]->prev;
    djikstra_node *start = current;
    uint32_t path_length = 0;
    while (start->prev != NULL)
    {
        path_length++;
        start = start->prev;
    }
    // exclude src and dst

    mixnet_address *path = malloc(sizeof(mixnet_address) * (path_length));
    int i = (int)path_length;

    while (i > 0 && current->prev != NULL && current->prev->addr != state->node_addr)
    {
        path[i] = current->addr;
        i--;
        current = current->prev;
    }

    *length = path_length;
    return path;
}

/* Helper functions */
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

    // learn neighbor address
    state->neighbor_addrs[port] = stp_payload->node_address;
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

void send_lsa(void *const handle, node_state *state)
{
    // fprintf(stderr, "Node %d sending LSA\n", state->node_addr);
    size_t lsa_size = sizeof(mixnet_packet) + sizeof(mixnet_packet_lsa) + (sizeof(mixnet_lsa_link_params) * state->num_neighbors);
    mixnet_packet *packet = malloc(lsa_size);
    packet->total_size = lsa_size;
    packet->type = PACKET_TYPE_LSA;

    mixnet_packet_lsa *payload = (mixnet_packet_lsa *)packet->payload;
    payload->node_address = state->node_addr;
    payload->neighbor_count = state->num_neighbors;
    // memcpy(payload->links, state->link_costs, sizeof(mixnet_lsa_link_params) * state->num_neighbors)

    for (int i = 0; i < state->num_neighbors; i++)
    {
        payload->links[i].neighbor_mixaddr = state->neighbor_addrs[i];
        payload->links[i].cost = state->link_costs[i];
        fprintf(stderr, "Link to neighbor %d with cost %d\n", payload->links[i].neighbor_mixaddr, payload->links[i].cost);
    }

    for (int i = 0; i < state->num_neighbors; i++)
    {
        if (!state->port_is_blocked[i])
        {
            // allocate and copy packet
            mixnet_packet *packet_copy = malloc(packet->total_size);
            memcpy(packet_copy, packet, packet->total_size);

            if (mixnet_send(handle, i, packet_copy) < 0)
            {
                fprintf(stderr, "Error sending LSA packet to neighbor %d\n", i);
                exit(1);
            }
        }
    }
    free(packet);
}

void handle_message(void *const handle, node_state *state, uint8_t port,
                    mixnet_packet *recv_packet)
{
    mixnet_packet_stp *stp_payload;
    mixnet_packet_lsa *lsa_payload;
    mixnet_packet_routing_header *data_payload;
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
    case PACKET_TYPE_LSA:
        fprintf(stderr, "Node %d received LSA\n", state->node_addr);
        if (state->port_is_blocked[port] || !state->has_converged)
        {
            free(recv_packet);
            break;
        }

        lsa_payload = (mixnet_packet_lsa *)recv_packet->payload;
        uint16_t neighbor_count = lsa_payload->neighbor_count;
        mixnet_lsa_link_params *lsa_link_ptr = (mixnet_lsa_link_params *)(recv_packet->payload + sizeof(mixnet_packet_lsa));

        // update link state
        for (uint16_t i = 0; i < neighbor_count; i++)
        {
            mixnet_lsa_link_params link = lsa_link_ptr[i];
            // add to graph if not present
            add_edge(state->topology, lsa_payload->node_address, link.neighbor_mixaddr, link.cost);
        }

        fprintf(stderr, "Flooding LSA from node %d\n", state->node_addr);
        // flood to all unblocked neighbors except sender
        for (int i = 0; i < state->num_neighbors; i++)
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
    case PACKET_TYPE_DATA:
        fprintf(stderr, "Node %d received DATA packet\n", state->node_addr);
        data_payload = (mixnet_packet_routing_header *)recv_packet->payload;

        // if we are sender, encode path
        if (port == state->num_neighbors)
        {
            run_djikstras(state, state->node_addr);
            fprintf(stderr, "Handling DATA packet from user at node %d to dst %d\n", state->node_addr, data_payload->dst_address);

            // packet destined for this node
            // run_djikstras(state, state->node_addr);
            uint32_t length = 0;
            mixnet_address *path = find_route(state, data_payload->dst_address, &length);

            // create new packet with routing header
            int packet_size = sizeof(mixnet_packet) + sizeof(mixnet_packet_routing_header) + sizeof(mixnet_address) * length + (recv_packet->total_size - sizeof(mixnet_packet) - sizeof(mixnet_packet_routing_header));
            mixnet_packet *new_packet = malloc(packet_size);
            new_packet->total_size = packet_size;
            new_packet->type = PACKET_TYPE_DATA;

            mixnet_packet_routing_header *new_payload = (mixnet_packet_routing_header *)new_packet->payload;
            new_payload->src_address = data_payload->src_address;
            new_payload->dst_address = data_payload->dst_address;
            new_payload->route_length = length;
            new_payload->hop_index = 0;
            memcpy(new_payload->route, path, sizeof(mixnet_address) * length);

            // copy data
            memcpy((char *)new_payload + sizeof(mixnet_packet_routing_header) + sizeof(mixnet_address) * length,
                   (char *)data_payload + sizeof(mixnet_packet_routing_header),
                   recv_packet->total_size - sizeof(mixnet_packet) - sizeof(mixnet_packet_routing_header));

            // find port of next hop
            int next_hop = 0;
            for (int i = 0; i < state->num_neighbors; i++)
            {
                if (state->neighbor_addrs[i] == path[1])
                {
                    next_hop = i;
                    break;
                }
            }
            fprintf(stderr, "Forwarding DATA packet at node %d to next hop %d\n", state->node_addr, path[1]);
            if (mixnet_send(handle, next_hop, new_packet) < 0)
            {
                fprintf(stderr, "Error sending DATA packet to next hop\n");
                exit(1);
            }
            // free(path);
        }
        else
        {
            // if we are receiver, forward to output port
            if (data_payload->dst_address == state->node_addr)
            {
                fprintf(stderr, "DATA packet reached destination %d\n", state->node_addr);
                if (mixnet_send(handle, state->num_neighbors, recv_packet) < 0)
                {
                    fprintf(stderr, "Error sending DATA packet to output port\n");
                    exit(1);
                }
            }
            else
            {
                fprintf(stderr, "Forwarding DATA packet at node %d to dst %d\n", state->node_addr, data_payload->dst_address);
                int next_hop = 0;
                for (int i = 0; i < state->num_neighbors; i++)
                {
                    if (state->neighbor_addrs[i] == data_payload->route[data_payload->hop_index])
                    {
                        next_hop = i;
                        break;
                    }
                }
                data_payload->hop_index += 1;
                mixnet_packet *packet_copy = malloc(recv_packet->total_size);
                memcpy(packet_copy, recv_packet, recv_packet->total_size);
                if (mixnet_send(handle, next_hop, packet_copy) < 0)
                {
                    fprintf(stderr, "Error sending DATA packet to next hop\n");
                    exit(1);
                }
            }
        }
        // free(recv_packet);
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

    // Initialize routing Fields
    state->topology = create_graph();
    state->neighbor_addrs = malloc(sizeof(mixnet_address) * c.num_neighbors);
    state->lsa_interval_ms = 100; // send LSA every 300 ms
    bool sent_lsa = false;

    clock_t current_time = clock();
    clock_t start_stp_time = clock();
    state->last_hello_time = clock();
    state->last_lsa_time = clock();

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

        // check if it's time to send LSA
        if (state->has_converged && !sent_lsa && ((current_time - state->last_lsa_time) * 1000.0) / CLOCKS_PER_SEC > state->lsa_interval_ms)
        {
            if (!sent_lsa)
            {
                fprintf(stderr, "Node %d sending initial LSA\n", state->node_addr);
                for (int i = 0; i < state->num_neighbors; i++)
                {
                    add_edge(state->topology, state->node_addr, state->neighbor_addrs[i], state->link_costs[i]); // add self to graph
                }
            }

            send_lsa(handle, state);
            state->last_lsa_time = clock();
            state->lsa_interval_ms *= 2; // exponential backoff
            sent_lsa = true;
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
