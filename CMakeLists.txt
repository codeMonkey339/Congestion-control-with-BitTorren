cmake_minimum_required(VERSION 3.8)
project(Congestion_control_with_BitTorren)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        bt_parse.c
        bt_parse.h
        chunk.c
        chunk.h
        client.c
        debug-text.h
        debug.c
        debug.h
        input_buffer.c
        input_buffer.h
        make_chunks.c
        packet.h
        packet.c
        peer.c
        reliable_udp.c
        reliable_udp.h
        server.c
        sha.c
        sha.h
        spiffy.c
        spiffy.h
        test_input_buffer.c
        utility.c
        utility.h
        packet_handler.c
        packet_handler.h
        job.c
        job.h
        peer_utils.h
        peer_utils.c
        timers.h
        timers.c
        )

add_executable(Congestion_control_with_BitTorren ${SOURCE_FILES})