#include <gtest/gtest.h>

// C++ wrapper to run C tests with GoogleTest
extern "C" {
#include "wt.h"

// Test function declarations
int test_init_cleanup(void);
int test_server_create_destroy(void);
int test_client_create_destroy(void);
int test_session_operations(void);
int test_stream_operations(void);
int test_datagram_operations(void);
int test_memory_pool_operations(void);
int test_ring_buffer_operations(void);
int test_state_machine_transitions(void);
}

class LibWTTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Each test gets a fresh library state
        wt_cleanup(); // Just in case
        ASSERT_EQ(wt_init(), WT_SUCCESS);
    }
    
    void TearDown() override {
        wt_cleanup();
    }
};

TEST_F(LibWTTest, InitializationAndCleanup) {
    EXPECT_EQ(test_init_cleanup(), 0);
}

TEST_F(LibWTTest, ServerCreateDestroy) {
    EXPECT_EQ(test_server_create_destroy(), 0);
}

TEST_F(LibWTTest, ClientCreateDestroy) {
    EXPECT_EQ(test_client_create_destroy(), 0);
}

TEST_F(LibWTTest, SessionOperations) {
    EXPECT_EQ(test_session_operations(), 0);
}

TEST_F(LibWTTest, StreamOperations) {
    EXPECT_EQ(test_stream_operations(), 0);
}

TEST_F(LibWTTest, DatagramOperations) {
    EXPECT_EQ(test_datagram_operations(), 0);
}

TEST_F(LibWTTest, MemoryPoolOperations) {
    EXPECT_EQ(test_memory_pool_operations(), 0);
}

TEST_F(LibWTTest, RingBufferOperations) {
    EXPECT_EQ(test_ring_buffer_operations(), 0);
}

TEST_F(LibWTTest, StateMachineTransitions) {
    EXPECT_EQ(test_state_machine_transitions(), 0);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}