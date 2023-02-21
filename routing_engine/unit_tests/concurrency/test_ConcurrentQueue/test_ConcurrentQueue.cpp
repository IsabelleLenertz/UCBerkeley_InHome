#include "gtest/gtest.h"
#include "concurrency/ConcurrentQueue.hpp"

#include <thread>
#include <iostream>

typedef struct
{
    int thread_id;
    int message_id;
} entry_t;

template class ConcurrentQueue<entry_t>;

/// <summary>
/// Tests the dequeue order of messages
/// placed in the queue by different threads.
/// The relative order of messages from one
/// to another is non-deterministic, but
/// messages from each individual thread
/// must be removed in ascending order of
/// message ID.
/// </summary>
TEST(test_ConcurrentQueue, test_DequeueOrder)
{
    static const int NUM_THREADS = 8;
    static const int NUM_MESSAGES = 16;
    
    ConcurrentQueue<entry_t> _queue;
    std::thread _threads[NUM_THREADS];
    
    // Spin up all threads
    for (int i = 0; i < NUM_THREADS; i++)
    {
        _threads[i] = std::thread([i, &_queue]()
        {
            int messages_left = NUM_MESSAGES;
            while (messages_left > 0)
            {
                // Enqueue the next message
                _queue.Enqueue(entry_t
                   {i, NUM_MESSAGES - messages_left});
                
                messages_left--;
                
                // Spin loop for delay
                // to increase chance of
                // preemption
                // (Might end up optimized out)
                for (volatile int d = 0; d < 99999; d++);
            }
        });
    }
    
    // TODO Dequeue messages and validate order
    uint8_t next_message[NUM_THREADS] = {0};
    int messages_left = NUM_THREADS * NUM_MESSAGES;
    
    while (messages_left > 0)
    {
        if (!_queue.IsEmpty())
        {
            entry_t entry;
            bool found = _queue.Dequeue(entry);
            
            // Queue is known not to be empty,
            // if the dequeue fails, something
            // is wrong, so fail test case.
            ASSERT_EQ(true, found);
            
            // Verify that the message ID
            // was expected from the corresponding
            // thread ID
            ASSERT_EQ(next_message[entry.thread_id],
                      entry.message_id);
            
            // Move to next message ID
            next_message[entry.thread_id]++;
            messages_left--;
        }
    }
    
    // Join all threads to main
    for (int i = 0; i < NUM_THREADS; i++)
    {
        _threads[i].join();
    }
}
