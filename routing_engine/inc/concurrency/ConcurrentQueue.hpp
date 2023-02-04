#ifndef INC_CONCURRENT_QUEUE_HPP_
#define INC_CONCURRENT_QUEUE_HPP_

#include <queue>
#include <mutex>

/// <summary>
/// Templated implementation of a concurrent queue
/// </summary>
template<class T>
class ConcurrentQueue<T>
{
public:
    /// <summary>
    /// Default constructor
    /// </summary>
    ConcurrentQueue();
    
    /// <summary>
    /// Destructor
    /// </summary>
    ~ConcurrentQueue();
    
    /// <summary>
    /// Adds value to the end of the queue.
    /// </summary>
    /// <param name="val">Value to add</param>
    /// <returns>True if added successfully</returns>
    bool Enqueue(const T &val);
    
    /// <summary>
    /// Removes value from the beginning of the queue
    /// and outputs that value
    /// </summary>
    /// <param name="val">Reference to value out</param>
    /// <returns>True if dequeued successfully</returns>
    /// <remarks>
    /// If return value is false, contents of val are undefined
    /// </remarks>
    bool Dequeue(T &val);
    
    /// <summary>
    /// Returns true if no items are in the queue.
    /// </summary>
    /// <returns>True if no items in queue</returns>
    bool IsEmpty();
    
    /// <summary>
    /// Returns the number of elements in the queue.
    /// </summary>
    /// <returns>Number of elements in queue</returns>
    size_t Size();

private:
    std::queue<T> _queue;
    std::mutex _mutex;
};

#endif