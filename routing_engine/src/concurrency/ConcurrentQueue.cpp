#include "concurrency/ConcurrentQueue.hpp"

ConcurrentQueue::ConcurrentQueue()
    : _queue(),
      _mutex()
{
}

ConcurrentQueue::~ConcurrentQueue()
{
}

bool ConcurrentQueue::Enqueue(const T &val)
{
    bool result;
    std::scoped_lock lock {_mutex};
    
    _queue.push(val);
    
    return true;
}

bool ConcurrentQueue::Dequeue(T &val)
{
    bool result;
    std::scoped_lock lock {_mutex};
    
    result = !_queue.empty();
    
    // If list is not empty
    if (result)
    {
        val = _queue.front; // Get element
        _queue.pop();       // Remove element
    }
    
    return result;
}

bool ConcurrentQueue::IsEmpty()
{
    bool result;
    std::scoped_lock lock {_mutex};
    
    result = _queue.empty();
    
    return result;
}

size_t ConcurrentQueue::Size()
{
    size_t result;
    std::scoped_lock lock {_mutex};
    
    result = _queue.size();
    
    return result;
}