//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.CryptoProviderCacheOptions
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// This is an LRU cache implementation that relies on an event queue rather than locking to achieve thread safety.
    /// This approach has been decided on in order to optimize the performance of the get and set operations on the cache.
    /// This cache contains a doubly linked list in order to maintain LRU order, as well as a dictionary (map) to keep track of
    /// keys and expiration times. The linked list (a structure which is not thread-safe) is NEVER modified directly inside
    /// an API call (e.g. get, set, remove); it is only ever modified sequentially by a background thread. On the other hand,
    /// the map is a <see cref="ConcurrentDictionary{TKey, TValue}"/> which may be modified directly inside an API call or
    /// through eventual processing of the event queue. This implementation relies on the principle of 'eventual consistency':
    /// though the map and it's corresponding linked list may be out of sync at any given point in time, they will eventually line up.
    /// See here for more details:
    /// https://aka.ms/identitymodel/caching
    /// </summary>
    /// <typeparam name="TKey">The key type to be used by the cache.</typeparam>
    /// <typeparam name="TValue">The value type to be used by the cache</typeparam>
    internal class EventBasedLRUCache<TKey, TValue>
    {
        internal delegate void ItemRemoved(TValue Value);

        private readonly int _capacity;

        // The percentage of the cache to be removed when _maxCapacityPercentage is reached.
        private readonly double _compactionPercentage = .20;
        private LinkedList<LRUCacheItem<TKey, TValue>> _doubleLinkedList = new LinkedList<LRUCacheItem<TKey, TValue>>();
        private ConcurrentQueue<Action> _eventQueue = new();
        private ConcurrentDictionary<TKey, LRUCacheItem<TKey, TValue>> _map;

        // When the current cache size gets to this percentage of _capacity, _compactionPercentage% of the cache will be removed.
        private readonly double _maxCapacityPercentage = .95;

        // if true, expired values will not be added to the cache and clean-up of expired values will occur on a 5 minute interval
        private readonly bool _removeExpiredValues;
        private readonly int _removeExpiredValuesIntervalInSeconds;
        private readonly TaskCreationOptions _options;

        // timer that removes expired items periodically
        private Timer _timer = null;

        // for testing purpose only to verify the task count
        private int _taskCount = 0;

        #region event queue
  
        private int _eventQueuePollingInterval = 50;

        // The idle timeout, the _eventQueueTask will end after being idle for the specified time interval (execution continues even if the queue is empty to reduce the task startup overhead), default to 120 seconds.
        // TODO: consider implementing a better algorithm that tracks and predicts the usage patterns and adjusts this value dynamically.
        private long _eventQueueTaskIdleTimeoutInSeconds = 120;

        // the event queue task
        private Task _eventQueueTask;

        // The time when the _eventQueueTask should end. The intent is to reduce the overhead costs of starting/ending tasks too frequently
        // but at the same time keep the _eventQueueTask a short running task.
        // Since Task is based on thread pool the overhead should be reasonable.
        private DateTime _eventQueueTaskStopTime;

        // task states used to ensure thread safety (Interlocked.CompareExchange)
        private const int EventQueueTaskStopped = 0; // task not started yet
        private const int EventQueueTaskRunning = 1; // task is running
        private const int EventQueueTaskDoNotStop = 2; // force the task to continue even it has past the _eventQueueTaskStopTime, see StartEventQueueTaskIfNotRunning() for more details.
        private int _eventQueueTaskState = EventQueueTaskStopped;

        internal ItemRemoved OnItemRemoved
        {
            get;
            set;
        }

        internal long EventQueueTaskIdleTimeoutInSeconds
        {
            get => _eventQueueTaskIdleTimeoutInSeconds;
            set
            {
                if (value <= 0)
                    throw new ArgumentOutOfRangeException(nameof(value), "EventQueueTaskExecutionTimeInSeconds must be positive.");
                _eventQueueTaskIdleTimeoutInSeconds = value;
            }
        }

        // If the task operating on the _eventQueue has not timed out and the _eventQueue is empty, this polling interval will be used
        // to determine how often the cache should be checked for the presence of a new action.
        private int EventQueuePollingInterval
        {
            get => _eventQueuePollingInterval;
            set
            {
                if (value <= 0)
                    throw new ArgumentOutOfRangeException(nameof(value), "EventQueuePollingInterval must be positive.");
                _eventQueuePollingInterval = value;
            }
        }

        #endregion

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="capacity">The capacity of the cache, used to determine if experiencing overflow.</param>
        /// <param name="options">The event queue task creation option, default to None instead of LongRunning as LongRunning will always start a task on a new thread instead of ThreadPool.</param>
        /// <param name="comparer">The equality comparison implementation to be used by the map when comparing keys.</param>
        /// <param name="removeExpiredValues">Whether or not to remove expired items.</param>
        /// <param name="removeExpiredValuesIntervalInSeconds">The period to wait to remove expired items, in milliseconds.</param>
        internal EventBasedLRUCache(
            int capacity,
            TaskCreationOptions options = TaskCreationOptions.None,
            IEqualityComparer<TKey> comparer = null,
            bool removeExpiredValues = false,
            int removeExpiredValuesIntervalInSeconds = 300)
        {
            _capacity = capacity > 0 ? capacity : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(capacity)));
            _options = options;
            _map = new ConcurrentDictionary<TKey, LRUCacheItem<TKey, TValue>>(comparer ?? EqualityComparer<TKey>.Default);
            _removeExpiredValuesIntervalInSeconds = 1000 * removeExpiredValuesIntervalInSeconds;
            _removeExpiredValues = removeExpiredValues;
            _eventQueueTaskStopTime = DateTime.UtcNow;

            if (_removeExpiredValues)
                _timer = new Timer(RemoveExpiredValuesPeriodically, null, _removeExpiredValuesIntervalInSeconds, _removeExpiredValuesIntervalInSeconds);
        }

        private void AddActionToEventQueue(Action action)
        {
            _eventQueue.Enqueue(action);
            // start the event queue task if it is not running
            StartEventQueueTaskIfNotRunning();
        }

        public bool Contains(TKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            return _map.ContainsKey(key);
        }

        /// <summary>
        /// This is the delegate for the event queue task (and the timer to remove the expired items if _removeExpiredValues is true).
        /// The task keeps running until it is disposed or expired (DateTime.UtcNow > _eventQueueTaskEndTime).
        /// Note the task and timer are synchronized; both are running or stopped.
        /// </summary>
        private void EventQueueTaskAction()
        {
            Interlocked.Increment(ref _taskCount);
            // Keep running until the queue is empty *AND* expired (DateTime.UtcNow > _eventQueueTaskEndTime).
            while (true)
            {
                // always set the state to EventQueueTaskRunning in case it was set to EventQueueTaskDoNotStop
                _eventQueueTaskState = EventQueueTaskRunning;

                try
                {
                    if (_eventQueue.TryDequeue(out var action))
                    {
                        action?.Invoke();
                    }
                    else if (DateTime.UtcNow > _eventQueueTaskStopTime) // no more event to be processed, exit if expired
                    {
                        // Setting _eventQueueTaskState = EventQueueTaskStopped if the _eventQueueTaskEndTime has past and _eventQueueTaskState == EventQueueTaskRunning.
                        // This means no other thread came in and it is safe to end this task.
                        // If another thread adds new events while this task is still running, it will set the _eventQueueTaskState = EventQueueTaskDoNotStop instead of starting a new task.
                        // The Interlocked.CompareExchange() call below will not succeed and the loop continues (until the event queue is empty and the _eventQueueTaskEndTime expires again).
                        // This should prevent a rare (but theoretically possible) scenario caused by context switching.
                        if (Interlocked.CompareExchange(ref _eventQueueTaskState, EventQueueTaskStopped, EventQueueTaskRunning) == EventQueueTaskRunning)
                            break;

                    }
                    else // if empty, let the thread sleep for a specified number of milliseconds before attempting to retrieve another value from the queue
                    {
                        Thread.Sleep(_eventQueuePollingInterval);
                    }
                }
                catch (Exception ex)
                {
                    LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10900, ex));
                }
            }

            Interlocked.Decrement(ref _taskCount);
        }

        internal int RemoveExpiredValues()
        {
            int numItemsRemoved = 0;
            try
            {
                var node = _doubleLinkedList.First;
                while (node != null)
                {
                    var nextNode = node.Next;
                    if (node.Value.ExpirationTime < DateTime.UtcNow)
                    {
                        _doubleLinkedList.Remove(node);
                        if (_map.TryRemove(node.Value.Key, out var cacheItem))
                            OnItemRemoved?.Invoke(cacheItem.Value);

                        numItemsRemoved++;
                    }

                    node = nextNode;
                }
            }
            catch (ObjectDisposedException ex)
            {
                LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10902, nameof(RemoveExpiredValues), ex));
            }

            return numItemsRemoved;
        }

        /// <summary>
        /// The timer callback that adds a request to remove expired items from the event queue.
        /// </summary>
        /// <param name="state">the timer state</param>
        protected void RemoveExpiredValuesPeriodically(object state)
        {
            if (_map.Count > 0)
                AddActionToEventQueue(() => RemoveExpiredValues());
        }

        /// <summary>
        /// Remove items from the LinkedList by the desired compaction percentage.
        /// This should be a private method.
        /// </summary>
        private void RemoveLRUs()
        {
            // use the _capacity for the newCacheSize calculation in the case where the cache is experiencing overflow
            int currentCount = _map.Count <= _capacity ? _capacity : _map.Count;
            var newCacheSize = currentCount - (int)(currentCount * _compactionPercentage);
            while (_map.Count > newCacheSize && _doubleLinkedList.Count > 0)
            {
                var lru = _doubleLinkedList.Last;
                if (_map.TryRemove(lru.Value.Key, out var cacheItem))
                    OnItemRemoved?.Invoke(cacheItem.Value);

                _doubleLinkedList.Remove(lru);
            }
        }

        /// <summary>
        /// This is the method that determines the end time for the event queue task.
        /// The goal is to be able to track the incoming events and predict how long the task should run in order to
        /// avoid a long running task and reduce the overhead costs of restarting tasks.
        /// For example, maybe we can track the last three events' time and set the _eventQueueRunDurationInSeconds = 2 * average_time_between_events.
        /// Note: tasks are based on thread pool so the overhead should not be huge but we should still try to minimize it.
        /// </summary>
        /// <returns>the time when the event queue task should end</returns>
        private DateTime SetTaskEndTime()
        {
            return DateTime.UtcNow.AddSeconds(EventQueueTaskIdleTimeoutInSeconds);
        }

        public void SetValue(TKey key, TValue value)
        {
            SetValue(key, value, DateTime.MaxValue);
        }

        public bool SetValue(TKey key, TValue value, DateTime expirationTime)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (value == null)
                throw LogHelper.LogArgumentNullException(nameof(value));

            // if item already expired, do not add it to the cache if the _removeExpiredValues setting is set to true
            if (_removeExpiredValues && expirationTime < DateTime.UtcNow)
                return false;

            // just need to update value and move it to the top
            if (_map.TryGetValue(key, out var cacheItem))
            {
                cacheItem.Value = value;
                cacheItem.ExpirationTime = expirationTime;
                AddActionToEventQueue(() =>
                {
                    _doubleLinkedList.Remove(cacheItem);
                    _doubleLinkedList.AddFirst(cacheItem);
                });
            }
            else
            {
                // if cache is at _maxCapacityPercentage, trim it by _compactionPercentage
                if ((double)_map.Count / _capacity >= _maxCapacityPercentage)
                {
                    _eventQueue.Enqueue(() =>
                    {
                        RemoveLRUs();
                    });
                }
                // add the new node
                var existingCacheItem = new LRUCacheItem<TKey, TValue>(key, value, expirationTime);
                AddActionToEventQueue(() =>
                {
                    // Add a remove operation in case two threads are trying to add the same value. Only the second remove will succeed in this case.
                    _doubleLinkedList.Remove(existingCacheItem);
                    _doubleLinkedList.AddFirst(existingCacheItem);
                });

                _map[key] = existingCacheItem;
            }

            return true;
        }

        /// <summary>
        /// This method is called after an item is added to the event queue, and the event queue task needs to be started if not running (_eventQueueTaskState != EventQueueTaskRunning).
        /// Setting _eventQueueTaskState to EventQueueTaskRunning should prevent multiple task being started.
        /// </summary>
        private void StartEventQueueTaskIfNotRunning()
        {
            _eventQueueTaskStopTime = SetTaskEndTime(); // set the time when the _eventQueueTask should end

            // Setting _eventQueueTaskState to EventQueueTaskDoNotStop here will force the event queue task in EventQueueTaskAction to continue even it has past the _eventQueueTaskEndTime.
            // It is mainly to prevent a rare (but theoretically possible) scenario caused by context switching
            // For example:
            //   1. the task execution in EventQueueTaskAction() checks _eventQueueTaskStopTime and it has already passed (ready to exit)
            //   2. the execution is switched to this thread (before it calls the Interlocked.CompareExchange() to set the _eventQueueTaskState to EventQueueTaskStopped)
            //   3. the _eventQueueTaskStopTime is extended but it can't stop the task from stopping as the task has already passed the time check
            //   4. now since the _eventQueueTaskState == EventQueueTaskRunning, it can be set to EventQueueTaskDoNotStop by the Interlocked.CompareExchange() below
            //   5. if _eventQueueTaskState is successfully set to EventQueueTaskDoNotStop, the Interlocked.CompareExchange() in the EventQueueTaskAction() will fail
            //      and the task will continue the while loop and the new _eventQueueTaskStopTime will keep the task running
            //   6. if _eventQueueTaskState is NOT set to EventQueueTaskDoNotStop because of context switch back to the EventQueueTaskAction() and the _eventQueueTaskState is
            //      set to EventQueueTaskStopped (task exits), then the second Interlocked.CompareExchange() below should set the _eventQueueTaskState to EventQueueTaskRunning
            //      and start a task again (though this scenario is unlikely to happen)
            //
            // Though this kind of context switching is probably unlikely to happen, this hopefully will take care of it.

            if (Interlocked.CompareExchange(ref _eventQueueTaskState, EventQueueTaskDoNotStop, EventQueueTaskRunning) == EventQueueTaskRunning)
            {
                return;
            }

            // If the task is stopped, set _eventQueueTaskState = EventQueueTaskRunning and start a new task.
            // Note: we need to call the Task.Run() to start a new task on the default TaskScheduler (TaskScheduler.Default) so it does not interfere with
            // the caller's TaskScheduler (if there is one) as some custom TaskSchedulers might be single-threaded and its execution can be blocked.
            if (Interlocked.CompareExchange(ref _eventQueueTaskState, EventQueueTaskRunning, EventQueueTaskStopped) == EventQueueTaskStopped)
            {
                _eventQueueTask = Task.Run(EventQueueTaskAction);
            }
        }

        /// Each time a node gets accessed, it gets moved to the beginning (head) of the list.
        public bool TryGetValue(TKey key, out TValue value)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!_map.ContainsKey(key))
            {
                value = default;
                return false;
            }

            // make sure node hasn't been removed by a different thread
            if (_map.TryGetValue(key, out var cacheItem))
                AddActionToEventQueue(() =>
                {
                    _doubleLinkedList.Remove(cacheItem);
                    _doubleLinkedList.AddFirst(cacheItem);
                });

            value = cacheItem != null ? cacheItem.Value : default;
            return cacheItem != null;
        }

        /// Removes a particular key from the cache.
        public bool TryRemove(TKey key, out TValue value)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!_map.TryGetValue(key, out var cacheItem))
            {
                value = default;
                return false;
            }

            value = cacheItem.Value;
            AddActionToEventQueue(() => _doubleLinkedList.Remove(cacheItem));
            if (_map.TryRemove(key, out cacheItem))
            {
                OnItemRemoved?.Invoke(cacheItem.Value);
                return true;
            }

            return false;
        }

        #region FOR TESTING (INTERNAL ONLY)

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
        /// <returns></returns>
        internal LinkedList<LRUCacheItem<TKey, TValue>> LinkedList => _doubleLinkedList;

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
        internal long LinkedListCount => _doubleLinkedList.Count;

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
        internal long MapCount => _map.Count;

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
        /// <returns></returns>
        internal ICollection<LRUCacheItem<TKey, TValue>> MapValues => _map.Values;

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
        internal long EventQueueCount => _eventQueue.Count;

        /// <summary>
        /// FOR TESTING PURPOSES ONLY.
        /// This is for tests to verify all tasks exit at the end of tests if the queue is empty.
        /// </summary>
        internal int TaskCount => _taskCount;

        /// <summary>
        /// FOR TESTING PURPOSES ONLY.
        /// </summary>
        internal void WaitForProcessing()
        {
            while (true)
            {
                if (_eventQueue.Count == 0)
                    return;
            }
        }

        #endregion
    }

    internal class LRUCacheItem<TKey, TValue>
    {
        internal TKey Key { get; }
        internal TValue Value { get; set; }
        internal DateTime ExpirationTime { get; set; }

        internal LRUCacheItem(TKey key, TValue value)
        {
            Key = key ?? throw LogHelper.LogArgumentNullException(nameof(key));
            Value = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        internal LRUCacheItem(TKey key, TValue value, DateTime expirationTime)
        {
            Key = key ?? throw LogHelper.LogArgumentNullException(nameof(key));
            Value = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
            ExpirationTime = expirationTime;
        }

        public override bool Equals(object obj)
        {
            LRUCacheItem<TKey, TValue> item = obj as LRUCacheItem<TKey, TValue>;
            return item != null && Key.Equals(item.Key);
        }

        public override int GetHashCode() => 990326508 + EqualityComparer<TKey>.Default.GetHashCode(Key);
    }
}

