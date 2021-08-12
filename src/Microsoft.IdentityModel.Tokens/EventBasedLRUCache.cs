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
    internal class EventBasedLRUCache<TKey, TValue> : IDisposable
    {
        internal delegate void ItemRemoved(TValue Value);

        private readonly int _capacity;
        // The percentage of the cache to be removed when _maxCapacityPercentage is reached.
        private readonly double _compactionPercentage = .20;
        private LinkedList<LRUCacheItem<TKey, TValue>> _doubleLinkedList = new LinkedList<LRUCacheItem<TKey, TValue>>();
        private BlockingCollection<Action> _eventQueue = new BlockingCollection<Action>();

        #region event queue

        // the duration the _eventQueueTask should run after it is started, default to 120 seconds
        // TODO: consider implementing a better and yet simple algorithm that tracks and predicts the usage patterns and adjusts this value dynamically.
        private int _eventQueueRunDurationInSeconds = 120;

        // the event queue task
        private Task _eventQueueTask;

        // The time when the _eventQueueTask should end. The intent is to reduce the overhead costs of starting/ending tasks too refrequently
        // but at the same time keep the _eventQueueTask a short running task.
        // Since Task is based on thread pool the overhead should be reasonable.
        private DateTime _eventQueueTaskStopTime;

        // task states used to ensure thread safety (Interlocked.CompareExchange)
        private const int EventQueueTaskStopped = 0; // task not started yet
        private const int EventQueueTaskRunning = 1; // task is running
        private const int EventQueueTaskDoNotStop = 2; // force the task to continue even it has past the _eventQueueTaskStopTime, see StartEventQueueTaskIfNotRunning() for more details

        private int _eventQueueTaskState = EventQueueTaskStopped;

        #endregion

        private ConcurrentDictionary<TKey, LRUCacheItem<TKey, TValue>> _map;
        // When the current cache size gets to this percentage of _capacity, _compactionPercentage% of the cache will be removed.
        private readonly double _maxCapacityPercentage = .95;
        private bool _disposed = false;
        private readonly int _tryTakeTimeout;
        // if true, expired values will not be added to the cache and clean-up of expired values will occur on a 5 minute interval
        private readonly bool _removeExpiredValues;
        private readonly int _cleanUpIntervalInMilliSeconds;

        private readonly TaskCreationOptions _options;

        // timer that removes expired items periodically
        private Timer _timer = null;

        // for testing purpose only to verify the task count
        private int _taskCount = 0;

        internal EventBasedLRUCache(
            int capacity,
            TaskCreationOptions options = TaskCreationOptions.LongRunning,
            IEqualityComparer<TKey> comparer = null,
            int tryTakeTimeout = 500,
            bool removeExpiredValues = true,
            int cleanUpIntervalInSeconds = 300)
        {
            _tryTakeTimeout = tryTakeTimeout;
            _capacity = capacity > 0 ? capacity : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(capacity)));
            _options = options;
            _map = new ConcurrentDictionary<TKey, LRUCacheItem<TKey, TValue>>(comparer ?? EqualityComparer<TKey>.Default);
            _cleanUpIntervalInMilliSeconds = 1000 * cleanUpIntervalInSeconds;
            _removeExpiredValues = removeExpiredValues;
            _eventQueueTaskStopTime = DateTime.Now;

            if (_removeExpiredValues)
                _timer = new Timer(RemoveExpiredValuesPeriodically, null, _cleanUpIntervalInMilliSeconds, _cleanUpIntervalInMilliSeconds); // initial delay then ticks every periodInMilliSeconds
        }

        public bool Contains(TKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            return _map.ContainsKey(key);
        }

        /// <summary>
        /// FOR TESTING PURPOSES ONLY.
        /// </summary>
        internal void WaitForProcessing()
        {
            while (!_disposed)
            {
                if (_eventQueue.Count == 0)
                    return;
            }
        }

        /// <summary>
        /// FOR TESTING PURPOSES ONLY.
        /// This is for tests to verify all tasks exit at the end of tests if the queue is empty.
        /// </summary>
        internal int TaskCount => _taskCount;

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
        /// The timer callback that adds a request to remove expired items from the event queue.
        /// </summary>
        /// <param name="state">the timer state</param>
        protected void RemoveExpiredValuesPeriodically(object state)
        {
            _eventQueue.Add(() => RemoveExpiredValues());
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
                _eventQueue.Add(() =>
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
                    _eventQueue.Add(() =>
                    {
                        RemoveLRUs();
                    });
                }
                // add the new node
                var newCacheItem = new LRUCacheItem<TKey, TValue>(key, value, expirationTime);
                _eventQueue.Add(() =>
                {
                    // Add a remove operation in case two threads are trying to add the same value. Only the second remove will succeed in this case.
                    _doubleLinkedList.Remove(newCacheItem);
                    _doubleLinkedList.AddFirst(newCacheItem);
                });
                _map[key] = newCacheItem;

                // start the event queue task if it is not running
                StartEventQueueTaskIfNotRunning();
            }

            return true;
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
                _eventQueue.Add(() =>
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
            _eventQueue.Add(() => RemoveItemFromLinkedList(cacheItem));
            if (_map.TryRemove(key, out cacheItem))
            {
                OnItemRemoved?.Invoke(cacheItem.Value);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Remove an item from the LinkedList.
        /// When the last item is removed from the LinkedList, the OnLinkedListItemRemoved() will cancel the running _eventQueue task.
        /// </summary>
        /// <param name="newCacheItem">the item to be removed</param>
        private void RemoveItemFromLinkedList(LRUCacheItem<TKey, TValue> newCacheItem)
        {
            _doubleLinkedList.Remove(newCacheItem);
        }


        /// <summary>
        /// This is the delegate for the event queue task (and the timer to remove the expired items if _removeExpiredValues is true).
        /// The task keeps running until it is disposed or expired (DateTime.Now > _eventQueueTaskEndTime).
        /// Note the task and timer are synchronized; both are running or stopped.
        /// </summary>
        private void EventQueueTaskAction()
        {
            Interlocked.Increment(ref _taskCount);

            if (_removeExpiredValues)
            {
                ResumeTimer();
            }

            // Keep running until it is disposed, or expired (DateTime.Now > _eventQueueTaskEndTime).
            while (!_disposed)
            {
                // always set the state to EventQueueTaskRunning in case it was set to EventQueueTaskDoNotStop
                _eventQueueTaskState = EventQueueTaskRunning;

                try
                {
                    if (_eventQueue.TryTake(out var action, _tryTakeTimeout))
                    {
                        action?.Invoke();
                    }
                    else if (DateTime.Now > _eventQueueTaskStopTime) // no more event to be processed, exit if expired
                    {
                        if (Interlocked.CompareExchange(ref _eventQueueTaskState, EventQueueTaskStopped, EventQueueTaskRunning) == EventQueueTaskRunning) // if no other thread trying to start the task
                            break;
                    }
                }
                catch (Exception ex)
                {
                    LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10900, ex));
                }
            }

            Interlocked.Decrement(ref _taskCount);
            if (_removeExpiredValues && _taskCount == 0) // pause the timer only if the _taskCount is 0 to avoid the scenario that it is being resumed (above)
            {
                PauseTimer();
            }
        }

        /// <summary>
        /// This method is called after an item is added to the event queue, and the event queue task needs to be started if not running (_eventQueueTaskState != EventQueueTaskRunning).
        /// Settitng _eventQueueTaskState to EventQueueTaskRunning should prevent multiple task being started.
        /// </summary>
        private void StartEventQueueTaskIfNotRunning()
        {
             _eventQueueTaskStopTime = SetTaskEndTime(); // set the time when the _eventQueueTask should end

            // Setting _eventQueueTaskState to EventQueueTaskDoNotStop here will force the event queue task in EventQueueTaskAction to continue even it has past the _eventQueueTaskEndTime.
            // It is mainly to prevent a rare (but theoratically possible) scenario caused by context switching
            // For example:
            //   1. the task execution in EventQueueTaskAction() checks _eventQueueTaskStopTime and it has already passed (ready to exit)
            //   2. the execution is switched to this thread (before it calls the Interlocked.CompareExchange() to set the _eventQueueTaskState to EventQueueTaskStopped)
            //   3. the _eventQueueTaskStopTime is extended but it can't stop the task from stopping as the task has already passed the time check
            //   4. now since the _eventQueueTaskState == EventQueueTaskRunning, it can be set to EventQueueTaskDoNotStop by the Interlocked.CompareExchange() below
            //   5. if _eventQueueTaskState is successfully set to EventQueueTaskDoNotStop, the Interlocked.CompareExchang() in the EventQueueTaskAction() will fail
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

            // if the task is stopped, set _eventQueueTaskState = EventQueueTaskRunning and start a new task
            if (Interlocked.CompareExchange(ref _eventQueueTaskState, EventQueueTaskRunning, EventQueueTaskStopped) == EventQueueTaskStopped)
            {
                var eventQueueTask = new Task(EventQueueTaskAction, _options);
                eventQueueTask.Start();
                _eventQueueTask = eventQueueTask;
            }
        }

        /// <summary>
        /// This is the method that determines the end time for the event queue task.
        /// The goal is to be able to track the incoming events and predict how long the task should run in order to
        /// avoid a long running task and reduce the overhead costs of restarting tasks.
        /// For example, maybe we can track the last three events' time and set the _eventQueueRunDurationInSeconds = 2 * average_time_between_events.
        /// Note: tasks are based on thread poool so the overhead should not be huge but it shouls be minimized.
        /// </summary>
        /// <returns>the time when the event queue task should end</returns>
        private DateTime SetTaskEndTime()
        {
            return DateTime.Now.AddSeconds(_eventQueueRunDurationInSeconds);
        }

        /// <summary>
        /// Pause the timer.
        /// </summary>
        private void PauseTimer()
        {
            if (_timer != null)
                _timer.Change(Timeout.Infinite, Timeout.Infinite);
        }

        /// <summary>
        /// Resume the timer.
        /// </summary>
        private void ResumeTimer()
        {
            if (_timer != null)
                _timer.Change(_cleanUpIntervalInMilliSeconds, _cleanUpIntervalInMilliSeconds);
        }

        internal ItemRemoved OnItemRemoved
        {
            get;
            set;
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

#endregion

        /// <summary>
        /// Calls <see cref="Dispose(bool)"/> and <see cref="GC.SuppressFinalize"/>
        /// </summary>
        public void Dispose()
        {
            // Dispose of unmanaged resources.
            Dispose(true);
            // Suppress finalization.
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// If <paramref name="disposing"/> is true, this method disposes of <see cref="_eventQueue"/>.
        /// </summary>
        /// <param name="disposing">True if called from the <see cref="Dispose()"/> method, false otherwise.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;
                if (disposing)
                {
                    if (_timer != null)
                    {
                        _timer.Dispose();
                        _timer = null;
                    }

                    _eventQueue.Dispose();
                    _eventQueue = null;
                    _map = null;
                    _doubleLinkedList = null;
                }
            }
        }
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

