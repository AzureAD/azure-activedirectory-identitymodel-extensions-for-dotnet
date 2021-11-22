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
        private ConcurrentQueue<Action> _eventQueue = new ConcurrentQueue<Action>();
        private ConcurrentDictionary<TKey, LRUCacheItem<TKey, TValue>> _map;

        // When the current cache size gets to this percentage of _capacity, _compactionPercentage% of the cache will be removed.
        private readonly double _maxCapacityPercentage = .95;

        // if true, expired values will not be added to the cache and clean-up of expired values will occur on a 5 minute interval
        private readonly bool _removeExpiredValues;
        private readonly int _removeExpiredValuesIntervalInSeconds;
        // if true, then items will be maintained in a LRU fashion, moving to front of list when accessed in the cache.
        private readonly bool _maintainLRU;

        private readonly TaskCreationOptions _options;
        private DateTime _dueForExpiredValuesRemoval;

        // for testing purpose only to verify the task count
        private int _taskCount = 0;

        #region event queue
  
        // task states used to ensure thread safety (Interlocked.CompareExchange)
        private const int EventQueueTaskStopped = 0; // task not started yet
        private const int EventQueueTaskRunning = 1; // task is running
        private const int EventQueueTaskDoNotStop = 2; // force the task to continue even it has past the _eventQueueTaskStopTime, see StartEventQueueTaskIfNotRunning() for more details.
        private int _eventQueueTaskState = EventQueueTaskStopped;

        // set to true when the AppDomain is to be unloaded or the default AppDomain process is ready to exit
        private bool _shouldStopImmediately = false;

        internal ItemRemoved OnItemRemoved
        {
            get;
            set;
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
        /// <param name="maintainLRU">Whether or not to maintain items in a LRU fashion, moving to front of list when accessed in the cache.</param>
        internal EventBasedLRUCache(
            int capacity,
            TaskCreationOptions options = TaskCreationOptions.None,
            IEqualityComparer<TKey> comparer = null,
            bool removeExpiredValues = false,
            int removeExpiredValuesIntervalInSeconds = 300,
            bool maintainLRU = false)
        {
            _capacity = capacity > 0 ? capacity : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(capacity)));
            _options = options;
            _map = new ConcurrentDictionary<TKey, LRUCacheItem<TKey, TValue>>(comparer ?? EqualityComparer<TKey>.Default);
            _removeExpiredValuesIntervalInSeconds = 1000 * removeExpiredValuesIntervalInSeconds;
            _removeExpiredValues = removeExpiredValues;
            _maintainLRU = maintainLRU;
            _dueForExpiredValuesRemoval = DateTime.UtcNow.AddSeconds(_removeExpiredValuesIntervalInSeconds);
        }

        /// <summary>
        /// Occurs when the application is ready to exit.
        /// </summary>
        /// <param name="sender">The sender of the event.</param>
        /// <param name="e">The event argument.</param>
        private void DomainProcessExit(object sender, EventArgs e) => StopEventQueueTask();

        /// <summary>
        /// Occurs when an AppDomain is about to be unloaded.
        /// </summary>
        /// <param name="sender">The sender of the event.</param>
        /// <param name="e">The event argument.</param>
        private void DomainUnload(object sender, EventArgs e) => StopEventQueueTask();

        /// <summary>
        /// Stop the event queue task if it is running. This allows the task/thread to terminate gracefully.
        /// </summary>
        private void StopEventQueueTask() => _shouldStopImmediately = true;

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
        /// This is the delegate for the event queue task.
        /// </summary>
        private void EventQueueTaskAction()
        {
            Interlocked.Increment(ref _taskCount);
            // Keep running until the queue is empty or the AppDomain is about to be unloaded or the application is ready to exit.
            while (!_shouldStopImmediately)
            {
                // always set the state to EventQueueTaskRunning in case it was set to EventQueueTaskDoNotStop
                Interlocked.Exchange(ref _eventQueueTaskState, EventQueueTaskRunning);

                try
                {
                    // remove expired items if needed
                    if (_removeExpiredValues && DateTime.UtcNow >= _dueForExpiredValuesRemoval)
                    {
                        RemoveExpiredValues();
                        _dueForExpiredValuesRemoval = DateTime.UtcNow.AddSeconds(_removeExpiredValuesIntervalInSeconds);
                    }

                    // process all events in the queue and exit
                    if (_eventQueue.TryDequeue(out var action))
                    {
                        action?.Invoke();
                    }
                    else
                    {
                        // Setting _eventQueueTaskState = EventQueueTaskStopped if _eventQueueTaskState == EventQueueTaskRunning.
                        // This means no other thread came in and it is safe to end this task.
                        // If another thread adds new events while this task is still running, it will set the _eventQueueTaskState = EventQueueTaskDoNotStop instead of starting a new task.
                        // The Interlocked.CompareExchange() call below will not succeed and the loop continues (until the event queue is empty).
                        // This should prevent a rare (but theoretically possible) scenario caused by context switching.
                        if (Interlocked.CompareExchange(ref _eventQueueTaskState, EventQueueTaskStopped, EventQueueTaskRunning) == EventQueueTaskRunning)
                            break;

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
                LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10902, LogHelper.MarkAsNonPII(nameof(RemoveExpiredValues)), ex));
            }

            return numItemsRemoved;
        }

        /// <summary>
        /// Remove items from the LinkedList by the desired compaction percentage.
        /// This should be a private method.
        /// </summary>
        private void RemoveLRUs()
        {
            // use the smaller of _map.Count and _capacity as the current count
            int currentCount = Math.Min(_map.Count, _capacity);

            // use the _capacity for the newCacheSize calculation in the case where the cache is experiencing overflow
            var newCacheSize = currentCount - (int)(currentCount * _compactionPercentage);
            while (_map.Count > newCacheSize && _doubleLinkedList.Count > 0)
            {
                var lru = _doubleLinkedList.Last;
                if (_map.TryRemove(lru.Value.Key, out var cacheItem))
                    OnItemRemoved?.Invoke(cacheItem.Value);

                _doubleLinkedList.Remove(lru);
            }
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
                if (_maintainLRU)
                {
                    AddActionToEventQueue(() =>
                    {
                        _doubleLinkedList.Remove(cacheItem);
                        _doubleLinkedList.AddFirst(cacheItem);
                    });
                }
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
        /// This method is called after an item is added to the event queue. It will start the event queue task if one is not already running (_eventQueueTaskState != EventQueueTaskRunning).
        /// Using CompareExchange to set the _eventQueueTaskState prevents multiple tasks from being started.
        /// </summary>
        private void StartEventQueueTaskIfNotRunning()
        {
            // Setting _eventQueueTaskState to EventQueueTaskDoNotStop here will force the event queue task in EventQueueTaskAction to continue even if the event queue is empty and it is ready to exit.
            // It is mainly to prevent a rare (but theoretically possible) thread synchronization issue.
            // For example:
            //   1. the task execution in EventQueueTaskAction() checks event queue and it is empty (ready to exit)
            //   2. the execution is switched to this thread (before the event queue task calls the Interlocked.CompareExchange() to set the _eventQueueTaskState to EventQueueTaskStopped)
            //   3. now since the _eventQueueTaskState == EventQueueTaskRunning, it can be set to EventQueueTaskDoNotStop by the Interlocked.CompareExchange() below
            //   4. if _eventQueueTaskState is successfully set to EventQueueTaskDoNotStop, the Interlocked.CompareExchange() in the EventQueueTaskAction() will fail
            //      and the task will continue the while loop and the new event will keep the task running
            //   5. if _eventQueueTaskState is NOT set to EventQueueTaskDoNotStop because execution switches back to the EventQueueTaskAction() and the _eventQueueTaskState is
            //      set to EventQueueTaskStopped (task exits), then the second Interlocked.CompareExchange() below should set the _eventQueueTaskState to EventQueueTaskRunning
            //      and start a task again (though this scenario is unlikely to happen)
            //
            // Without the EventQueueTaskDoNotStop state check below, steps (3), (4) and (5) above will not be applicable.
            // After step (2) the event queue task is still running and the state is still EventQueueTaskRunning (even though the EventQueueTaskAction() method has already checked that the queue is empty
            // and is about to stop the task). This method (StartEventQueueTaskIfNotRunning()) will return, the execution will switch over to EventQueueTaskAction(),
            // and the task will terminate. This means no new task would be started to process the newly added event.
            //
            // This scenario is unlikely to happen, as it can only occur if the event queue task ALREADY checked the queue and it was empty, and the new event was added AFTER that check but BEFORE the
            // event queue task set the _eventQueueTaskState to EventQueueTaskStopped.

            if (Interlocked.CompareExchange(ref _eventQueueTaskState, EventQueueTaskDoNotStop, EventQueueTaskRunning) == EventQueueTaskRunning)
            {
                return;
            }

            // If the task is stopped, set _eventQueueTaskState = EventQueueTaskRunning and start a new task.
            // Note: we need to call the Task.Run() to start a new task on the default TaskScheduler (TaskScheduler.Default) so it does not interfere with
            // the caller's TaskScheduler (if there is one) as some custom TaskSchedulers might be single-threaded and its execution can be blocked.
            if (Interlocked.CompareExchange(ref _eventQueueTaskState, EventQueueTaskRunning, EventQueueTaskStopped) == EventQueueTaskStopped)
            {
                Task.Run(EventQueueTaskAction);
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
            if (_map.TryGetValue(key, out var cacheItem) && _maintainLRU)
            {
                AddActionToEventQueue(() =>
                {
                    _doubleLinkedList.Remove(cacheItem);
                    _doubleLinkedList.AddFirst(cacheItem);
                });
            }

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

