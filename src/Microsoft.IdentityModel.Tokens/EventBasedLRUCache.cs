// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Abstractions;
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
        internal delegate void ItemCompacted(TValue Value);
        internal delegate void ItemExpired(TValue Value);
        internal delegate void ItemRemoved(TValue Value);
        internal delegate bool ShouldRemove(TValue Value);

        private readonly int _capacity;
        private List<LRUCacheItem<TKey, TValue>> _compactedItems = new List<LRUCacheItem<TKey, TValue>>();
        // The percentage of the cache to be removed when _maxCapacityPercentage is reached.
        private readonly double _compactionPercentage = .20;
        private LinkedList<LRUCacheItem<TKey, TValue>> _doubleLinkedList = new LinkedList<LRUCacheItem<TKey, TValue>>();
        private ConcurrentQueue<Action> _eventQueue = new ConcurrentQueue<Action>();
        private readonly TaskCreationOptions _options;
        // if true, then items will be maintained in a LRU fashion, moving to front of list when accessed in the cache.
        private readonly bool _maintainLRU;
        private ConcurrentDictionary<TKey, LRUCacheItem<TKey, TValue>> _map;
        // When the current cache size gets to this percentage of _capacity, _compactionPercentage% of the cache will be removed.
        private readonly double _maxCapacityPercentage = .95;
        private readonly int _compactIntervalInSeconds;

        // if true, expired values will not be added to the cache and clean-up of expired values will occur on a 5 minute interval
        private readonly bool _removeExpiredValues;
        private readonly int _removeExpiredValuesIntervalInSeconds;
        private DateTime _timeForNextExpiredValuesRemoval;

        #region event queue
        private const int ActionNotQueued = 0; // compaction action not in the event queue
        private const int ActionQueuedOrRunning = 1; // compaction action in the event queue or currently in progress

        private int _compactValuesState = ActionNotQueued;
        private int _removeExpiredValuesState = ActionNotQueued;
        private int _processCompactedValuesState = ActionNotQueued;
        private Task _eventQTask;
        private int _eventQueuePollingInterval = 50; // in milliseconds
        // for testing purpose only to verify the task count
        private int _taskCount;

        // set to true when the AppDomain is to be unloaded or the default AppDomain process is ready to exit
        private bool _stopEventQueueTask;

        internal ItemExpired OnItemExpired { get; set; }

        /// <summary>
        /// For back compat any friend would be broken, this is the same as OnItemExpired.
        /// </summary>
        internal ItemExpired OnItemRemoved
        {
            get { return OnItemExpired; }
            set { OnItemExpired = value; }
        }

        internal ItemCompacted OnItemMovedToCompactedList { get; set; }

        internal ItemRemoved OnItemRemovedFromCompactedList { get; set; }

        internal ShouldRemove OnShouldRemoveFromCompactedList { get; set; }
        #endregion

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="capacity">The capacity of the cache, used to determine if experiencing overflow.</param>
        /// <param name="options">The event queue task creation option, default to None instead of LongRunning as LongRunning will always start a task on a new thread instead of ThreadPool.</param>
        /// <param name="comparer">The equality comparison implementation to be used by the map when comparing keys.</param>
        /// <param name="removeExpiredValues">Whether or not to remove expired items.</param>
        /// <param name="removeExpiredValuesIntervalInSeconds">The period to wait to remove expired items, in seconds.</param>
        /// <param name="maintainLRU">Whether or not to maintain items in a LRU fashion, moving to front of list when accessed in the cache.</param>
        /// <param name="compactIntervalInSeconds">The period to wait to compact items, in seconds.</param>
        internal EventBasedLRUCache(
            int capacity,
            TaskCreationOptions options = TaskCreationOptions.None,
            IEqualityComparer<TKey> comparer = null,
            bool removeExpiredValues = false,
            int removeExpiredValuesIntervalInSeconds = 300,
            bool maintainLRU = false,
            int compactIntervalInSeconds = 20)
        {
            _capacity = capacity > 0 ? capacity : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(capacity)));
            _options = options;
            _map = new ConcurrentDictionary<TKey, LRUCacheItem<TKey, TValue>>(comparer ?? EqualityComparer<TKey>.Default);
            _removeExpiredValuesIntervalInSeconds = removeExpiredValuesIntervalInSeconds;
            _removeExpiredValues = removeExpiredValues;
            _compactIntervalInSeconds = compactIntervalInSeconds;
            _timeForNextExpiredValuesRemoval = DateTime.UtcNow.AddSeconds(_removeExpiredValuesIntervalInSeconds);
            _maintainLRU = maintainLRU;
        }

        /// <summary>
        /// Occurs when the application is ready to exit.
        /// </summary>
        /// <param name="sender">The sender of the event.</param>
        /// <param name="e">The event argument.</param>
        private void DomainProcessExit(object sender, EventArgs e) => StopEventQueueTaskImmediately();

        /// <summary>
        /// Occurs when an AppDomain is about to be unloaded.
        /// </summary>
        /// <param name="sender">The sender of the event.</param>
        /// <param name="e">The event argument.</param>
        private void DomainUnload(object sender, EventArgs e) => StopEventQueueTaskImmediately();

        /// <summary>
        /// Stop the event queue task.
        /// This is provided mainly for users who have unit tests that check for running task(s) to stop the task at the end of each test.
        /// </summary>
        internal void StopEventQueueTaskImmediately() => _stopEventQueueTask = true;

        private void AddActionToEventQueue(Action action)
        {
            if (_eventQTask == null || _eventQTask.Status != TaskStatus.Running)
                _eventQTask = Task.Run(EventQueueTaskAction);

            _eventQueue.Enqueue(action);
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

            try
            {
                // Keep running until the queue is empty or the AppDomain is about to be unloaded or the application is ready to exit.
                while (!_stopEventQueueTask)
                {
                    try
                    {
                        // remove expired items if needed
                        if (_removeExpiredValues && DateTime.UtcNow >= _timeForNextExpiredValuesRemoval)
                        {
                            if (Interlocked.CompareExchange(ref _removeExpiredValuesState, ActionNotQueued, ActionQueuedOrRunning) == ActionQueuedOrRunning)
                            {
                                if (_maintainLRU)
                                    RemoveExpiredValuesLRU();
                                else
                                    RemoveExpiredValues();
                            }
                        }

                        // process all events in the queue and exit
                        if (_eventQueue.TryDequeue(out var action))
                        {
                            action?.Invoke();
                        }
                        else // if empty, let the thread sleep for a specified number of milliseconds before attempting to retrieve another value from the queue
                        {
                            Thread.Sleep(_eventQueuePollingInterval);
                        }
                    }
                    catch (Exception ex)
                    {
                        if (LogHelper.IsEnabled(EventLogLevel.Warning))
                            LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10900, ex));
                    }
                }
            }
            catch (Exception ex)
            {
                if (LogHelper.IsEnabled(EventLogLevel.Warning))
                    LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10900, ex));
            }

            Interlocked.Decrement(ref _taskCount);
        }

        /// <summary>
        /// Remove all expired cache items from _doubleLinkedList and _map.
        /// </summary>
        /// <returns>Number of items removed.</returns>
        internal void RemoveExpiredValuesLRU()
        {
            try
            {
                LinkedListNode<LRUCacheItem<TKey, TValue>> node = _doubleLinkedList.First;
                while (node != null)
                {
                    LinkedListNode<LRUCacheItem<TKey, TValue>> nextNode = node.Next;
                    if (node.Value.ExpirationTime < DateTime.UtcNow)
                    {
                        if (_map.TryRemove(node.Value.Key, out LRUCacheItem<TKey, TValue> cacheItem))
                        {
                            OnItemExpired?.Invoke(cacheItem.Value);
                            _doubleLinkedList.Remove(node);
                        }
                    }

                    node = nextNode;
                }
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                if (LogHelper.IsEnabled(EventLogLevel.Warning))
                    LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10902, LogHelper.MarkAsNonPII(nameof(RemoveExpiredValuesLRU)), ex));
            }
            finally
            {
                _removeExpiredValuesState = ActionNotQueued;
                _timeForNextExpiredValuesRemoval = DateTime.UtcNow.AddSeconds(_removeExpiredValuesIntervalInSeconds);
            }
        }

        /// <summary>
        /// Remove all expired cache items from the _map ONLY. This is called for the non-LRU (_maintainLRU = false) scenaro.
        /// The enumerator returned from the dictionary is safe to use concurrently with reads and writes to the dictionary, according to the MS document.
        /// </summary>
        /// <returns>Number of items removed.</returns>
        internal void RemoveExpiredValues()
        {
            try
            {
                foreach (KeyValuePair<TKey, LRUCacheItem<TKey, TValue>> node in _map)
                {
                    if (node.Value.ExpirationTime < DateTime.UtcNow)
                    {
                        if (_map.TryRemove(node.Value.Key, out var cacheItem))
                            OnItemExpired?.Invoke(cacheItem.Value);
                    }
                }
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                if (LogHelper.IsEnabled(EventLogLevel.Warning))
                    LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10902, LogHelper.MarkAsNonPII(nameof(ProcessCompactedValues)), ex));
            }
            finally
            {
                _removeExpiredValuesState = ActionNotQueued;
                _timeForNextExpiredValuesRemoval = DateTime.UtcNow.AddSeconds(_removeExpiredValuesIntervalInSeconds);
            }
        }

        /// <summary>
        /// Remove all compacted items.
        /// </summary>
        internal void ProcessCompactedValues()
        {
            try
            {
                for (int i = _compactedItems.Count - 1; i >= 0; i--)
                {
                    if ((OnShouldRemoveFromCompactedList == null) || OnShouldRemoveFromCompactedList(_compactedItems[i].Value))
                    {
                        OnItemRemovedFromCompactedList?.Invoke(_compactedItems[i].Value);
                        _compactedItems.RemoveAt(i);
                    }
                }
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                if (LogHelper.IsEnabled(EventLogLevel.Warning))
                    LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10906, LogHelper.MarkAsNonPII(nameof(ProcessCompactedValues)), ex));
            }
            finally
            {
                _processCompactedValuesState = ActionNotQueued;
            }
        }

        /// <summary>
        /// Remove items from the LinkedList by the desired compaction percentage.
        /// This should be a private method.
        /// </summary>
        private void CompactLRU()
        {
            try
            {
                int newCacheSize = CalculateNewCacheSize();
                while (_map.Count > newCacheSize && _doubleLinkedList.Count > 0)
                {
                    LinkedListNode<LRUCacheItem<TKey, TValue>> node = _doubleLinkedList.Last;
                    if (_map.TryRemove(node.Value.Key, out LRUCacheItem<TKey, TValue> cacheItem))
                    {
                        OnItemMovedToCompactedList?.Invoke(cacheItem.Value);
                        _compactedItems.Add(cacheItem);
                        _doubleLinkedList.RemoveLast();
                    }
                }
            }
            finally
            {
                _compactValuesState = ActionNotQueued;
            }
        }

        /// <summary>
        /// Remove items from the Dictionary by the desired compaction percentage.
        /// Since _map does not have LRU order, items are simply removed from using FirstOrDefault(). 
        /// </summary>
        private void Compact()
        {
            try
            {
                int newCacheSize = CalculateNewCacheSize();
                while (_map.Count > newCacheSize)
                {
                    // Since all items could have been removed by the public TryRemove() method, leaving the map empty, we need to check if a default value is returned.
                    // Remove the item from the map only if the returned item is NOT default value.
                    KeyValuePair<TKey, LRUCacheItem<TKey, TValue>> item = _map.FirstOrDefault();
                    if (!item.Equals(default))
                    {
                        if (_map.TryRemove(item.Key, out LRUCacheItem<TKey, TValue> cacheItem))
                        {
                            OnItemMovedToCompactedList?.Invoke(cacheItem.Value);
                            _compactedItems.Add(cacheItem);
                        }
                    }
                }
            }
            finally
            {
                _compactValuesState = ActionNotQueued;
            }
        }

        /// <summary>
        /// When the cache is at _maxCapacityPercentage, it needs to be compacted by _compactionPercentage.
        /// This method calculates the new size of the cache after being compacted.
        /// </summary>
        /// <returns>The new target cache size after compaction.</returns>
        protected int CalculateNewCacheSize()
        {
            // use the smaller of _map.Count and _capacity
            int currentCount = Math.Min(_map.Count, _capacity);

            // use the _capacity for the newCacheSize calculation in the case where the cache is experiencing overflow
            return currentCount - (int)(currentCount * _compactionPercentage);
        }

        public bool SetValue(TKey key, TValue value)
        {
            return SetValue(key, value, DateTime.MaxValue);
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

            if (Interlocked.CompareExchange(ref _compactValuesState, ActionQueuedOrRunning, ActionQueuedOrRunning) == ActionQueuedOrRunning)
                return false;

            // just need to update value and move it to the top
            if (_map.TryGetValue(key, out var cacheItem))
            {
                cacheItem.Value = value;
                cacheItem.ExpirationTime = expirationTime;

                if (_maintainLRU)
                {
                    var localCacheItem = cacheItem; // avoid closure when !_maintainLRU
                    var localThis = this;
                    AddActionToEventQueue(() =>
                    {
                        localThis._doubleLinkedList.Remove(localCacheItem);
                        localThis._doubleLinkedList.AddFirst(localCacheItem);
                    });
                }
            }
            else
            {
                // if cache is at _maxCapacityPercentage, trim it by _compactionPercentage
                if ((double)_map.Count / _capacity >= _maxCapacityPercentage)
                {
                    if (Interlocked.CompareExchange(ref _compactValuesState, ActionQueuedOrRunning, ActionNotQueued) == ActionNotQueued)
                    {
                        if (_maintainLRU)
                            AddActionToEventQueue(CompactLRU);
                        else
                            AddActionToEventQueue(Compact);

                        if (Interlocked.CompareExchange(ref _processCompactedValuesState, ActionQueuedOrRunning, ActionNotQueued) == ActionNotQueued)
                            AddActionToEventQueue(ProcessCompactedValues);
                    }

                    return false;
                }

                var newCacheItem = new LRUCacheItem<TKey, TValue>(key, value, expirationTime);
                if (_maintainLRU)
                {
                    if (_map.TryAdd(key, newCacheItem))
                    {
                        var localCacheItem = newCacheItem; // avoid closure on fast path or when !_maintainLRU
                        var localThis = this;
                        AddActionToEventQueue(() =>
                        {
                            localThis._doubleLinkedList.Remove(localCacheItem);
                            localThis._doubleLinkedList.AddFirst(localCacheItem);
                        });
                    }
                }
                else
                {
                    _map[key] = newCacheItem;
                }
            }

            return true;
        }

        internal KeyValuePair<TKey, LRUCacheItem<TKey, TValue>>[] ToArray()
        {
            return _map.ToArray();
        }

        /// Each time a node gets accessed, it gets moved to the beginning (head) of the list if the _maintainLRU == true
        public bool TryGetValue(TKey key, out TValue value)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!_map.TryGetValue(key, out var cacheItem))
            {
                value = default;
                return false;
            }

            // make sure node hasn't been removed by a different thread
            if (_maintainLRU)
            {
                var localCacheItem = cacheItem; // avoid closure on fast path or when !_maintainLRU
                var localThis = this;
                AddActionToEventQueue(() =>
                {
                    localThis._doubleLinkedList.Remove(localCacheItem);
                    localThis._doubleLinkedList.AddFirst(localCacheItem);
                });
            }

            value = cacheItem != null ? cacheItem.Value : default;
            return cacheItem != null;
        }

        // These Try methods are not thread safe and they rely on the SignatureProviders to have logic to dispose of important objects.
        // A better design would be to have TryRemove move the SignatureProvider to the compacted list.
        // This would need a new action in LRUCache, AddItemToCompactedList.

        /// Removes a particular key from the cache.
        public bool TryRemove(TKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!_map.TryRemove(key, out var cacheItem))
                return false;

            OnItemMovedToCompactedList?.Invoke(cacheItem.Value);
            return true;
        }

        /// Removes a particular key from the cache.
        public bool TryRemove(TKey key, out TValue value)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!_map.TryRemove(key, out var cacheItem))
            {
                value = default;
                return false;
            }

            if (_maintainLRU)
            {
                var localCacheItem = cacheItem; // avoid closure on fast path or when !_maintainLRU
                var localThis = this;
                AddActionToEventQueue(() => localThis._doubleLinkedList.Remove(localCacheItem));
            }

            value = cacheItem.Value;
            OnItemMovedToCompactedList?.Invoke(cacheItem.Value);

            return true;
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
            while (!_eventQueue.IsEmpty)
            {
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
