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
    /// This is a simplified version of <see cref="EventBasedCache{TKey, TValue}"/>.
    /// It doesn't support LRU, and it doesn't add to the event queue if already at capacity.
    /// </summary>
    /// <typeparam name="TKey">The key type to be used by the cache.</typeparam>
    /// <typeparam name="TValue">The value type to be used by the cache</typeparam>
    internal class EventBasedCache<TKey, TValue>
    {
        private readonly int _capacity;
        private readonly List<LRUCacheItem<TKey, TValue>> _compactedItems = new List<LRUCacheItem<TKey, TValue>>();
        // The percentage of the cache to be removed when _maxCapacityPercentage is reached.
        private readonly double _compactionPercentage = .20;
        private readonly LinkedList<LRUCacheItem<TKey, TValue>> _doubleLinkedList = new LinkedList<LRUCacheItem<TKey, TValue>>();
        private readonly ConcurrentQueue<Action> _eventQueue = new ConcurrentQueue<Action>();
        private readonly ConcurrentDictionary<TKey, LRUCacheItem<TKey, TValue>> _map;
        // When the current cache size gets to this percentage of _capacity, _compactionPercentage% of the cache will be removed.
        private readonly double _maxCapacityPercentage = .95;

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
        private readonly Task _eventQTask;
        private readonly int _eventQueuePollingInterval = 50; // in milliseconds

        // set to true when the AppDomain is to be unloaded or the default AppDomain process is ready to exit
        private bool _stopEventQueueTask;

        public EventBasedLRUCache<TKey, TValue>.ItemExpired OnItemExpired { get; set; }

        public EventBasedLRUCache<TKey, TValue>.ItemCompacted OnItemMovedToCompactedList { get; set; }

        public EventBasedLRUCache<TKey, TValue>.ItemRemoved OnItemRemovedFromCompactedList { get; set; }

        public EventBasedLRUCache<TKey, TValue>.ShouldRemove OnShouldRemoveFromCompactedList { get; set; }
        #endregion

        /// <summary>
        /// Initializes a new instance of the <see cref="EventBasedCache{TKey, TValue}"/> class.
        /// </summary>
        /// <param name="capacity">The capacity of the cache, used to determine if experiencing overflow.</param>
        /// <param name="comparer">The equality comparison implementation to be used by the map when comparing keys.</param>
        /// <param name="removeExpiredValues">Whether or not to remove expired items.</param>
        /// <param name="removeExpiredValuesIntervalInSeconds">The period to wait to remove expired items, in seconds.</param>
        internal EventBasedCache(
            int capacity,
            IEqualityComparer<TKey> comparer,
            bool removeExpiredValues,
            int removeExpiredValuesIntervalInSeconds)
        {
            _capacity = capacity > 0 ? capacity : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(capacity)));
            _map = new ConcurrentDictionary<TKey, LRUCacheItem<TKey, TValue>>(comparer ?? EqualityComparer<TKey>.Default);
            _removeExpiredValuesIntervalInSeconds = removeExpiredValuesIntervalInSeconds;
            _removeExpiredValues = removeExpiredValues;
            _timeForNextExpiredValuesRemoval = DateTime.UtcNow.AddSeconds(_removeExpiredValuesIntervalInSeconds);
            _eventQTask = Task.Run(EventQueueTaskAction);
        }

        /// <summary>
        /// Stop the event queue task.
        /// This is provided mainly for users who have unit tests that check for running task(s) to stop the task at the end of each test.
        /// </summary>
        internal void StopEventQueueTaskImmediately() => _stopEventQueueTask = true;

        private void AddActionToEventQueue(Action action)
        {
            _eventQueue.Enqueue(action);
        }

        /// <summary>
        /// This is the delegate for the event queue task.
        /// </summary>
        private void EventQueueTaskAction()
        {
            try
            {
                // Keep running until instructed to stop.
                // When the event queue is empty, the thread will sleep for a specified number of milliseconds before checking again.
                while (!_stopEventQueueTask)
                {
                    try
                    {
                        // remove expired items if needed
                        if (_removeExpiredValues && DateTime.UtcNow >= _timeForNextExpiredValuesRemoval)
                        {
                            if (Interlocked.CompareExchange(ref _removeExpiredValuesState, ActionNotQueued, ActionQueuedOrRunning) == ActionQueuedOrRunning)
                            {
                                RemoveExpiredValues();
                            }
                        }

                        if (_eventQueue.TryDequeue(out var action))
                        {
                            action?.Invoke();
                        }
                        else
                        {
                            Thread.Sleep(_eventQueuePollingInterval);
                        }
                    }
#pragma warning disable CA1031 // Do not catch general exception types
                    catch (Exception ex)
                    {
                        if (LogHelper.IsEnabled(EventLogLevel.Warning))
                            LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10900, ex));
                    }
                }
            }
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                if (LogHelper.IsEnabled(EventLogLevel.Warning))
                    LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10900, ex));
            }
        }

        /// <summary>
        /// Remove all expired cache items from the _map ONLY.
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
                    LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10902, LogHelper.MarkAsNonPII(nameof(RemoveExpiredValues)), ex));
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
                    if ((OnShouldRemoveFromCompactedList is null) || OnShouldRemoveFromCompactedList(_compactedItems[i].Value))
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
        /// Remove items from the Dictionary by the desired compaction percentage.
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
        private int CalculateNewCacheSize()
        {
            // use the smaller of _map.Count and _capacity
            int currentCount = Math.Min(_map.Count, _capacity);

            // use the _capacity for the newCacheSize calculation in the case where the cache is experiencing overflow
            return currentCount - (int)(currentCount * _compactionPercentage);
        }

        public bool TrySetValue(TKey key, TValue value, DateTime expirationTime)
        {
            if (key is null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (value is null)
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
            }
            else
            {
                // if cache is at _maxCapacityPercentage, trim it by _compactionPercentage
                if ((double)_map.Count / _capacity >= _maxCapacityPercentage)
                {
                    if (Interlocked.CompareExchange(ref _compactValuesState, ActionQueuedOrRunning, ActionNotQueued) == ActionNotQueued)
                    {
                        AddActionToEventQueue(Compact);

                        if (Interlocked.CompareExchange(ref _processCompactedValuesState, ActionQueuedOrRunning, ActionNotQueued) == ActionNotQueued)
                            AddActionToEventQueue(ProcessCompactedValues);
                    }

                    return false;
                }

                var newCacheItem = new LRUCacheItem<TKey, TValue>(key, value, expirationTime);
                _map[key] = newCacheItem;
            }

            return true;
        }

        internal KeyValuePair<TKey, LRUCacheItem<TKey, TValue>>[] ToArray() => _map.ToArray();

        public bool TryGetValue(TKey key, out TValue value)
        {
            if (key is null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!_map.TryGetValue(key, out var cacheItem))
            {
                value = default;
                return false;
            }

            value = cacheItem is not null ? cacheItem.Value : default;
            return cacheItem is not null;
        }

        // These Try methods are not thread safe and they rely on the SignatureProviders to have logic to dispose of important objects.
        // A better design would be to have TryRemove move the SignatureProvider to the compacted list.
        // This would need a new action in LRUCache, AddItemToCompactedList.

        /// Removes a particular key from the cache.
        public bool TryRemove(TKey key, out LRUCacheItem<TKey, TValue> cacheItem)
        {
            if (key is null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!_map.TryRemove(key, out cacheItem))
            {
                cacheItem = default;
                return false;
            }

            OnItemMovedToCompactedList?.Invoke(cacheItem.Value);

            return true;
        }

        #region FOR TESTING (INTERNAL ONLY)

        internal LinkedList<LRUCacheItem<TKey, TValue>> LinkedList => _doubleLinkedList;

        internal long LinkedListCount => _doubleLinkedList.Count;

        internal long MapCount => _map.Count;

        /// <returns></returns>
        internal ICollection<LRUCacheItem<TKey, TValue>> MapValues => _map.Values;

        internal long EventQueueCount => _eventQueue.Count;

        #endregion
    }
}
