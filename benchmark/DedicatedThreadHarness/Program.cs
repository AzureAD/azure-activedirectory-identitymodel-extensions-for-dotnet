// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace DedicatedThreadHarness
{
    /// <summary>
    /// Exercises <see cref="BackgroundConfigurationManager{T}"/> under concurrent synchronous load.
    /// The mock retriever sleeps on the dedicated retrieval thread and records retrieval and overlap counts.
    /// </summary>
    internal static class Program
    {
        private const string Audience = "https://www.contoso.com/api";
        private const string Issuer = "https://www.contoso.com";
        private const string UpdateConfigAsBlockingSwitch = "Switch.Microsoft.IdentityModel.UpdateConfigAsBlocking";

        private static int Main(string[] args)
        {
            if (args.Length >= 3 &&
                string.Equals(args[0], "--stress-test-variant", StringComparison.OrdinalIgnoreCase) &&
                bool.TryParse(args[1], out bool useProductionConfigurationManager) &&
                bool.TryParse(args[2], out bool useAsyncRetrieval))
            {
                return StressTests.RunVariant(
                    args.Skip(3).ToArray(),
                    useProductionConfigurationManager,
                    useAsyncRetrieval);
            }

            // Stress modes model key rotation and injected retrieval failures. The default mode is a
            // focused throughput comparison and thread starvation reproducer between ThreadPool and dedicated-thread retrieval.
            // ignore these 2 flags for now
            if (args.Length > 0 &&
                string.Equals(args[0], "--stress-tests", StringComparison.OrdinalIgnoreCase))
            {
                return StressTests.Run(
                    args.Skip(1).ToArray(),
                    useProductionConfigurationManager: false);
            }

            if (args.Length > 0 &&
                string.Equals(args[0], "--production-stress-tests", StringComparison.OrdinalIgnoreCase))
            {
                return StressTests.Run(
                    args.Skip(1).ToArray(),
                    useProductionConfigurationManager: true);
            }

            if (!HarnessHelpers.TryParseOptions(args, out HarnessOptions options, out string error))
            {
                Console.Error.WriteLine(error);
                Console.Error.WriteLine();
                HarnessHelpers.PrintUsage();
                return 1;
            }

            AppContext.SetSwitch(UpdateConfigAsBlockingSwitch, options.BlockingRefresh);
            // option to limit the threadpool with --threadpool-size
            if (options.ThreadPoolSize is int poolSize)
            {
                ThreadPool.GetMaxThreads(out _, out int maxCompletion);
                ThreadPool.SetMinThreads(poolSize, poolSize);
                ThreadPool.SetMaxThreads(poolSize, maxCompletion);
            }

            SigningCredentials signingCredentials = HarnessHelpers.CreateSigningCredentials();
            var handler = new JsonWebTokenHandler();
            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Claims = HarnessHelpers.CreateClaims(Issuer, Audience),
                SigningCredentials = signingCredentials,
            });
            var retriever = new MockConfigurationRetriever(options.RetrieverDelay, signingCredentials.Key);
            BaseConfigurationManager manager = CreateConfigurationManager(retriever, options);
            var observations = new VersionObservations();
            var refreshSignals = new ConcurrentQueue<RefreshSignal>();

            Console.WriteLine("Dedicated thread configuration retrieval harness");
            Console.WriteLine($"  Runtime                  : {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
            Console.WriteLine($"  Logical processors       : {Environment.ProcessorCount}");
            Console.WriteLine($"  Incoming request rate    : {options.RequestRate:N0}/second");
            Console.WriteLine($"  Run duration             : {HarnessHelpers.FormatDuration(options.RunDuration)}");
            Console.WriteLine($"  Retriever delay          : {HarnessHelpers.FormatDuration(options.RetrieverDelay)}");
            Console.WriteLine($"  RequestRefresh cadence   : once every {HarnessHelpers.FormatDuration(options.RefreshInterval)}");
            Console.WriteLine($"  Configuration retrieval  : {(options.UseThreadPoolRetriever ? "production ConfigurationManager (ThreadPool refresh)" : "BackgroundConfigurationManager (dedicated thread)")}");
            if (!options.UseThreadPoolRetriever)
                Console.WriteLine($"  Dedicated fetch entrypoint: {(options.UseAsyncFetch ? "GetConfigurationAsync" : "GetConfigurationSync")}");
            Console.WriteLine($"  Validation entrypoint    : {(options.UseAsyncValidation ? "ValidateTokenAsync" : "ValidateToken")}");
            Console.WriteLine($"  Refresh mode             : {(options.BlockingRefresh ? "blocking" : "non-blocking")}");
            if (options.ThreadPoolSize is int cappedSize)
                Console.WriteLine($"  ThreadPool worker cap    : {cappedSize:N0} (min=max)");
            Console.WriteLine();

            // this runs the harness
            LoadResult loadResult = RunOpenLoopLoad(
                handler,
                token,
                manager,
                observations,
                refreshSignals,
                options);

            // everything else is just diagnostic logging:
            Console.WriteLine("Results");
            Console.WriteLine($"  Requests submitted       : {loadResult.Submitted:N0}");
            Console.WriteLine($"  Requests started         : {loadResult.Started:N0}");
            Console.WriteLine($"  Requests completed       : {loadResult.Completed:N0}");
            Console.WriteLine($"  Requests canceled/abandoned: {loadResult.Canceled:N0}");
            Console.WriteLine($"  Request failures         : {loadResult.Failures:N0}");
            if (loadResult.Latencies is not null)
            {
                Console.WriteLine($"  Maximum queue depth      : {loadResult.Latencies.MaximumQueueDepth:N0}");
                Console.WriteLine($"  Queue delay p50/p95/p99  : {loadResult.Latencies.QueueDelay}");
                Console.WriteLine($"  Execution p50/p95/p99    : {loadResult.Latencies.ExecutionLatency}");
                Console.WriteLine($"  End-to-end p50/p95/p99   : {loadResult.Latencies.EndToEndLatency}");
            }
            Console.WriteLine($"  Retriever calls started  : {retriever.StartedCount:N0}");
            Console.WriteLine($"  Retriever calls complete : {retriever.CompletedCount:N0}");
            Console.WriteLine($"  Max retrieval overlap    : {retriever.MaxConcurrentRetrievals:N0}");
            Console.WriteLine($"  Retrieval thread IDs     : {string.Join(", ", retriever.RetrievalThreadIds)}");
            Console.WriteLine("  Retriever fetch starts   :");
            RetrievalStart[] retrievalStarts = retriever.RetrievalStarts;
            for (int i = 0; i < retrievalStarts.Length; i++)
            {
                RetrievalStart retrievalStart = retrievalStarts[i];
                string interval = i == 0
                    ? "initial"
                    : $"+{(retrievalStart.Timestamp - retrievalStarts[i - 1].Timestamp).TotalMilliseconds:N2} ms";
                Console.WriteLine(
                    $"    #{retrievalStart.Number:N0} {retrievalStart.Timestamp:O} " +
                    $"({interval}, thread {retrievalStart.ThreadId})");
            }
            Console.WriteLine("  Retriever fetch completions:");
            RetrievalCompletion[] retrievalCompletions = retriever.RetrievalCompletions;
            var retrievalStartsByNumber = retrievalStarts.ToDictionary(start => start.Number);
            foreach (RetrievalCompletion retrievalCompletion in retrievalCompletions)
            {
                string duration = retrievalStartsByNumber.TryGetValue(
                    retrievalCompletion.Number,
                    out RetrievalStart retrievalStart)
                    ? $"{(retrievalCompletion.Timestamp - retrievalStart.Timestamp).TotalMilliseconds:N2} ms"
                    : "start unavailable";
                Console.WriteLine(
                    $"    #{retrievalCompletion.Number:N0} {retrievalCompletion.Timestamp:O} " +
                    $"({duration}, thread {retrievalCompletion.ThreadId})");
            }
            Console.WriteLine("  RequestRefresh signals   :");
            RefreshSignal[] signals = refreshSignals.ToArray();
            foreach (RefreshSignal signal in signals)
                Console.WriteLine($"    #{signal.Number:N0} {signal.Timestamp:O}");

            Console.WriteLine("  Signal-to-fetch delays   :");
            for (int retrievalIndex = 1; retrievalIndex < retrievalStarts.Length; retrievalIndex++)
            {
                RetrievalStart retrievalStart = retrievalStarts[retrievalIndex];
                RefreshSignal? precedingSignal = null;
                foreach (RefreshSignal signal in signals)
                {
                    if (signal.Timestamp > retrievalStart.Timestamp)
                        break;

                    precedingSignal = signal;
                }

                if (precedingSignal.HasValue)
                {
                    double delay = (retrievalStart.Timestamp - precedingSignal.Value.Timestamp).TotalMilliseconds;
                    Console.WriteLine(
                        $"    fetch #{retrievalStart.Number:N0} after signal #{precedingSignal.Value.Number:N0}: " +
                        $"{delay:N2} ms");
                }
            }
            Console.WriteLine($"  Configuration transitions: {string.Join(" -> ", observations.Transitions)}");

            return loadResult.Failures == 0 ? 0 : 2;
        }

        // this creates a ConfigurationManager that gets VersionedConfigurations, allowing us to ensure that configurations are moving forward
        private static BaseConfigurationManager CreateConfigurationManager(
            MockConfigurationRetriever retriever,
            HarnessOptions options)
        {
            const string metadataAddress = "https://www.contoso.com/.well-known/openid-configuration";
            var documentRetriever = new HarnessDocumentRetriever();
            BaseConfigurationManager manager;

            // --threadpool-retriever (options.UseThreadPoolRetriever) means we want to use the existing production ConfigurationManager, which uses the ThreadPool to refresh configurations
            // with a Task.Run() background kickoff
            if (options.UseThreadPoolRetriever)
            {
                manager = options.UseAsyncValidation
                    ? new ConfigurationManager<VersionedConfiguration>(
                        metadataAddress,
                        retriever,
                        documentRetriever)
                    : new ConfigurationManagerSync<VersionedConfiguration>(
                        metadataAddress,
                        retriever,
                        documentRetriever);
            }
            else
            {
                // --async-fetch (options.UseAsyncFetch) means we want to use DocumentRetriever.GetDocumentAsync() to fetch the configuration vs. DocumentRetriever.GetDocument() (sync)
                if (options.UseAsyncFetch)
                {
                    var dedicatedThreadRetriever = new DedicatedThreadRetriever<VersionedConfiguration>(
                            metadataAddress,
                            retriever,
                            documentRetriever);

                    manager = new BackgroundConfigurationManager<VersionedConfiguration>(
                        metadataAddress,
                        dedicatedThreadRetriever);
                }
                else
                {
                    DedicatedThreadRetriever<VersionedConfiguration> dedicatedThreadRetriever =
                        DedicatedThreadRetriever<VersionedConfiguration>.CreateSync(
                            metadataAddress,
                            retriever,
                            documentRetriever);

                    manager = new BackgroundConfigurationManagerSync<VersionedConfiguration>(
                        metadataAddress,
                        dedicatedThreadRetriever);
                }
            }

            manager.RefreshInterval = BaseConfigurationManager.MinimumRefreshInterval;
            return manager;
        }

        private static LoadResult RunOpenLoopLoad(
            JsonWebTokenHandler handler,
            string token,
            BaseConfigurationManager manager,
            VersionObservations observations,
            ConcurrentQueue<RefreshSignal> refreshSignals,
            HarnessOptions options)
        {
            long startTimestamp = Stopwatch.GetTimestamp();
            long endTimestamp = startTimestamp + HarnessHelpers.ToStopwatchTicks(options.RunDuration);
            long refreshIntervalTicks = HarnessHelpers.ToStopwatchTicks(options.RefreshInterval);
            long nextRefreshTimestamp = startTimestamp + refreshIntervalTicks;
            long refreshSignalNumber = 0;
            var metrics = new RequestMetrics();
            var cancellation = new CancellationTokenSource();
            TokenValidationParameters validationParameters = HarnessHelpers.CreateValidationParameters<VersionedConfiguration>(
                manager,
                Audience,
                Issuer,
                configuration => observations.RecordVersion(configuration.Version));

            // Generate arrivals independently of request completion so ThreadPool starvation is visible
            // as queue delay instead of being hidden by a closed-loop workload.
            var producer = new Thread(() =>
            {
                double requestIntervalTicks = (double)Stopwatch.Frequency / options.RequestRate;
                double nextRequestTimestamp = startTimestamp;

                while (Stopwatch.GetTimestamp() < endTimestamp)
                {
                    long now = Stopwatch.GetTimestamp();
                    if (now < nextRequestTimestamp)
                    {
                        if (nextRequestTimestamp - now > Stopwatch.Frequency / 500)
                            Thread.Sleep(1);
                        else
                            Thread.SpinWait(20);

                        continue;
                    }

                    long enqueueTimestamp = Stopwatch.GetTimestamp();
                    metrics.RecordSubmission();
                    // we add work items to the ThreadPool at a rate of --request-rate per second
                    ThreadPool.UnsafeQueueUserWorkItem(
                        static state => state.Execute(),
                        new RequestWorkItem(
                            handler,
                            token,
                            validationParameters,
                            metrics,
                            enqueueTimestamp,
                            options.UseAsyncValidation,
                            cancellation.Token),
                        preferLocal: false);
                    nextRequestTimestamp += requestIntervalTicks;
                }
            })
            {
                IsBackground = true,
                Name = "DedicatedThreadHarness request producer",
            };

            producer.Start();

            while (Stopwatch.GetTimestamp() < endTimestamp)
            {
                long now = Stopwatch.GetTimestamp();
                if (now >= nextRefreshTimestamp)
                {
                    // Record the signal separately from retrieval starts to expose refresh dispatch latency.
                    refreshSignals.Enqueue(
                        new RefreshSignal(
                            ++refreshSignalNumber,
                            DateTimeOffset.UtcNow));
                    manager.RequestRefresh();
                    nextRefreshTimestamp = Stopwatch.GetTimestamp() + refreshIntervalTicks;
                    continue;
                }

                Thread.Sleep(1);
            }

            // Work that has not started by the end of the measurement window is intentionally abandoned.
            cancellation.Cancel();
            producer.Join();

            return metrics.CreateResult();
        }

        private sealed class RequestWorkItem
        {
            private readonly long _enqueueTimestamp;
            private readonly JsonWebTokenHandler _handler;
            private readonly RequestMetrics _metrics;
            private readonly bool _useAsyncValidation;
            private readonly CancellationToken _cancellationToken;
            private readonly string _token;
            private readonly TokenValidationParameters _validationParameters;

            internal RequestWorkItem(
                JsonWebTokenHandler handler,
                string token,
                TokenValidationParameters validationParameters,
                RequestMetrics metrics,
                long enqueueTimestamp,
                bool useAsyncValidation,
                CancellationToken cancellationToken)
            {
                _handler = handler;
                _token = token;
                _validationParameters = validationParameters;
                _metrics = metrics;
                _enqueueTimestamp = enqueueTimestamp;
                _useAsyncValidation = useAsyncValidation;
                _cancellationToken = cancellationToken;
            }

            internal void Execute()
            {
                long startTimestamp = Stopwatch.GetTimestamp();
                _metrics.RecordStart(_enqueueTimestamp, startTimestamp);

                if (_useAsyncValidation)
                {
                    _ = ExecuteAsync(startTimestamp);
                    return;
                }

                try
                {
                    _cancellationToken.ThrowIfCancellationRequested();
                    TokenValidationResult result =
                        _handler.ValidateToken(_token, _validationParameters);
                    if (!result.IsValid)
                        _metrics.RecordFailure();
                }
                catch (OperationCanceledException)
                {
                }
#pragma warning disable CA1031 // The harness records request failures so all queued work can drain.
                catch (Exception)
#pragma warning restore CA1031
                {
                    _metrics.RecordFailure();
                }
                finally
                {
                    _metrics.RecordCompletion(_enqueueTimestamp, startTimestamp, Stopwatch.GetTimestamp());
                }
            }

            private async Task ExecuteAsync(long startTimestamp)
            {
                try
                {
                    _cancellationToken.ThrowIfCancellationRequested();
                    TokenValidationResult result = await _handler
                        .ValidateTokenAsync(_token, _validationParameters)
                        .ConfigureAwait(false);
                    if (!result.IsValid && !_cancellationToken.IsCancellationRequested)
                        _metrics.RecordFailure();
                }
                catch (OperationCanceledException)
                {
                }
#pragma warning disable CA1031 // The harness records request failures so all queued work can drain.
                catch (Exception)
#pragma warning restore CA1031
                {
                    _metrics.RecordFailure();
                }
                finally
                {
                    _metrics.RecordCompletion(_enqueueTimestamp, startTimestamp, Stopwatch.GetTimestamp());
                }
            }
        }

        private sealed class RequestMetrics
        {
            private readonly ConcurrentQueue<long> _endToEndLatencies = new();
            private readonly ConcurrentQueue<long> _executionLatencies = new();
            private readonly ConcurrentQueue<long> _queueDelays = new();
            private long _completed;
            private long _failures;
            private int _maximumQueueDepth;
            private long _started;
            private long _submitted;

            internal void RecordSubmission()
            {
                long submitted = Interlocked.Increment(ref _submitted);
                long started = Interlocked.Read(ref _started);
                HarnessHelpers.UpdateMaximum(
                    ref _maximumQueueDepth,
                    checked((int)(submitted - started)));
            }

            internal void RecordStart(long enqueueTimestamp, long startTimestamp)
            {
                _queueDelays.Enqueue(startTimestamp - enqueueTimestamp);
                Interlocked.Increment(ref _started);
            }

            internal void RecordCompletion(long enqueueTimestamp, long startTimestamp, long completionTimestamp)
            {
                _executionLatencies.Enqueue(completionTimestamp - startTimestamp);
                _endToEndLatencies.Enqueue(completionTimestamp - enqueueTimestamp);

                Interlocked.Increment(ref _completed);
            }

            internal void RecordFailure()
            {
                Interlocked.Increment(ref _failures);
            }

            internal LoadResult CreateResult()
            {
                long submitted = Interlocked.Read(ref _submitted);
                long completed = Interlocked.Read(ref _completed);
                return new LoadResult(
                    submitted,
                    Interlocked.Read(ref _started),
                    completed,
                    submitted - completed,
                    Interlocked.Read(ref _failures),
                    new LatencyResults(
                        Volatile.Read(ref _maximumQueueDepth),
                        FormatPercentiles(_queueDelays),
                        FormatPercentiles(_executionLatencies),
                        FormatPercentiles(_endToEndLatencies)));
            }

            private static string FormatPercentiles(ConcurrentQueue<long> samples)
            {
                long[] values = samples.ToArray();
                Array.Sort(values);

                return $"{ToMilliseconds(GetPercentile(values, 0.50)):N2} / " +
                    $"{ToMilliseconds(GetPercentile(values, 0.95)):N2} / " +
                    $"{ToMilliseconds(GetPercentile(values, 0.99)):N2} ms";
            }

            private static long GetPercentile(long[] sortedValues, double percentile)
            {
                if (sortedValues.Length == 0)
                    return 0;

                int index = Math.Min(
                    sortedValues.Length - 1,
                    (int)Math.Ceiling(sortedValues.Length * percentile) - 1);
                return sortedValues[index];
            }

            private static double ToMilliseconds(long stopwatchTicks)
            {
                return stopwatchTicks * 1000d / Stopwatch.Frequency;
            }

        }

        private sealed class LoadResult
        {
            internal LoadResult(
                long submitted,
                long started,
                long completed,
                long canceled,
                long failures,
                LatencyResults? latencies)
            {
                Submitted = submitted;
                Started = started;
                Completed = completed;
                Canceled = canceled;
                Failures = failures;
                Latencies = latencies;
            }

            internal long Submitted { get; }

            internal long Started { get; }

            internal long Completed { get; }

            internal long Canceled { get; }

            internal long Failures { get; }

            internal LatencyResults? Latencies { get; }
        }

        private sealed class LatencyResults
        {
            internal LatencyResults(
                int maximumQueueDepth,
                string queueDelay,
                string executionLatency,
                string endToEndLatency)
            {
                MaximumQueueDepth = maximumQueueDepth;
                QueueDelay = queueDelay;
                ExecutionLatency = executionLatency;
                EndToEndLatency = endToEndLatency;
            }

            internal int MaximumQueueDepth { get; }

            internal string QueueDelay { get; }

            internal string ExecutionLatency { get; }

            internal string EndToEndLatency { get; }
        }

        private sealed class MockConfigurationRetriever :
            IConfigurationRetriever<VersionedConfiguration>,
            IConfigurationRetrieverSync<VersionedConfiguration>
        {
            private readonly TimeSpan _delay;
            private readonly SecurityKey _signingKey;
            private readonly ManualResetEventSlim _idle = new(true);
            private readonly ConcurrentQueue<RetrievalCompletion> _retrievalCompletions = new();
            private readonly ConcurrentQueue<RetrievalStart> _retrievalStarts = new();
            private readonly ConcurrentDictionary<int, byte> _retrievalThreadIds = new();
            private long _startedCount;
            private long _completedCount;
            private int _activeRetrievals;
            private int _maxConcurrentRetrievals;

            internal MockConfigurationRetriever(TimeSpan delay, SecurityKey signingKey)
            {
                _delay = delay;
                _signingKey = signingKey;
            }

            internal long StartedCount => Interlocked.Read(ref _startedCount);

            internal long CompletedCount => Interlocked.Read(ref _completedCount);

            internal int MaxConcurrentRetrievals => Volatile.Read(ref _maxConcurrentRetrievals);

            internal RetrievalCompletion[] RetrievalCompletions => _retrievalCompletions.ToArray();

            internal RetrievalStart[] RetrievalStarts => _retrievalStarts.ToArray();

            internal int[] RetrievalThreadIds
            {
                get
                {
                    int[] threadIds = _retrievalThreadIds.Keys.ToArray();
                    Array.Sort(threadIds);
                    return threadIds;
                }
            }

            internal void WaitForIdle()
            {
                _idle.Wait();
            }

            public async Task<VersionedConfiguration> GetConfigurationAsync(
                string address,
                IDocumentRetriever retriever,
                CancellationToken cancel)
            {
                long retrievalNumber = BeginRetrieval();

                try
                {
                    if (_delay > TimeSpan.Zero)
                        await Task.Delay(_delay, cancel).ConfigureAwait(false);

                    return CreateConfiguration(retrievalNumber);
                }
                finally
                {
                    CompleteRetrieval(retrievalNumber);
                }
            }

            public VersionedConfiguration GetConfigurationSync(
                string address,
                IDocumentRetrieverSync retriever,
                CancellationToken cancel)
            {
                long retrievalNumber = BeginRetrieval();

                try
                {
                    if (_delay > TimeSpan.Zero)
                        Thread.Sleep(_delay);

                    return CreateConfiguration(retrievalNumber);
                }
                finally
                {
                    CompleteRetrieval(retrievalNumber);
                }
            }

            private long BeginRetrieval()
            {
                _idle.Reset();
                long retrievalNumber = Interlocked.Increment(ref _startedCount);
                int threadId = Environment.CurrentManagedThreadId;
                _retrievalThreadIds.TryAdd(threadId, 0);
                _retrievalStarts.Enqueue(new RetrievalStart(retrievalNumber, DateTimeOffset.UtcNow, threadId));

                int activeRetrievals = Interlocked.Increment(ref _activeRetrievals);
                HarnessHelpers.UpdateMaximum(ref _maxConcurrentRetrievals, activeRetrievals);
                return retrievalNumber;
            }

            private void CompleteRetrieval(long retrievalNumber)
            {
                int threadId = Environment.CurrentManagedThreadId;
                _retrievalThreadIds.TryAdd(threadId, 0);
                _retrievalCompletions.Enqueue(
                    new RetrievalCompletion(retrievalNumber, DateTimeOffset.UtcNow, threadId));
                if (Interlocked.Decrement(ref _activeRetrievals) == 0)
                    _idle.Set();
                Interlocked.Increment(ref _completedCount);
            }

            private VersionedConfiguration CreateConfiguration(long retrievalNumber)
            {
                var configuration = new VersionedConfiguration
                {
                    Issuer = Issuer,
                    Version = checked((int)retrievalNumber),
                };
                configuration.SigningKeys.Add(_signingKey);
                return configuration;
            }

        }

        private sealed class VersionedConfiguration : OpenIdConnectConfiguration
        {
            internal int Version { get; init; }
        }

        private readonly struct RetrievalStart
        {
            internal RetrievalStart(long number, DateTimeOffset timestamp, int threadId)
            {
                Number = number;
                Timestamp = timestamp;
                ThreadId = threadId;
            }

            internal long Number { get; }

            internal DateTimeOffset Timestamp { get; }

            internal int ThreadId { get; }
        }

        private readonly struct RetrievalCompletion
        {
            internal RetrievalCompletion(long number, DateTimeOffset timestamp, int threadId)
            {
                Number = number;
                Timestamp = timestamp;
                ThreadId = threadId;
            }

            internal long Number { get; }

            internal DateTimeOffset Timestamp { get; }

            internal int ThreadId { get; }
        }

        private readonly struct RefreshSignal
        {
            internal RefreshSignal(long number, DateTimeOffset timestamp)
            {
                Number = number;
                Timestamp = timestamp;
            }

            internal long Number { get; }

            internal DateTimeOffset Timestamp { get; }
        }

        private sealed class VersionObservations
        {
            private readonly ConcurrentQueue<int> _transitions = new();
            private int _highestVersion;

            internal int[] Transitions => _transitions.ToArray();

            internal void RecordVersion(int version)
            {
                int observedHighest = Volatile.Read(ref _highestVersion);
                while (version > observedHighest)
                {
                    int previous = Interlocked.CompareExchange(ref _highestVersion, version, observedHighest);
                    if (previous == observedHighest)
                    {
                        _transitions.Enqueue(version);
                        break;
                    }

                    observedHighest = previous;
                }
            }
        }
    }
}
