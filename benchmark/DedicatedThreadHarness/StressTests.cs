// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace DedicatedThreadHarness
{
    internal static class StressTests
    {
        private const string Audience = "https://www.contoso.com/api";
        private const string Issuer = "https://www.contoso.com";
        private const string MetadataAddress = "https://localhost/config";
        private const string UpdateConfigAsBlockingSwitch =
            "Switch.Microsoft.IdentityModel.UpdateConfigAsBlocking";

        internal static int Run(
            string[] args,
            bool useProductionConfigurationManager)
        {
            // Validate once in the parent process before starting the isolated variants.
            if (!TryParseOptions(
                args,
                useProductionConfigurationManager,
                out _,
                out _,
                out _,
                out _))
            {
                return 1;
            }

            // A deliberately overloaded variant can leave millions of callbacks queued. Run each
            // retrieval contract in a fresh process so one ThreadPool cannot contaminate the next.
            int syncResult = RunIsolatedVariant(
                args,
                useProductionConfigurationManager,
                useAsyncRetrieval: false);

            Console.WriteLine();
            int asyncResult = RunIsolatedVariant(
                args,
                useProductionConfigurationManager,
                useAsyncRetrieval: true);

            return syncResult != 0 ? syncResult : asyncResult;
        }

        internal static int RunVariant(
            string[] args,
            bool useProductionConfigurationManager,
            bool useAsyncRetrieval)
        {
            if (!TryParseOptions(
                args,
                useProductionConfigurationManager,
                out TimeSpan duration,
                out int requestRate,
                out int retrievalFaultPercentage,
                out int threadInterruptPercentage))
            {
                return 1;
            }

            return RunVariant(
                useProductionConfigurationManager,
                useAsyncRetrieval,
                duration,
                requestRate,
                retrievalFaultPercentage,
                threadInterruptPercentage);
        }

        private static int RunIsolatedVariant(
            string[] args,
            bool useProductionConfigurationManager,
            bool useAsyncRetrieval)
        {
            string processPath = Environment.ProcessPath
                ?? throw new InvalidOperationException("Could not locate the current process.");
            var startInfo = new ProcessStartInfo(processPath)
            {
                UseShellExecute = false,
            };

            // Environment.ProcessPath is normally the generated apphost. Retain support for launching
            // the harness through `dotnet DedicatedThreadHarness.dll` as well.
            if (string.Equals(
                System.IO.Path.GetFileNameWithoutExtension(processPath),
                "dotnet",
                StringComparison.OrdinalIgnoreCase))
            {
                startInfo.ArgumentList.Add(
                    Assembly.GetEntryAssembly()?.Location
                    ?? throw new InvalidOperationException("Could not locate the harness assembly."));
            }

            startInfo.ArgumentList.Add("--stress-test-variant");
            startInfo.ArgumentList.Add(useProductionConfigurationManager.ToString());
            startInfo.ArgumentList.Add(useAsyncRetrieval.ToString());
            foreach (string argument in args)
                startInfo.ArgumentList.Add(argument);

            using Process process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("Could not start the isolated stress variant.");
            process.WaitForExit();
            return process.ExitCode;
        }

        private static int RunVariant(
            bool useProductionConfigurationManager,
            bool useAsyncRetrieval,
            TimeSpan duration,
            int requestRate,
            int retrievalFaultPercentage,
            int threadInterruptPercentage)
        {
            AppContext.SetSwitch(UpdateConfigAsBlockingSwitch, false);

            var signingState = new RotatingSigningState();
            var configurationRetriever = new FaultingConfigurationRetriever(
                signingState,
                retrievalFaultPercentage);
            var documentRetriever = new HarnessDocumentRetriever();
            DedicatedThreadRetriever<RotatingConfiguration>? dedicatedThreadRetriever = null;
            BaseConfigurationManager configurationManager;
            Func<CancellationToken, RotatingConfiguration>? getConfigurationSync = null;
            Func<CancellationToken, Task<RotatingConfiguration>>? getConfigurationAsync = null;

            if (useProductionConfigurationManager)
            {
                if (useAsyncRetrieval)
                {
                    var manager = new ConfigurationManager<RotatingConfiguration>(
                        MetadataAddress,
                        configurationRetriever,
                        documentRetriever);
                    getConfigurationAsync = manager.GetConfigurationAsync;
                    configurationManager = manager;
                }
                else
                {
                    var syncManager = new ConfigurationManagerSync<RotatingConfiguration>(
                        MetadataAddress,
                        configurationRetriever,
                        documentRetriever);
                    getConfigurationSync = syncManager.GetConfigurationSync;
                    configurationManager = syncManager;
                }

                // Production throttling (BaseConfigurationManager.MinimumRefreshInterval) would mask the short stress cadence. Override it only in this
                // standalone harness so every failed validation can request a prompt configuration refresh.
                FieldInfo refreshIntervalField = typeof(BaseConfigurationManager).GetField(
                    "_refreshInterval",
                    BindingFlags.Instance | BindingFlags.NonPublic)
                    ?? throw new InvalidOperationException(
                        "Could not locate the production refresh interval field.");
                refreshIntervalField.SetValue(configurationManager, TimeSpan.Zero);
            }
            else
            {
                if (useAsyncRetrieval)
                {
                    dedicatedThreadRetriever = new DedicatedThreadRetriever<RotatingConfiguration>(
                        MetadataAddress,
                        configurationRetriever,
                        documentRetriever);
                    var manager = new BackgroundConfigurationManager<RotatingConfiguration>(
                        MetadataAddress,
                        dedicatedThreadRetriever);
                    getConfigurationAsync = manager.GetConfigurationAsync;
                    configurationManager = manager;
                }
                else
                {
                    dedicatedThreadRetriever = DedicatedThreadRetriever<RotatingConfiguration>.CreateSync(
                        MetadataAddress,
                        configurationRetriever,
                        documentRetriever);
                    var manager = new BackgroundConfigurationManagerSync<RotatingConfiguration>(
                        MetadataAddress,
                        dedicatedThreadRetriever);
                    getConfigurationSync = manager.GetConfigurationSync;
                    configurationManager = manager;
                }
            }

            using var timeout = new CancellationTokenSource(duration + TimeSpan.FromMinutes(1));

            // Establish a known-good initial configuration before enabling faults. Subsequent progress
            // therefore proves refresh recovery rather than initial bootstrap luck.
            _ = useAsyncRetrieval
                ? getConfigurationAsync!(timeout.Token).GetAwaiter().GetResult()
                : getConfigurationSync!(timeout.Token);
            configurationRetriever.EnableFaults();

            int highestConfigurationGeneration = 0;
            int highestValidatedGeneration = 0;
            int rotationCount = 0;
            int workerInterruptCount = 0;
            long validationRetryCount = 0;
            DateTimeOffset endTime = DateTimeOffset.UtcNow + duration;

            var handler = new JsonWebTokenHandler();
            TokenValidationParameters validationParameters =
                HarnessHelpers.CreateValidationParameters<RotatingConfiguration>(
                    configurationManager,
                    Audience,
                    Issuer,
                    configuration =>
                        HarnessHelpers.UpdateMaximum(
                            ref highestConfigurationGeneration,
                            configuration.Generation));

            // Model a large upstream discontinuity: tokens immediately move to the new generation and
            // the prior key disappears from JWKS. Recovery now requires a successful configuration refresh;
            // any ThreadPool starvation delaying that refresh appears as validation retries and queue growth.
            var rotator = new Thread(() =>
            {
                var random = new Random();
                while (true)
                {
                    TimeSpan remaining = endTime - DateTimeOffset.UtcNow;
                    if (remaining <= TimeSpan.Zero)
                        return;

                    TimeSpan delay = TimeSpan.FromMilliseconds(random.Next(5000, 15001));
                    Thread.Sleep(delay < remaining ? delay : remaining);
                    if (DateTimeOffset.UtcNow >= endTime)
                        return;

                    signingState.Rotate();
                    Interlocked.Increment(ref rotationCount);
                }
            })
            {
                IsBackground = true,
                Name = "DedicatedThreadHarness signing key rotator",
            };

            Thread? interrupter = null;
            if (!useProductionConfigurationManager)
            {
                // Random interrupts model non-graceful managed worker shutdown. The dedicated retriever
                // must replace the worker and preserve liveness for queued and future retrievals.
                FieldInfo workerField = typeof(DedicatedThreadRetriever<RotatingConfiguration>)
                    .GetField("_worker", BindingFlags.Instance | BindingFlags.NonPublic)
                    ?? throw new InvalidOperationException(
                        "Could not locate the dedicated worker field.");
                interrupter = new Thread(() =>
                {
                    var random = new Random();
                    while (DateTimeOffset.UtcNow < endTime)
                    {
                        Thread.Sleep(100);
                        if (random.Next(100) >= threadInterruptPercentage)
                            continue;

                        var worker = workerField.GetValue(dedicatedThreadRetriever) as Thread;
                        if (worker is null || !worker.IsAlive)
                            continue;

                        try
                        {
                            worker.Interrupt();
                            Interlocked.Increment(ref workerInterruptCount);
                        }
                        catch (ThreadStateException)
                        {
                        }
                    }
                })
                {
                    IsBackground = true,
                    Name = "DedicatedThreadHarness random worker interrupter",
                };
            }

            Func<Task<bool>> validateToken = async () =>
            {
                SigningSnapshot snapshot = signingState.GetSnapshot();
                // A request remains pending across the hard cutover. Failed validation triggers/coalesces
                // refresh work in the manager, and this loop observes when the new key becomes available.
                while (true)
                {
                    TokenValidationResult result =
                        handler.ValidateToken(snapshot.Token, validationParameters);
                    if (result.IsValid)
                    {
                        HarnessHelpers.UpdateMaximum(
                            ref highestValidatedGeneration,
                            snapshot.Generation);
                        return true;
                    }
                    Interlocked.Increment(ref validationRetryCount);
                    await Task.Delay(10).ConfigureAwait(false);
                }
            };

            Func<Task<bool>> validateTokenAsync = async () =>
            {
                SigningSnapshot snapshot = signingState.GetSnapshot();
                // Match the synchronous workload semantics: the request waits for recovery rather than
                // turning a transient stale-key result into an application-level failure.
                while (true)
                {
                    TokenValidationResult result = await handler
                        .ValidateTokenAsync(snapshot.Token, validationParameters)
                        .ConfigureAwait(false);
                    if (result.IsValid)
                    {
                        HarnessHelpers.UpdateMaximum(
                            ref highestValidatedGeneration,
                            snapshot.Generation);
                        return true;
                    }
                    Interlocked.Increment(ref validationRetryCount);
                    await Task.Delay(10).ConfigureAwait(false);
                }
            };

            Console.WriteLine(
                useProductionConfigurationManager
                    ? "Production ConfigurationManager signing-key rotation stress tests"
                    : "Dedicated thread signing-key rotation stress tests");
            Console.WriteLine(
                $"  Configuration retrieval  : {(useAsyncRetrieval ? "asynchronous" : "synchronous")}");
            Console.WriteLine(
                $"  Token validation         : {(useAsyncRetrieval ? "ValidateTokenAsync" : "ValidateToken")}");
            Console.WriteLine($"  Duration                 : {duration.TotalSeconds:N0} seconds");
            Console.WriteLine($"  Incoming request rate    : {requestRate:N0}/second");
            Console.WriteLine("  Signing key rotation     : random 5-15 seconds with immediate old-key invalidation");
            Console.WriteLine("  Retrieval delay          : 750 milliseconds");
            Console.WriteLine($"  Retrieval fault chance   : {retrievalFaultPercentage}%");
            Console.WriteLine("  Retrieval fault selection: 50% interrupted hang / 50% exception");
            if (!useProductionConfigurationManager)
            {
                Console.WriteLine(
                    $"  Worker interrupt chance  : {threadInterruptPercentage}% every 100 ms");
            }

            rotator.Start();
            interrupter?.Start();
            LoadResult loadResult = useAsyncRetrieval
                ? RunOpenLoopLoad(validateTokenAsync, duration, requestRate)
                : RunOpenLoopLoad(validateToken, duration, requestRate);
            rotator.Join();
            interrupter?.Join();
            bool retrievalIsIdle = configurationRetriever.WaitForIdle(TimeSpan.Zero);

            Console.WriteLine($"  Requests submitted       : {loadResult.Submitted:N0}");
            Console.WriteLine($"  Requests completed       : {loadResult.CompletedAfterObservation:N0}");
            Console.WriteLine($"  Remaining backlog        : {loadResult.RemainingAfterObservation:N0}");
            Console.WriteLine($"  Post-load completions    : {loadResult.PostLoadCompletions:N0}");
            Console.WriteLine($"  Request failures         : {loadResult.Failures:N0}");
            Console.WriteLine($"  Maximum queue depth      : {loadResult.MaximumQueueDepth:N0}");
            Console.WriteLine($"  Signing key rotations     : {rotationCount:N0}");
            Console.WriteLine($"  Current key generation    : {signingState.CurrentGeneration:N0}");
            Console.WriteLine($"  Highest config generation : {highestConfigurationGeneration:N0}");
            Console.WriteLine($"  Highest validated key     : {highestValidatedGeneration:N0}");
            Console.WriteLine($"  Validation retries        : {validationRetryCount:N0}");
            Console.WriteLine($"  Retrieval attempts        : {configurationRetriever.CallCount:N0}");
            Console.WriteLine($"  Successful retrievals     : {configurationRetriever.SuccessfulCallCount:N0}");
            Console.WriteLine($"  Interrupted hangs         : {configurationRetriever.HangCount:N0}");
            Console.WriteLine($"  Thrown exceptions         : {configurationRetriever.ThrowCount:N0}");
            Console.WriteLine($"  Retrieval idle at report  : {retrievalIsIdle}");
            if (!useProductionConfigurationManager)
                Console.WriteLine($"  Random worker interrupts  : {workerInterruptCount:N0}");
            if (loadResult.FirstException is not null)
                Console.WriteLine($"  First request exception   : {loadResult.FirstException}");

            // A saturated queue does not need to drain. It must continue completing work after submissions
            // stop, and validation must still recover to the newest key generation.
            bool latestConfigurationRetrieved =
                highestConfigurationGeneration == signingState.CurrentGeneration;
            bool latestKeyValidated =
                highestValidatedGeneration == signingState.CurrentGeneration;
            if (loadResult.Failures != 0 ||
                !loadResult.MadeProgressAfterLoad ||
                rotationCount == 0 ||
                !latestKeyValidated)
            {
                Console.Error.WriteLine("Stress variant failed:");
                if (loadResult.Failures != 0)
                {
                    Console.Error.WriteLine(
                        $"  - {loadResult.Failures:N0} validation work item(s) failed.");
                }

                if (!loadResult.MadeProgressAfterLoad)
                {
                    Console.Error.WriteLine(
                        "  - No queued validation completed during the five-second post-load " +
                        $"liveness window; {loadResult.RemainingAfterObservation:N0} remained.");
                }

                if (rotationCount == 0)
                    Console.Error.WriteLine("  - No signing-key rotation occurred.");

                if (!latestConfigurationRetrieved)
                {
                    Console.Error.WriteLine(
                        $"  - Configuration refresh reached generation " +
                        $"{highestConfigurationGeneration:N0}, but generation " +
                        $"{signingState.CurrentGeneration:N0} was current.");
                }
                else if (!latestKeyValidated)
                {
                    Console.Error.WriteLine(
                        $"  - Configuration generation {signingState.CurrentGeneration:N0} was " +
                        $"retrieved, but validation reached only generation " +
                        $"{highestValidatedGeneration:N0}.");
                }

                if (!retrievalIsIdle)
                    Console.Error.WriteLine("  - A configuration retrieval was still active at report time.");

                return 3;
            }

            return 0;
        }

        private static bool TryParseOptions(
            string[] args,
            bool useProductionConfigurationManager,
            out TimeSpan duration,
            out int requestRate,
            out int retrievalFaultPercentage,
            out int threadInterruptPercentage)
        {
            duration = TimeSpan.FromSeconds(60);
            requestRate = 1000;
            retrievalFaultPercentage = 10;
            threadInterruptPercentage = 10;

            if (args.Length == 0)
                return true;

            int maximumArgumentCount = useProductionConfigurationManager ? 3 : 4;
            if (args.Length < 1 ||
                args.Length > maximumArgumentCount ||
                !int.TryParse(args[0], out int durationSeconds) ||
                (args.Length >= 2 && !int.TryParse(args[1], out requestRate)) ||
                (args.Length >= 3 && !int.TryParse(args[2], out retrievalFaultPercentage)) ||
                (args.Length == 4 && !int.TryParse(args[3], out threadInterruptPercentage)) ||
                durationSeconds <= 0 ||
                requestRate <= 0 ||
                retrievalFaultPercentage is < 0 or > 100 ||
                threadInterruptPercentage is < 0 or > 100)
            {
                Console.Error.WriteLine(
                    $"Usage: {(useProductionConfigurationManager ? "--production-stress-tests" : "--stress-tests")} " +
                    "[duration-seconds [request-rate [retrieval-fault-percentage " +
                    (useProductionConfigurationManager
                        ? "]]"
                        : "[thread-interrupt-percentage]]]]"));
                return false;
            }

            duration = TimeSpan.FromSeconds(durationSeconds);
            return true;
        }

        private static LoadResult RunOpenLoopLoad(
            Func<Task<bool>> executeRequest,
            TimeSpan duration,
            int requestRate)
        {
            long startTimestamp = Stopwatch.GetTimestamp();
            long endTimestamp = startTimestamp + HarnessHelpers.ToStopwatchTicks(duration);
            var result = new LoadResult();

            // A dedicated producer preserves the requested arrival rate even when the ThreadPool is
            // saturated, making queue growth and continued post-load progress observable.
            var producer = new Thread(() =>
            {
                double requestIntervalTicks = (double)Stopwatch.Frequency / requestRate;
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

                    result.RecordSubmission();
                    ThreadPool.UnsafeQueueUserWorkItem(
                        static state => state.Execute(),
                        new ValidationWorkItem(
                            executeRequest,
                            result),
                        preferLocal: false);
                    nextRequestTimestamp += requestIntervalTicks;
                }
            })
            {
                IsBackground = true,
                Name = "DedicatedThreadHarness token validation producer",
            };

            producer.Start();
            producer.Join();

            long completedAtEndOfLoad = result.Completed;
            long observationEnd = Stopwatch.GetTimestamp() +
                HarnessHelpers.ToStopwatchTicks(TimeSpan.FromSeconds(5));
            while (result.Completed != result.Submitted &&
                Stopwatch.GetTimestamp() < observationEnd)
            {
                Thread.Sleep(100);
            }

            result.RecordPostLoadObservation(completedAtEndOfLoad);
            return result;
        }

        private sealed class ValidationWorkItem
        {
            private readonly Func<Task<bool>> _executeRequest;
            private readonly LoadResult _result;

            internal ValidationWorkItem(
                Func<Task<bool>> executeRequest,
                LoadResult result)
            {
                _executeRequest = executeRequest;
                _result = result;
            }

            internal void Execute()
            {
                _result.RecordStart();
                _ = ExecuteAsync();
            }

            private async Task ExecuteAsync()
            {
                try
                {
                    if (!await _executeRequest().ConfigureAwait(false))
                        _result.RecordFailure(null);
                }
                catch (Exception exception)
                {
                    _result.RecordFailure(exception);
                }
                finally
                {
                    _result.RecordCompletion();
                }
            }
        }

        private sealed class LoadResult
        {
            private long _completed;
            private long _failures;
            private Exception? _firstException;
            private int _maximumQueueDepth;
            private long _started;
            private long _submitted;
            private long _completedAfterObservation;
            private long _completedAtEndOfLoad;

            internal long Completed => Interlocked.Read(ref _completed);

            internal long CompletedAfterObservation =>
                Interlocked.Read(ref _completedAfterObservation);

            internal long Failures => Interlocked.Read(ref _failures);

            internal Exception? FirstException => _firstException;

            internal int MaximumQueueDepth => Volatile.Read(ref _maximumQueueDepth);

            internal bool MadeProgressAfterLoad =>
                CompletedAfterObservation == Submitted || PostLoadCompletions > 0;

            internal long PostLoadCompletions =>
                CompletedAfterObservation - Interlocked.Read(ref _completedAtEndOfLoad);

            internal long RemainingAfterObservation =>
                Submitted - CompletedAfterObservation;

            internal long Submitted => Interlocked.Read(ref _submitted);

            internal void RecordCompletion()
            {
                Interlocked.Increment(ref _completed);
            }

            internal void RecordFailure(Exception? exception)
            {
                if (exception is not null)
                    Interlocked.CompareExchange(ref _firstException, exception, null);

                Interlocked.Increment(ref _failures);
            }

            internal void RecordPostLoadObservation(long completedAtEndOfLoad)
            {
                Interlocked.Exchange(ref _completedAtEndOfLoad, completedAtEndOfLoad);
                Interlocked.Exchange(ref _completedAfterObservation, Completed);
            }

            internal void RecordStart()
            {
                Interlocked.Increment(ref _started);
            }

            internal void RecordSubmission()
            {
                long submitted = Interlocked.Increment(ref _submitted);
                long started = Interlocked.Read(ref _started);
                HarnessHelpers.UpdateMaximum(
                    ref _maximumQueueDepth,
                    checked((int)(submitted - started)));
            }
        }

        private readonly struct SigningSnapshot
        {
            internal SigningSnapshot(
                int generation,
                string token,
                SecurityKey signingKey)
            {
                Generation = generation;
                Token = token;
                SigningKey = signingKey;
            }

            internal int Generation { get; }

            internal SecurityKey SigningKey { get; }

            internal string Token { get; }
        }

        private sealed class RotatingSigningState
        {
            private readonly object _lock = new();
            private SigningSnapshot _snapshot;

            internal RotatingSigningState()
            {
                _snapshot = RotateCore(1);
            }

            internal int CurrentGeneration
            {
                get
                {
                    lock (_lock)
                        return _snapshot.Generation;
                }
            }

            internal SigningSnapshot GetSnapshot()
            {
                lock (_lock)
                    return _snapshot;
            }

            internal void Rotate()
            {
                lock (_lock)
                    _snapshot = RotateCore(_snapshot.Generation + 1);
            }

            private SigningSnapshot RotateCore(int generation)
            {
                var rsa = RSA.Create(2048);
                var key = new RsaSecurityKey(rsa)
                {
                    KeyId = $"DedicatedThreadHarnessKey-{generation}"
                };
                var credentials = new SigningCredentials(
                    key,
                    SecurityAlgorithms.RsaSha256,
                    SecurityAlgorithms.Sha256);
                var handler = new JsonWebTokenHandler();
                string token = handler.CreateToken(new SecurityTokenDescriptor
                {
                    Claims = HarnessHelpers.CreateClaims(Issuer, Audience),
                    SigningCredentials = credentials,
                });

                // Publishing only this key invalidates every prior generation immediately.
                return new SigningSnapshot(
                    generation,
                    token,
                    key);
            }
        }

        private sealed class RotatingConfiguration : OpenIdConnectConfiguration
        {
            internal int Generation { get; init; }
        }

        private sealed class FaultingConfigurationRetriever :
            IConfigurationRetriever<RotatingConfiguration>,
            IConfigurationRetrieverSync<RotatingConfiguration>
        {
            private readonly int _failurePercentage;
            private readonly ManualResetEventSlim _idle = new(true);
            private readonly RotatingSigningState _signingState;
            private int _activeRetrievals;
            private int _callCount;
            private int _faultsEnabled;
            private int _hangCount;
            private int _successfulCallCount;
            private int _throwCount;

            internal FaultingConfigurationRetriever(
                RotatingSigningState signingState,
                int failurePercentage)
            {
                _signingState = signingState;
                _failurePercentage = failurePercentage;
            }

            internal int CallCount => Volatile.Read(ref _callCount);

            internal int HangCount => Volatile.Read(ref _hangCount);

            internal int SuccessfulCallCount => Volatile.Read(ref _successfulCallCount);

            internal int ThrowCount => Volatile.Read(ref _throwCount);

            internal void EnableFaults()
            {
                Volatile.Write(ref _faultsEnabled, 1);
            }

            internal bool WaitForIdle(TimeSpan timeout)
            {
                return _idle.Wait(timeout);
            }

            public RotatingConfiguration GetConfigurationSync(
                string address,
                IDocumentRetrieverSync retriever,
                CancellationToken cancel)
            {
                BeginRetrieval();
                SigningSnapshot snapshot = _signingState.GetSnapshot();

                try
                {
                    RetrievalFault fault = GetRetrievalFault();
                    if (fault == RetrievalFault.Hang)
                        HangUntilInterrupted();
                    if (fault == RetrievalFault.Throw)
                    {
                        Interlocked.Increment(ref _throwCount);
                        throw new InvalidOperationException("Injected configuration retrieval failure.");
                    }

                    Thread.Sleep(750);
                    Interlocked.Increment(ref _successfulCallCount);
                    return CreateConfiguration(snapshot);
                }
                finally
                {
                    CompleteRetrieval();
                }
            }

            public async Task<RotatingConfiguration> GetConfigurationAsync(
                string address,
                IDocumentRetriever retriever,
                CancellationToken cancel)
            {
                BeginRetrieval();
                SigningSnapshot snapshot = _signingState.GetSnapshot();

                try
                {
                    RetrievalFault fault = GetRetrievalFault();
                    if (fault == RetrievalFault.Hang)
                        await HangUntilInterruptedAsync().ConfigureAwait(false);
                    if (fault == RetrievalFault.Throw)
                    {
                        Interlocked.Increment(ref _throwCount);
                        throw new InvalidOperationException("Injected configuration retrieval failure.");
                    }

                    await Task.Delay(750).ConfigureAwait(false);
                    Interlocked.Increment(ref _successfulCallCount);
                    return CreateConfiguration(snapshot);
                }
                finally
                {
                    CompleteRetrieval();
                }
            }

            private void BeginRetrieval()
            {
                if (Interlocked.Increment(ref _activeRetrievals) == 1)
                    _idle.Reset();

                Interlocked.Increment(ref _callCount);
            }

            private void CompleteRetrieval()
            {
                if (Interlocked.Decrement(ref _activeRetrievals) == 0)
                    _idle.Set();
            }

            private static RotatingConfiguration CreateConfiguration(SigningSnapshot snapshot)
            {
                var configuration = new RotatingConfiguration
                {
                    Generation = snapshot.Generation,
                    Issuer = Issuer,
                };
                configuration.SigningKeys.Add(snapshot.SigningKey);

                return configuration;
            }

            private RetrievalFault GetRetrievalFault()
            {
                if (Volatile.Read(ref _faultsEnabled) == 0 ||
                    Random.Shared.Next(100) >= _failurePercentage)
                {
                    return RetrievalFault.None;
                }

                return Random.Shared.Next(2) == 0
                    ? RetrievalFault.Hang
                    : RetrievalFault.Throw;
            }

            private void HangUntilInterrupted()
            {
                Interlocked.Increment(ref _hangCount);
                Thread retrievalThread = Thread.CurrentThread;
                // Bound the injected hang without cancellation so the sync path exercises interruption
                // and the retriever's worker-recovery logic.
                new Thread(() =>
                {
                    Thread.Sleep(100);
                    retrievalThread.Interrupt();
                })
                {
                    IsBackground = true,
                    Name = "DedicatedThreadHarness hung retrieval interrupter",
                }.Start();

                Thread.Sleep(Timeout.Infinite);
            }

            private async Task HangUntilInterruptedAsync()
            {
                Interlocked.Increment(ref _hangCount);
                // The async equivalent faults the pending retrieval with the same exception type without
                // blocking a worker while the failure is outstanding.
                var interruption = new TaskCompletionSource<bool>(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                new Thread(() =>
                {
                    Thread.Sleep(100);
                    interruption.TrySetException(new ThreadInterruptedException());
                })
                {
                    IsBackground = true,
                    Name = "DedicatedThreadHarness hung async retrieval interrupter",
                }.Start();

                await interruption.Task.ConfigureAwait(false);
            }

            private enum RetrievalFault
            {
                None,
                Hang,
                Throw,
            }
        }
    }
}
