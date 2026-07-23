// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.ValidateTokenThroughput
{
    /// <summary>
    /// A standalone throughput harness that compares the experimental synchronous
    /// <c>JsonWebTokenHandler.ValidateToken</c> and asynchronous <c>JsonWebTokenHandler.ValidateTokenAsync</c>
    /// code paths under high concurrent load.
    ///
    /// Each validation attaches an unmodified, real <see cref="ConfigurationManager{OpenIdConnectConfiguration}"/> so
    /// its caching and last-known-good behavior are exercised exactly as in production; only the metadata retriever is
    /// swapped for <see cref="MockConfigurationRetriever"/>, which returns a fixed <see cref="OpenIdConnectConfiguration"/>
    /// after a simulated delay. The ConfigurationManager caches the result so all subsequent requests should pull
    /// straight from the cache. Load is modeled as a bounded in-flight open loop: the harness keeps up to
    /// <see cref="ConcurrentOperations"/> (100) discrete requests outstanding at once, each dispatched as its own
    /// thread-pool work item (mimicking independent requests arriving concurrently), and submits a new one whenever one
    /// completes. This lets the thread pool decide real parallelism - synchronous requests hold their pool thread for
    /// their whole duration, while asynchronous requests release it whenever they await I/O (e.g. a metadata refresh),
    /// so more can be in flight than there are threads. Each run lasts a fixed wall-clock window (default 10 seconds)
    /// and records how many requests completed and how many times the retriever was actually invoked. A retriever count
    /// of exactly one confirms the config fetch happens only once and that there are no races around the cache under load.
    ///
    /// CLI options:
    ///   dotnet run -c Release benchmark\Microsoft.IdentityModel.ValidateTokenThroughput
    ///      --retriever-delay <duration>: How long we want our simulated HTTP Fetch to take (default 5 ms)
    ///      --refresh-interval <duration>: How long between RequestRefresh() calls (default 12h (no refresh), but minimum is 1s due to constants set in <see cref="BaseConfigurationManager">)
    ///      --run-duration <duration>: How long each (sync then async) run executes (default 10s)
    ///      --concurrency <n>: Max requests kept in flight at once, dispatched to the thread pool (default 100)
    ///      --blocking: sets <see cref="AppContextSwitches.UpdateConfigAsBlocking"/> to true (default: false)
    ///      --starvation: Cap the thread pool to starve the in-flight requests (default: off, pool self-sizes)
    ///      --sync / --async: Run only the sync or only the async path (default: run both)
    /// </summary>
    internal static class Program
    {
        /// <summary>Default number of requests kept in flight concurrently to simulate load.</summary>
        private const int ConcurrentOperations = 100;

        /// <summary>
        /// The number of worker threads the thread pool is capped to under <c>--starvation</c>. Set to half the default
        /// in-flight concurrency so requests contend for fewer worker threads than there are outstanding requests.
        /// </summary>
        private const int StarvedThreadCount = ConcurrentOperations / 2;

        /// <summary>The default wall-clock duration each throughput run executes for.</summary>
        private static readonly TimeSpan ThroughputRunDuration = TimeSpan.FromSeconds(10);

        /// <summary>Default retriever delay (the first, uncached metadata retrieval and every refresh pay this cost).</summary>
        private static readonly TimeSpan DefaultRetrieverDelay = TimeSpan.FromMilliseconds(5);

        /// <summary>Default time until a cached configuration is treated as expired (the library's built-in 12 hours; no refresh is driven at this value).</summary>
        private static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromHours(12);

        /// <summary>
        /// The floor applied to the requested refresh interval. <see cref="ConfigurationManager{T}.RequestRefresh"/> is
        /// throttled by <see cref="BaseConfigurationManager.RefreshInterval"/>, whose library minimum is one second, so a
        /// refresh can be triggered at most once per second. With a one-second interval a 10s run sees roughly nine refreshes.
        /// </summary>
        private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromSeconds(1);

        /// <summary>The AppContext switch that makes configuration refreshes block all threads until they complete.</summary>
        private const string UpdateConfigAsBlockingSwitch = "Switch.Microsoft.IdentityModel.UpdateConfigAsBlocking";

        private const string Issuer = "http://www.contoso.com";
        private const string Audience = "http://www.contoso.com/protected";
        private const string MetadataAddress = "https://www.contoso.com/.well-known/openid-configuration";

        private static async Task<int> Main(string[] args)
        {
            if (!TryParseOptions(args, out Options options, out string parseError))
            {
                Console.Error.WriteLine(parseError);
                Console.Error.WriteLine();
                PrintUsage();
                return 1;
            }

            // The AppContext switch is read (and cached) by the library on first use, so it must be set before any
            // configuration is requested. Setting it here makes every refresh block all threads until it finishes.
            AppContext.SetSwitch(UpdateConfigAsBlockingSwitch, options.Blocking);

            // Simulate thread-pool starvation (default on): cap the pool to half the attempted concurrency so the
            // asynchronous path (Task.Run based) contends for fewer worker threads than in-flight operations. When
            // disabled via --no-starvation the pool is left at its default (ample) size.
            if (options.Starvation)
            {
                ThreadPool.GetMinThreads(out _, out int minCompletion);
                ThreadPool.GetMaxThreads(out _, out int maxCompletion);
                ThreadPool.SetMaxThreads(StarvedThreadCount, maxCompletion);
                ThreadPool.SetMinThreads(StarvedThreadCount, minCompletion);
            }

            SigningCredentials signingCredentials = CreateSigningCredentials();
            var handler = new JsonWebTokenHandler();
            string jws = handler.CreateToken(new SecurityTokenDescriptor
            {
                Claims = CreateClaims(),
                SigningCredentials = signingCredentials,
            });
            var callContext = new CallContext();

            // Map the requested config-expiry to the ConfigurationManager's RefreshInterval, which throttles
            // RequestRefresh(). Floor it at the library minimum (1 second) so a refresh fires at most once per second.
            // Refreshes are only driven when the caller explicitly asks for them (i.e. overrides the 12h default).
            bool refreshRequested = options.RefreshInterval != DefaultRefreshInterval;
            TimeSpan effectiveRefreshInterval = options.RefreshInterval < MinimumRefreshInterval ? MinimumRefreshInterval : options.RefreshInterval;
            TimeSpan runDuration = options.RunDuration;

            // Both the sync and async runs use a bounded in-flight, open-loop load model: keep up to `concurrency`
            // discrete requests outstanding at once, each dispatched as its own thread-pool work item (mimicking
            // independent requests arriving concurrently). As each completes another is submitted. The thread pool then
            // decides real parallelism: sync requests block their pool thread for their whole duration, while async
            // requests release the thread whenever they await I/O (e.g. a metadata refresh), so more can be in flight
            // than there are threads.
            int concurrency = options.Concurrency;

            Console.WriteLine("ValidateToken throughput harness");
            Console.WriteLine($"  Runtime              : {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
            Console.WriteLine($"  ConfigurationManager : ConfigurationManager<OpenIdConnectConfiguration> (mocked retriever)");
            Console.WriteLine($"  Logical processors   : {Environment.ProcessorCount}");
            Console.WriteLine($"  Load model           : bounded in-flight \u2014 up to {concurrency} concurrent requests dispatched to the thread pool");
            Console.WriteLine($"  Thread pool          : {(options.Starvation ? $"capped to {StarvedThreadCount} worker threads (starvation)" : "default (self-sizing)")}");
            Console.WriteLine($"  Run duration         : {FormatDuration(runDuration)}");
            Console.WriteLine($"  Retriever delay      : {FormatDuration(options.RetrieverDelay)} (paid on first retrieval and every refresh)");
            if (refreshRequested)
            {
                string floored = effectiveRefreshInterval != options.RefreshInterval ? $" (requested {FormatDuration(options.RefreshInterval)}, floored to the 1s minimum)" : string.Empty;
                Console.WriteLine($"  Refresh interval     : {FormatDuration(effectiveRefreshInterval)}{floored} \u2014 RequestRefresh() is called every op and throttled to this interval");
            }
            else
            {
                Console.WriteLine($"  Refresh interval     : {FormatDuration(options.RefreshInterval)} (default; no refresh driven)");
            }

            Console.WriteLine($"  Refresh mode         : {(options.Blocking ? "blocking (refreshes block all threads)" : "non-blocking (stale config served while refreshing)")}");
            string pathsLabel = options.RunSyncPath && options.RunAsyncPath ? "sync and async"
                : options.RunSyncPath ? "sync only" : "async only";
            Console.WriteLine($"  Paths                : {pathsLabel}");
            Console.WriteLine();

            if (options.RunAsyncPath)
            {
                ThroughputResult asyncResult = await RunAsync(handler, jws, callContext, signingCredentials.Key, options, effectiveRefreshInterval, refreshRequested, runDuration, concurrency).ConfigureAwait(false);
                PrintResult("ValidateTokenAsync (async)", asyncResult);
            }

            if (options.RunSyncPath)
            {
                ThroughputResult syncResult = RunSync(handler, jws, callContext, signingCredentials.Key, options, effectiveRefreshInterval, refreshRequested, runDuration, concurrency);
                PrintResult("ValidateToken (sync)", syncResult);
            }

            return 0;
        }

        private static ThroughputResult RunSync(JsonWebTokenHandler handler, string jws, CallContext callContext, SecurityKey signingKey, Options options, TimeSpan refreshInterval, bool refreshRequested, TimeSpan runDuration, int maxConcurrency)
        {
            var retriever = new MockConfigurationRetriever(CreateOpenIdConnectConfiguration(signingKey), options.RetrieverDelay);
            ConfigurationManager<OpenIdConnectConfiguration> configurationManager = CreateConfigurationManager(retriever, refreshInterval);
            ValidationParameters validationParameters = CreateValidationParameters(signingKey, configurationManager);

            long completedOperations = 0;
            long succeededOperations = 0;

            // Bounded in-flight open loop: keep up to maxConcurrency discrete requests outstanding, each dispatched as
            // its own thread-pool work item (an independent request arriving at the server). The dispatch loop runs on
            // this (non-pool) calling thread, blocking on the semaphore until a slot frees, so it never competes with the
            // requests for a pool thread. Each request is handled synchronously and holds its pool thread until it ends.
            using var inFlight = new SemaphoreSlim(maxConcurrency, maxConcurrency);
            var stopwatch = Stopwatch.StartNew();

            while (stopwatch.Elapsed < runDuration)
            {
                inFlight.Wait();
                if (stopwatch.Elapsed >= runDuration)
                {
                    inFlight.Release();
                    break;
                }

                _ = Task.Run(() =>
                {
                    try
                    {
                        // Ask for a refresh every request; the ConfigurationManager throttles it to RefreshInterval.
                        if (refreshRequested)
                            configurationManager.RequestRefresh();

                        ValidationResult<ValidatedToken, ValidationError> result =
                            handler.ValidateToken(jws, validationParameters, callContext, CancellationToken.None);

                        Interlocked.Increment(ref completedOperations);
                        if (result.Succeeded)
                            Interlocked.Increment(ref succeededOperations);
                    }
                    finally
                    {
                        inFlight.Release();
                    }
                });
            }

            // Drain: re-acquire every slot so the run only ends once all outstanding requests have completed.
            for (int i = 0; i < maxConcurrency; i++)
                inFlight.Wait();

            stopwatch.Stop();

            return new ThroughputResult(
                stopwatch.Elapsed,
                completedOperations,
                succeededOperations,
                retriever.RetrievalCount);
        }

        private static async Task<ThroughputResult> RunAsync(JsonWebTokenHandler handler, string jws, CallContext callContext, SecurityKey signingKey, Options options, TimeSpan refreshInterval, bool refreshRequested, TimeSpan runDuration, int maxConcurrency)
        {
            var retriever = new MockConfigurationRetriever(CreateOpenIdConnectConfiguration(signingKey), options.RetrieverDelay);
            ConfigurationManager<OpenIdConnectConfiguration> configurationManager = CreateConfigurationManager(retriever, refreshInterval);
            ValidationParameters validationParameters = CreateValidationParameters(signingKey, configurationManager);

            long completedOperations = 0;
            long succeededOperations = 0;

            // Same bounded in-flight model as RunSync, but each request is an async operation. When a request awaits real
            // I/O (a metadata refresh's Task.Delay) it releases its pool thread, so more requests can be in flight than
            // there are threads - the key behavioral difference from the synchronous path under the same thread budget.
            using var inFlight = new SemaphoreSlim(maxConcurrency, maxConcurrency);
            var stopwatch = Stopwatch.StartNew();

            while (stopwatch.Elapsed < runDuration)
            {
                await inFlight.WaitAsync().ConfigureAwait(false);
                if (stopwatch.Elapsed >= runDuration)
                {
                    inFlight.Release();
                    break;
                }

                _ = Task.Run(async () =>
                {
                    try
                    {
                        // Ask for a refresh every request; the ConfigurationManager throttles it to RefreshInterval.
                        if (refreshRequested)
                            configurationManager.RequestRefresh();

                        ValidationResult<ValidatedToken, ValidationError> result =
                            await handler.ValidateTokenAsync(jws, validationParameters, callContext, CancellationToken.None)
                                .ConfigureAwait(false);

                        Interlocked.Increment(ref completedOperations);
                        if (result.Succeeded)
                            Interlocked.Increment(ref succeededOperations);
                    }
                    finally
                    {
                        inFlight.Release();
                    }
                });
            }

            // Drain: re-acquire every slot so the run only ends once all outstanding requests have completed.
            for (int i = 0; i < maxConcurrency; i++)
                await inFlight.WaitAsync().ConfigureAwait(false);

            stopwatch.Stop();

            return new ThroughputResult(
                stopwatch.Elapsed,
                completedOperations,
                succeededOperations,
                retriever.RetrievalCount);
        }

        private static ConfigurationManager<OpenIdConnectConfiguration> CreateConfigurationManager(
            MockConfigurationRetriever retriever,
            TimeSpan refreshInterval)
        {
            // RefreshInterval throttles RequestRefresh(); AutomaticRefreshInterval is left at its default since refreshes
            // are driven manually. The manager is otherwise the real, unmodified one so its caching and LKG behavior apply.
            return new ConfigurationManager<OpenIdConnectConfiguration>(
                MetadataAddress,
                retriever,
                new NullDocumentRetriever())
            {
                RefreshInterval = refreshInterval,
            };
        }

        private static ValidationParameters CreateValidationParameters(SecurityKey signingKey, BaseConfigurationManager configurationManager)
        {
            var validationParameters = new ValidationParameters();
            validationParameters.ValidAudiences.Add(Audience);
            validationParameters.ValidIssuers.Add(Issuer);
            validationParameters.SigningKeys.Add(signingKey);
            validationParameters.ConfigurationManager = configurationManager;
            return validationParameters;
        }

        private static OpenIdConnectConfiguration CreateOpenIdConnectConfiguration(SecurityKey signingKey)
        {
            var configuration = new OpenIdConnectConfiguration { Issuer = Issuer };
            configuration.SigningKeys.Add(signingKey);
            return configuration;
        }

        private static SigningCredentials CreateSigningCredentials()
        {
            var rsa = RSA.Create(2048);
            var key = new RsaSecurityKey(rsa) { KeyId = "RsaThroughputKey" };
            return new SigningCredentials(key, SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256);
        }

        private static Dictionary<string, object> CreateClaims()
        {
            DateTime now = DateTime.UtcNow;
            return new Dictionary<string, object>
            {
                { JwtRegisteredClaimNames.Email, "Bob@contoso.com" },
                { JwtRegisteredClaimNames.GivenName, "Bob" },
                { JwtRegisteredClaimNames.Iss, Issuer },
                { JwtRegisteredClaimNames.Aud, Audience },
                { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(now) },
                { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(now) },
                { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(now + TimeSpan.FromDays(1)) },
            };
        }

        private static void PrintResult(string label, ThroughputResult result)
        {
            double seconds = result.Elapsed.TotalSeconds;
            double opsPerSecond = seconds > 0 ? result.CompletedOperations / seconds : 0;

            Console.WriteLine(label);
            Console.WriteLine($"  Elapsed                       : {seconds:F3} s");
            Console.WriteLine($"  Operations completed          : {result.CompletedOperations:N0}");
            Console.WriteLine($"  Operations succeeded          : {result.SucceededOperations:N0}");
            Console.WriteLine($"  Retriever calls               : {result.ConfigurationRetrievals:N0} (1 initial + {Math.Max(0, result.ConfigurationRetrievals - 1):N0} refresh)");
            Console.WriteLine($"  Throughput                    : {opsPerSecond:N0} ops/s");
            Console.WriteLine();
        }

        /// <summary>Captures the measurements of a single throughput run.</summary>
        private readonly struct ThroughputResult
        {
            public ThroughputResult(
                TimeSpan elapsed,
                long completedOperations,
                long succeededOperations,
                long configurationRetrievals)
            {
                Elapsed = elapsed;
                CompletedOperations = completedOperations;
                SucceededOperations = succeededOperations;
                ConfigurationRetrievals = configurationRetrievals;
            }

            public TimeSpan Elapsed { get; }

            public long CompletedOperations { get; }

            public long SucceededOperations { get; }

            public long ConfigurationRetrievals { get; }
        }

        /// <summary>Runtime-configurable options parsed from the command line.</summary>
        private sealed class Options
        {
            public TimeSpan RetrieverDelay { get; set; } = DefaultRetrieverDelay;

            public TimeSpan RefreshInterval { get; set; } = DefaultRefreshInterval;

            public TimeSpan RunDuration { get; set; } = ThroughputRunDuration;

            public int Concurrency { get; set; } = ConcurrentOperations;

            public bool Starvation { get; set; }

            public bool Blocking { get; set; }

            /// <summary>Whether the <c>--sync</c> flag was supplied to run only the synchronous path.</summary>
            public bool SyncSelected { get; set; }

            /// <summary>Whether the <c>--async</c> flag was supplied to run only the asynchronous path.</summary>
            public bool AsyncSelected { get; set; }

            /// <summary>Whether to run the synchronous path. Runs when explicitly selected, or when neither path is selected (default: both).</summary>
            public bool RunSyncPath => SyncSelected || !AsyncSelected;

            /// <summary>Whether to run the asynchronous path. Runs when explicitly selected, or when neither path is selected (default: both).</summary>
            public bool RunAsyncPath => AsyncSelected || !SyncSelected;
        }

        private static bool TryParseOptions(string[] args, out Options options, out string error)
        {
            options = new Options();
            error = string.Empty;

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                switch (arg)
                {
                    case "--retriever-delay":
                    case "--refresh-interval":
                    case "--run-duration":
                        if (i + 1 >= args.Length)
                        {
                            error = $"Missing value for '{arg}'.";
                            return false;
                        }

                        string value = args[++i];
                        if (!TryParseDuration(value, out TimeSpan duration))
                        {
                            error = $"Invalid duration '{value}' for '{arg}'. Use e.g. 5ms, 250ms, 2s, 30s, 5m, 12h.";
                            return false;
                        }

                        if (duration <= TimeSpan.Zero)
                        {
                            error = $"Value for '{arg}' must be greater than zero.";
                            return false;
                        }

                        if (arg == "--retriever-delay")
                            options.RetrieverDelay = duration;
                        else if (arg == "--refresh-interval")
                            options.RefreshInterval = duration;
                        else
                            options.RunDuration = duration;
                        break;

                    case "--blocking":
                        options.Blocking = true;
                        break;

                    case "--concurrency":
                        if (i + 1 >= args.Length)
                        {
                            error = $"Missing value for '{arg}'.";
                            return false;
                        }

                        string concurrencyValue = args[++i];
                        if (!int.TryParse(concurrencyValue, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out int concurrency) || concurrency <= 0)
                        {
                            error = $"Invalid value '{concurrencyValue}' for '{arg}'. Provide a positive integer.";
                            return false;
                        }

                        options.Concurrency = concurrency;
                        break;

                    case "--starvation":
                        options.Starvation = true;
                        break;

                    case "--no-starvation":
                        options.Starvation = false;
                        break;

                    case "--sync":
                        options.SyncSelected = true;
                        break;

                    case "--async":
                        options.AsyncSelected = true;
                        break;

                    case "-h":
                    case "--help":
                        PrintUsage();
                        Environment.Exit(0);
                        break;

                    default:
                        error = $"Unknown argument '{arg}'.";
                        return false;
                }
            }

            return true;
        }

        /// <summary>Parses a duration with an optional ms/s/m/h suffix (a bare number is interpreted as milliseconds).</summary>
        private static bool TryParseDuration(string value, out TimeSpan duration)
        {
            duration = TimeSpan.Zero;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            value = value.Trim();
            (string suffix, Func<double, TimeSpan> factory)[] units =
            {
                ("ms", TimeSpan.FromMilliseconds),
                ("s", TimeSpan.FromSeconds),
                ("m", TimeSpan.FromMinutes),
                ("h", TimeSpan.FromHours),
            };

            foreach ((string suffix, Func<double, TimeSpan> factory) in units)
            {
                if (value.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                {
                    string number = value.Substring(0, value.Length - suffix.Length);
                    if (double.TryParse(number, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double parsed))
                    {
                        duration = factory(parsed);
                        return true;
                    }

                    return false;
                }
            }

            if (double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double bare))
            {
                duration = TimeSpan.FromMilliseconds(bare);
                return true;
            }

            return false;
        }

        private static string FormatDuration(TimeSpan duration)
        {
            if (duration.TotalMilliseconds < 1000)
                return $"{duration.TotalMilliseconds:N0} ms";
            if (duration.TotalSeconds < 60)
                return $"{duration.TotalSeconds:N0} s";
            if (duration.TotalMinutes < 60)
                return $"{duration.TotalMinutes:N0} m";
            return $"{duration.TotalHours:N0} h";
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage: dotnet run -- [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --retriever-delay <duration>   Time the retriever takes to return config (default 5ms).");
            Console.WriteLine("  --refresh-interval <duration>  Refresh throttle: how often RequestRefresh() may actually refresh");
            Console.WriteLine("                                 (default 12h = no refresh; floored at 1s, i.e. at most once per second).");
            Console.WriteLine("  --run-duration <duration>      How long each (sync then async) run executes (default 10s).");
            Console.WriteLine($"  --concurrency <n>              Max requests kept in flight at once, dispatched to the thread pool (default {ConcurrentOperations}).");
            Console.WriteLine($"  --starvation                   Cap the thread pool to {StarvedThreadCount} worker threads to starve the in-flight requests (default: off, pool self-sizes).");
            Console.WriteLine("  --blocking                     Refresh in blocking mode: every refresh blocks all threads until it finishes.");
            Console.WriteLine("  --sync                         Run only the synchronous path (default: run both sync and async).");
            Console.WriteLine("  --async                        Run only the asynchronous path (default: run both sync and async).");
            Console.WriteLine("  -h, --help                     Show this help.");
            Console.WriteLine();
            Console.WriteLine("Durations accept an ms/s/m/h suffix (a bare number is milliseconds), e.g. 5ms, 2s, 30s, 5m, 12h.");
        }

        /// <summary>
        /// An <see cref="IConfigurationRetriever{OpenIdConnectConfiguration}"/> that ignores the metadata endpoint and
        /// returns a fixed configuration after a simulated delay, counting how many actual retrievals were performed.
        /// </summary>
        private sealed class MockConfigurationRetriever : IConfigurationRetriever<OpenIdConnectConfiguration>, IConfigurationRetrieverSync<OpenIdConnectConfiguration>
        {
            private readonly OpenIdConnectConfiguration _configuration;
            private readonly TimeSpan _delay;
            private long _retrievalCount;

            public MockConfigurationRetriever(OpenIdConnectConfiguration configuration, TimeSpan delay)
            {
                _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
                _delay = delay;
            }

            /// <summary>Gets the number of times the (mocked) metadata endpoint was actually retrieved.</summary>
            public long RetrievalCount => Interlocked.Read(ref _retrievalCount);

            public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
            {
                Interlocked.Increment(ref _retrievalCount);
                if (_delay > TimeSpan.Zero)
                    await Task.Delay(_delay, cancel).ConfigureAwait(false);

                return _configuration;
            }

            public OpenIdConnectConfiguration GetConfigurationSync(string address, IDocumentRetriever retriever, CancellationToken cancel)
            {
                Interlocked.Increment(ref _retrievalCount);
                if (_delay > TimeSpan.Zero)
                    Thread.Sleep(_delay);

                return _configuration;
            }
        }

        /// <summary>An <see cref="IDocumentRetriever"/> stand-in; the mock retriever never actually reads a document.</summary>
        private sealed class NullDocumentRetriever : IDocumentRetriever
        {
            public Task<string> GetDocumentAsync(string address, CancellationToken cancel) => Task.FromResult(string.Empty);
        }
    }
}
