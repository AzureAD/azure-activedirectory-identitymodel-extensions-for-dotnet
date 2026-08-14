// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;

namespace DedicatedThreadHarness
{
    internal sealed class HarnessOptions
    {
        internal TimeSpan RetrieverDelay { get; set; } = TimeSpan.FromMilliseconds(100);

        internal TimeSpan RefreshInterval { get; set; } = TimeSpan.FromSeconds(1);

        internal TimeSpan RunDuration { get; set; } = TimeSpan.FromSeconds(10);

        internal int RequestRate { get; set; } = 1000;

        internal bool BlockingRefresh { get; set; }

        internal bool UseAsyncValidation { get; set; }

        internal bool UseAsyncFetch { get; set; }

        internal bool UseThreadPoolRetriever { get; set; }

        internal int? ThreadPoolSize { get; set; }
    }

    internal static class HarnessHelpers
    {
        // Parses command-line arguments into strongly typed harness options.
        internal static bool TryParseOptions(string[] args, out HarnessOptions options, out string error)
        {
            options = new HarnessOptions();
            error = string.Empty;

            for (int i = 0; i < args.Length; i++)
            {
                string argument = args[i];
                switch (argument)
                {
                    case "--request-rate":
                        if (!TryReadPositiveInt(args, ref i, argument, out int requestRate, out error))
                            return false;
                        options.RequestRate = requestRate;
                        break;

                    case "--retriever-delay":
                    case "--refresh-interval":
                    case "--run-duration":
                        if (!TryReadDuration(args, ref i, argument, out TimeSpan duration, out error))
                            return false;

                        if (argument == "--retriever-delay")
                            options.RetrieverDelay = duration;
                        else if (argument == "--refresh-interval")
                            options.RefreshInterval = duration;
                        else
                            options.RunDuration = duration;
                        break;

                    case "--blocking-refresh":
                        options.BlockingRefresh = true;
                        break;

                    case "--async":
                        options.UseAsyncValidation = true;
                        break;

                    case "--async-fetch":
                        options.UseAsyncFetch = true;
                        break;

                    case "--threadpool-retriever":
                        options.UseThreadPoolRetriever = true;
                        break;

                    case "--threadpool-size":
                        if (!TryReadPositiveInt(args, ref i, argument, out int threadPoolSize, out error))
                            return false;
                        options.ThreadPoolSize = threadPoolSize;
                        break;

                    case "-h":
                    case "--help":
                        PrintUsage();
                        Environment.Exit(0);
                        break;

                    default:
                        error = $"Unknown argument '{argument}'.";
                        return false;
                }
            }

            if (options.UseAsyncFetch && options.UseThreadPoolRetriever)
            {
                error = "'--async-fetch' applies only to the dedicated-thread retriever and cannot be combined with '--threadpool-retriever'.";
                return false;
            }

            if (!options.UseThreadPoolRetriever && options.UseAsyncFetch != options.UseAsyncValidation)
            {
                error = "Dedicated-thread fetch and validation modes must match; specify both '--async' and '--async-fetch', or neither.";
                return false;
            }

            return true;
        }

        // Converts a duration into ticks from the high-resolution Stopwatch clock.
        internal static long ToStopwatchTicks(TimeSpan duration)
        {
            return checked((long)(duration.TotalSeconds * Stopwatch.Frequency));
        }

        internal static void UpdateMaximum(ref int maximum, int candidate)
        {
            int observed = Volatile.Read(ref maximum);
            while (candidate > observed)
            {
                int previous = Interlocked.CompareExchange(ref maximum, candidate, observed);
                if (previous == observed)
                    return;

                observed = previous;
            }
        }

        // Creates validation parameters that validate against and observe the manager's current configuration.
        internal static TokenValidationParameters CreateValidationParameters<T>(
            BaseConfigurationManager configurationManager,
            string audience,
            string expectedIssuer,
            Action<T> observeConfiguration) where T : BaseConfiguration
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidAudience = audience,
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                IssuerValidatorUsingConfiguration = (issuer, _, _, configuration) =>
                {
                    if (configuration is T typedConfiguration)
                        observeConfiguration(typedConfiguration);

                    if (!string.Equals(issuer, expectedIssuer, StringComparison.Ordinal))
                        throw new SecurityTokenInvalidIssuerException($"Unexpected issuer '{issuer}'.");

                    return issuer;
                },
            };

            if (configurationManager is BaseConfigurationManagerSync configurationManagerSync)
                validationParameters.ConfigurationManagerSync = configurationManagerSync;
            else
                validationParameters.ConfigurationManager = configurationManager;

            return validationParameters;
        }

        // Creates the RSA signing credentials shared by generated tokens and retrieved configurations.
        internal static SigningCredentials CreateSigningCredentials()
        {
            var rsa = RSA.Create(2048);
            var key = new RsaSecurityKey(rsa) { KeyId = "DedicatedThreadHarnessKey" };
            return new SigningCredentials(key, SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256);
        }

        // Creates claims for a reusable valid token with the requested issuer and audience.
        internal static Dictionary<string, object> CreateClaims(string issuer, string audience)
        {
            DateTime now = DateTime.UtcNow;
            return new Dictionary<string, object>
            {
                { JwtRegisteredClaimNames.Iss, issuer },
                { JwtRegisteredClaimNames.Aud, audience },
                { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(now) },
                { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(now) },
                { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(now + TimeSpan.FromDays(1)) },
                { JwtRegisteredClaimNames.Sub, "DedicatedThreadHarness" },
            };
        }

        // Formats a duration for concise command-line output.
        internal static string FormatDuration(TimeSpan duration)
        {
            if (duration.TotalMilliseconds < 1000)
                return $"{duration.TotalMilliseconds:N0} ms";
            if (duration.TotalSeconds < 60)
                return $"{duration.TotalSeconds:N1} s";
            return $"{duration.TotalMinutes:N1} m";
        }

        // Prints the supported harness command-line options.
        internal static void PrintUsage()
        {
            Console.WriteLine("Usage: dotnet run --project benchmark\\DedicatedThreadHarness -- [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --request-rate <n>             Requests queued per second (default 1000).");
            Console.WriteLine("  --retriever-delay <duration>  Synchronous metadata retrieval delay (default 100ms).");
            Console.WriteLine("  --refresh-interval <duration> Harness RequestRefresh cadence; manager throttling remains default (default 1s).");
            Console.WriteLine("  --run-duration <duration>     Load duration (default 10s).");
            Console.WriteLine("  --blocking-refresh            Enable Switch.Microsoft.IdentityModel.UpdateConfigAsBlocking.");
            Console.WriteLine("  --async                       Use JsonWebTokenHandler.ValidateTokenAsync for every request.");
            Console.WriteLine("  --async-fetch                 Make the DedicatedThreadRetriever call GetConfigurationAsync.");
            Console.WriteLine("  --threadpool-retriever        Use production ConfigurationManager and its ThreadPool refresh path.");
            Console.WriteLine("  --threadpool-size <n>         Cap the ThreadPool min/max worker threads (default: runtime self-sizes).");
            Console.WriteLine("  -h, --help                    Show this help.");
        }

        // Reads a positive integer following a named command-line argument.
        private static bool TryReadPositiveInt(
            string[] args,
            ref int index,
            string argument,
            out int value,
            out string error)
        {
            value = 0;
            if (++index >= args.Length ||
                !int.TryParse(args[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out value) ||
                value <= 0)
            {
                error = $"'{argument}' requires a positive integer.";
                return false;
            }

            error = string.Empty;
            return true;
        }

        // Reads a positive duration following a named command-line argument.
        private static bool TryReadDuration(
            string[] args,
            ref int index,
            string argument,
            out TimeSpan duration,
            out string error)
        {
            duration = TimeSpan.Zero;
            if (++index >= args.Length || !TryParseDuration(args[index], out duration) || duration <= TimeSpan.Zero)
            {
                error = $"'{argument}' requires a positive duration such as 5ms, 2s, or 1m.";
                return false;
            }

            error = string.Empty;
            return true;
        }

        // Parses milliseconds, seconds, or minutes from a command-line value.
        private static bool TryParseDuration(string value, out TimeSpan duration)
        {
            duration = TimeSpan.Zero;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            value = value.Trim();
            (string Suffix, Func<double, TimeSpan> Factory)[] units =
            {
                ("ms", TimeSpan.FromMilliseconds),
                ("s", TimeSpan.FromSeconds),
                ("m", TimeSpan.FromMinutes),
            };

            foreach ((string suffix, Func<double, TimeSpan> factory) in units)
            {
                if (!value.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    continue;

                string number = value.Substring(0, value.Length - suffix.Length);
                if (!double.TryParse(number, NumberStyles.Float, CultureInfo.InvariantCulture, out double parsed))
                    return false;

                duration = factory(parsed);
                return true;
            }

            if (!double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out double milliseconds))
                return false;

            duration = TimeSpan.FromMilliseconds(milliseconds);
            return true;
        }
    }

    internal sealed class HarnessDocumentRetriever : IDocumentRetriever, IDocumentRetrieverSync
    {
        public Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            return Task.FromResult("{}");
        }

        public string GetDocument(string address, CancellationToken cancel)
        {
            return "{}";
        }
    }

}
