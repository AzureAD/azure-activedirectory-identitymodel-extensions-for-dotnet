// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ValidateTokenAsyncTests*

    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class ValidateTokenAsyncTests
    {
        private CallContext _callContext;
        private JsonWebTokenHandler _jsonWebTokenHandler;
        private JwtSecurityTokenHandler _jwtSecurityTokenHandler;
        private SecurityTokenDescriptor _tokenDescriptor;
        private SecurityTokenDescriptor _tokenDescriptorExtendedClaims;
        private string _jws;
        private string _jwsExtendedClaims;
        private TokenValidationParameters _tokenValidationParameters;
        private TokenValidationParameters _invalidTokenValidationParameters;
        private ValidationParameters _validationParameters;
        private ValidationParameters _invalidValidationParameters;

        [GlobalSetup]
        public void Setup()
        {
            _tokenDescriptor = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.Claims,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _tokenDescriptorExtendedClaims = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.ClaimsExtendedExample,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _jsonWebTokenHandler = new JsonWebTokenHandler();
            _jws = _jsonWebTokenHandler.CreateToken(_tokenDescriptor);
            _jwsExtendedClaims = _jsonWebTokenHandler.CreateToken(_tokenDescriptorExtendedClaims);

            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            _jwtSecurityTokenHandler.SetDefaultTimesOnTokenCreation = false;

            _tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
            };

            _validationParameters = new ValidationParameters();
            _validationParameters.ValidAudiences.Add(BenchmarkUtils.Audience);
            _validationParameters.ValidIssuers.Add(BenchmarkUtils.Issuer);
            _validationParameters.SigningKeys.Add(BenchmarkUtils.SigningCredentialsRsaSha256.Key);

            _invalidTokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                ValidateIssuerSigningKey = true,
                ValidateTokenReplay = true,
                ValidateSignatureLast = true
            };

            _invalidValidationParameters = new ValidationParameters();
            _invalidValidationParameters.ValidAudiences.Add(BenchmarkUtils.Audience);
            _invalidValidationParameters.ValidIssuers.Add(BenchmarkUtils.Issuer);

            _callContext = new CallContext();
        }

        [BenchmarkCategory("ValidateTokenAsync_Success"), Benchmark]
        public async Task<TokenValidationResult> JwtSecurityTokenHandler_ValidateTokenAsync() => await _jwtSecurityTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);

        [BenchmarkCategory("ValidateTokenAsync_Success"), Benchmark(Baseline = true)]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsyncWithTVP() => await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);

        [BenchmarkCategory("ValidateTokenAsync_Success"), Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsyncWithTVPUsingModifiedClone()
        {
            var tokenValidationParameters = _tokenValidationParameters.Clone();
            tokenValidationParameters.ValidIssuer = "different-issuer";
            tokenValidationParameters.ValidAudience = "different-audience";
            tokenValidationParameters.ValidateLifetime = false;
            return await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, tokenValidationParameters).ConfigureAwait(false);
        }

        [BenchmarkCategory("ValidateTokenAsync_Success"), Benchmark]
        public async Task<bool> JsonWebTokenHandler_ValidateTokenAsyncWithVP()
        {
            // Because ValidationResult is an internal type, we cannot return it in the benchmark.
            // We return a boolean instead until the type is made public.
            ValidationResult<ValidatedToken, ValidationError> validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _validationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);
            return validationResult.Succeeded;
        }

        [BenchmarkCategory("ValidateTokenAsync_FailTwiceBeforeSuccess"), Benchmark(Baseline = true)]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsyncWithTVP_SucceedOnThirdAttempt()
        {
            TokenValidationResult result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);

            return result;
        }

        [BenchmarkCategory("ValidateTokenAsync_FailTwiceBeforeSuccess"), Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsyncWithTVPUsingClone_SucceedOnThirdAttempt()
        {
            TokenValidationResult result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone()).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone()).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters.Clone()).ConfigureAwait(false);

            return result;
        }

        [BenchmarkCategory("ValidateTokenAsync_FailTwiceBeforeSuccess"), Benchmark]
        public async Task<bool> JsonWebTokenHandler_ValidateTokenAsyncWithVP_SucceedOnThirdAttempt()
        {
            ValidationResult<ValidatedToken, ValidationError> validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidValidationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);
            validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidValidationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);
            validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _validationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);

            return validationResult.Succeeded;
        }

        [BenchmarkCategory("ValidateTokenAsync_FailFourTimesBeforeSuccess"), Benchmark(Baseline = true)]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsyncWithTVP_SucceedOnFifthAttempt()
        {
            TokenValidationResult result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);

            return result;
        }

        [BenchmarkCategory("ValidateTokenAsync_FailFourTimesBeforeSuccess"), Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsyncWithTVPUsingClone_SucceedOnFifthAttempt()
        {
            TokenValidationResult result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone()).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone()).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone()).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone()).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters.Clone()).ConfigureAwait(false);

            return result;
        }

        [BenchmarkCategory("ValidateTokenAsync_FailFourTimesBeforeSuccess"), Benchmark]
        public async Task<bool> JsonWebTokenHandler_ValidateTokenAsyncWithVP_SucceedOnFifthAttempt()
        {
            ValidationResult<ValidatedToken, ValidationError> validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidValidationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);
            validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidValidationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);
            validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidValidationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);
            validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidValidationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);
            validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _validationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);

            return validationResult.Succeeded;
        }

        [BenchmarkCategory("ValidateTokenAsyncClaimAccess"), Benchmark(Baseline = true)]
        public async Task<List<Claim>> JsonWebTokenHandler_ValidateTokenAsyncWithTVP_CreateClaims()
        {
            var result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);
            var claimsIdentity = result.ClaimsIdentity;
            var claims = claimsIdentity.Claims;
            return claims.ToList();
        }

        [BenchmarkCategory("ValidateTokenAsyncClaimAccess"), Benchmark]
        public async Task<List<Claim>> JsonWebTokenHandler_ValidateTokenAsyncWithVP_CreateClaims()
        {
            ValidationResult<ValidatedToken, ValidationError> validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _validationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);
            var claimsIdentity = validationResult.Result.ClaimsIdentity;
            var claims = claimsIdentity.Claims;
            return claims.ToList();
        }
    }

    // ===== Telemetry Impact Benchmarks =====
    // "Tracking" in this context refers to tracking signature validation for specific issuer hosts.
    // When enabled, telemetry collects data for the configured hosts (e.g., "contoso.com").
    // Every other host is reported as "other" to avoid excessive cardinality in telemetry.
    // These benchmarks measure the performance impact of enabling telemetry overall, and of tracking specific hosts.
    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class ValidateTokenAsyncTests_TelemetryImpact
    {
        private const int IterationCount = 10000;
        private JsonWebTokenHandler _jsonWebTokenHandler;
        private string _jwsClaims;
        private TokenValidationParameters _tokenValidationParameters;

        [GlobalSetup]
        public void GlobalSetup()
        {
            var tokenDescriptorClaims = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.Claims,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _jsonWebTokenHandler = new JsonWebTokenHandler();
            _jwsClaims = _jsonWebTokenHandler.CreateToken(tokenDescriptorClaims);

            _tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
            };
        }

        [IterationSetup(Target = nameof(JsonWebTokenHandler_ValidateTokenAsync_TelemetryDisabled))]
        public void Setup_TelemetryDisabled()
        {
            CryptoTelemetry.EnableSignatureValidationTelemetry(false, null);
        }

        [BenchmarkCategory("ValidateTokenAsync_TelemetryImpact"), Benchmark(Baseline = true, OperationsPerInvoke = IterationCount)]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsync_TelemetryDisabled()
        {
            return await _jsonWebTokenHandler.ValidateTokenAsync(_jwsClaims, _tokenValidationParameters).ConfigureAwait(false);
        }

        [IterationSetup(Target = nameof(JsonWebTokenHandler_ValidateTokenAsync_TelemetryEnabledNoTracking))]
        public void Setup_TelemetryEnabledNoTracking()
        {
            CryptoTelemetry.EnableSignatureValidationTelemetry(true, null);
        }

        [BenchmarkCategory("ValidateTokenAsync_TelemetryImpact"), Benchmark(OperationsPerInvoke = IterationCount)]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsync_TelemetryEnabledNoTracking()
        {
            return await _jsonWebTokenHandler.ValidateTokenAsync(_jwsClaims, _tokenValidationParameters).ConfigureAwait(false);
        }

        [IterationSetup(Target = nameof(JsonWebTokenHandler_ValidateTokenAsync_TelemetryEnabledWithTracking))]
        public void Setup_TelemetryEnabledWithTracking()
        {
            CryptoTelemetry.EnableSignatureValidationTelemetry(true, new[] { "contoso.com" });
        }

        [BenchmarkCategory("ValidateTokenAsync_TelemetryImpact"), Benchmark(OperationsPerInvoke = IterationCount)]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsync_TelemetryEnabledWithTracking()
        {
            return await _jsonWebTokenHandler.ValidateTokenAsync(_jwsClaims, _tokenValidationParameters).ConfigureAwait(false);
        }
    }

    // ===== Logging Impact Benchmarks (issue #3455) =====
    // Measures the cost of the result-based validation logging contract: validators capture structured
    // MessageDetail entries on the CallContext and the handler drains/emits them once, on completion.
    // "LoggingDisabled" is the dominant production path (LogHelper.IsEnabled(Informational) == false), where
    // the capture guards short-circuit so nothing is recorded, drained, or emitted. "LoggingEnabled" exercises
    // the full capture + drain + emit path against a no-op sink, isolating the library overhead from sink I/O.
    // The ClaimAccess pair additionally exercises the lazy IDX10245 emission during ClaimsIdentity creation.
    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class ValidateTokenAsyncTests_LoggingImpact
    {
        private JsonWebTokenHandler _jsonWebTokenHandler;
        private string _jwsExtendedClaims;
        private ValidationParameters _validationParameters;
        // Reused across iterations on purpose: the drain scope clears the buffer at the end of every
        // ValidateTokenAsync, and lazy claims creation uses its own dedicated CallContext, so no state
        // leaks between iterations.
        private CallContext _callContext;

        private static readonly IIdentityLogger s_enabledLogger = new NoOpLogger(isEnabled: true);
        private static readonly IIdentityLogger s_disabledLogger = new NoOpLogger(isEnabled: false);
        // Captured once at type initialization, before any GlobalSetup mutates the static logger, so
        // GlobalCleanup always restores the true original regardless of target ordering within a process.
        private static readonly IIdentityLogger s_originalLogger = LogHelper.Logger;

        private void CommonSetup()
        {
            var tokenDescriptorExtendedClaims = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.ClaimsExtendedExample,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _jsonWebTokenHandler = new JsonWebTokenHandler();
            _jwsExtendedClaims = _jsonWebTokenHandler.CreateToken(tokenDescriptorExtendedClaims);

            _validationParameters = new ValidationParameters();
            _validationParameters.ValidAudiences.Add(BenchmarkUtils.Audience);
            _validationParameters.ValidIssuers.Add(BenchmarkUtils.Issuer);
            _validationParameters.SigningKeys.Add(BenchmarkUtils.SigningCredentialsRsaSha256.Key);

            _callContext = new CallContext();
        }

        // Logger state is established in GlobalSetup (once per benchmark, outside the measured region) so the
        // measurement isolates the capture/drain/emit overhead and does not time the static logger assignment.
        [GlobalSetup(Target = nameof(JsonWebTokenHandler_ValidateTokenAsyncWithVP_LoggingDisabled))]
        public void SetupSuccessLoggingDisabled()
        {
            CommonSetup();
            LogHelper.Logger = s_disabledLogger;
        }

        [GlobalSetup(Target = nameof(JsonWebTokenHandler_ValidateTokenAsyncWithVP_LoggingEnabled))]
        public void SetupSuccessLoggingEnabled()
        {
            CommonSetup();
            LogHelper.Logger = s_enabledLogger;
        }

        [GlobalSetup(Target = nameof(JsonWebTokenHandler_ValidateTokenAsyncWithVP_CreateClaims_LoggingDisabled))]
        public void SetupClaimsLoggingDisabled()
        {
            CommonSetup();
            LogHelper.Logger = s_disabledLogger;
        }

        [GlobalSetup(Target = nameof(JsonWebTokenHandler_ValidateTokenAsyncWithVP_CreateClaims_LoggingEnabled))]
        public void SetupClaimsLoggingEnabled()
        {
            CommonSetup();
            LogHelper.Logger = s_enabledLogger;
        }

        [GlobalCleanup]
        public void Cleanup() => LogHelper.Logger = s_originalLogger;

        [BenchmarkCategory("LoggingImpact_Success"), Benchmark(Baseline = true)]
        public async Task<bool> JsonWebTokenHandler_ValidateTokenAsyncWithVP_LoggingDisabled()
        {
            ValidationResult<ValidatedToken, ValidationError> validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _validationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);
            return validationResult.Succeeded;
        }

        [BenchmarkCategory("LoggingImpact_Success"), Benchmark]
        public async Task<bool> JsonWebTokenHandler_ValidateTokenAsyncWithVP_LoggingEnabled()
        {
            ValidationResult<ValidatedToken, ValidationError> validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _validationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);
            return validationResult.Succeeded;
        }

        [BenchmarkCategory("LoggingImpact_ClaimAccess"), Benchmark(Baseline = true)]
        public async Task<List<Claim>> JsonWebTokenHandler_ValidateTokenAsyncWithVP_CreateClaims_LoggingDisabled()
        {
            ValidationResult<ValidatedToken, ValidationError> validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _validationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);
            return validationResult.Result.ClaimsIdentity.Claims.ToList();
        }

        [BenchmarkCategory("LoggingImpact_ClaimAccess"), Benchmark]
        public async Task<List<Claim>> JsonWebTokenHandler_ValidateTokenAsyncWithVP_CreateClaims_LoggingEnabled()
        {
            ValidationResult<ValidatedToken, ValidationError> validationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _validationParameters, _callContext, CancellationToken.None).ConfigureAwait(false);
            return validationResult.Result.ClaimsIdentity.Claims.ToList();
        }

        // A no-op IIdentityLogger used to toggle LogHelper.IsEnabled without incurring sink I/O cost,
        // so the benchmark isolates the capture/drain/emit overhead of the logging contract itself.
        private sealed class NoOpLogger : IIdentityLogger
        {
            private readonly bool _isEnabled;

            public NoOpLogger(bool isEnabled) => _isEnabled = isEnabled;

            public bool IsEnabled(EventLogLevel eventLogLevel) => _isEnabled;

            public void Log(LogEntry entry)
            {
            }
        }
    }
}
