// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Logging.Tests
{
    public class LoggerImpl : ILogger
    {
        public class LogEntry
        {
            public LogLevel LogLevel { get; set; }

            public EventId EventId { get; set; }

            public object State { get; set; }

            public Exception Exception { get; set; }
        }

        private List<LogEntry> _logEntries = new List<LogEntry>();

        public LoggerImpl(LogLevel logLevel)
        {
            LogLevel = logLevel;
        }

        public LogLevel LogLevel { get; } = LogLevel.Information;

        public IDisposable BeginScope<TState>(TState state) => throw new NotImplementedException();

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception exception,
            Func<TState, Exception, string> formatter)
        {
            if (!IsEnabled(logLevel))
                return;

            _logEntries.Add(new LogEntry { LogLevel = logLevel, EventId = eventId, State = state, Exception = exception });
        }

        public IList<LogEntry> GetLogEntries()
        {
            return _logEntries.AsReadOnly();
        }
    }

    public class ILoggerTests
    {
        /// <summary>
        /// Test that the LogHelper.IsEnabled method returns false when Ilogger is null.
        /// </summary>
        [Fact]
        public void ReturnsFalse_WhenLoggerContextIsNull()
        {
            Assert.False(LogHelper.IsEnabled(LogLevel.Information, null));
        }

        /// <summary>
        /// Tests that the new LoggerConext throws when passed null to ctor.
        /// </summary>
        [Fact]
        public void ThrowsWhenILoggerNull()
        {
            Assert.Throws<ArgumentNullException>(() => new LoggerContext((ILogger)null));
        }

        /// <summary>
        /// Tests that the LogHelper.LogExceptionMessage method logs exceptions at the correct log levels.
        /// </summary>
        /// <param name="logLevel">level to set ILogger.</param>
        /// <param name="shouldLogInfo">should we be expecting logs.</param>
        [Theory]
        [InlineData(LogLevel.Trace, true)]
        [InlineData(LogLevel.Debug, true)]
        [InlineData(LogLevel.Information, true)]
        [InlineData(LogLevel.Warning, true)]
        [InlineData(LogLevel.Error, true)]
        [InlineData(LogLevel.Critical, false)]
        [InlineData(LogLevel.None, false)]
        public void LogExceptions_Levels(LogLevel logLevel, bool shouldLogInfo)
        {
            LoggerImpl logger = new LoggerImpl(logLevel);
            string correlationId = Guid.NewGuid().ToString();
            LogHelper.LogExceptionMessage(new Exception("Exception"), new LoggerContext(logger) { CorrelationId = correlationId });

            Assert.True(logger.GetLogEntries().Count == (shouldLogInfo ? 1 : 0));
            if (shouldLogInfo)
                Assert.Contains(correlationId, logger.GetLogEntries()[0].State.ToString());
        }

        /// <summary>
        /// Tests that the LogHelper.LogInformation method logs information messages at the correct log levels.
        /// </summary>
        /// <param name="logLevel">level to set ILogger.</param>
        /// <param name="shouldLogInfo">should we be expecting logs.</param>
        [Theory]
        [InlineData(LogLevel.Trace, true)]
        [InlineData(LogLevel.Debug, true)]
        [InlineData(LogLevel.Information, true)]
        [InlineData(LogLevel.Warning, false)]
        [InlineData(LogLevel.Error, false)]
        [InlineData(LogLevel.Critical, false)]
        [InlineData(LogLevel.None, false)]
        public void LogInformation_Levels(LogLevel logLevel, bool shouldLogInfo)
        {
            string correlationId = Guid.NewGuid().ToString();
            LoggerImpl logger = new LoggerImpl(logLevel);
            LogHelper.LogInformation("Information", new LoggerContext(logger) { CorrelationId = correlationId });

            Assert.True(logger.GetLogEntries().Count == (shouldLogInfo ? 1 : 0));
            if (shouldLogInfo)
                Assert.Contains(correlationId, logger.GetLogEntries()[0].State.ToString());
        }

        /// <summary>
        /// Tests that the LogHelper.LogVerbose method logs verbose messages at the correct log levels.
        /// </summary>
        /// <param name="logLevel">level to set ILogger.</param>
        /// <param name="shouldLogInfo">should we be expecting logs.</param>
        [Theory]
        [InlineData(LogLevel.Trace, true)]
        [InlineData(LogLevel.Debug, true)]
        [InlineData(LogLevel.Information, false)]
        [InlineData(LogLevel.Warning, false)]
        [InlineData(LogLevel.Error, false)]
        [InlineData(LogLevel.Critical, false)]
        [InlineData(LogLevel.None, false)]
        public void LogVerbose_Levels(LogLevel logLevel, bool shouldLogInfo)
        {
            string correlationId = Guid.NewGuid().ToString();
            LoggerImpl logger = new LoggerImpl(logLevel);
            LogHelper.LogVerbose("Verbose", new LoggerContext(logger) { CorrelationId = correlationId });

            Assert.True(logger.GetLogEntries().Count == (shouldLogInfo ? 1 : 0));
            if (shouldLogInfo)
                Assert.Contains(correlationId, logger.GetLogEntries()[0].State.ToString());
        }

        /// <summary>
        /// Tests that the LogHelper.LogWarning method logs warnings at the correct log levels.
        /// </summary>
        /// <param name="logLevel">level to set ILogger.</param>
        /// <param name="shouldLogInfo">should we be expecting logs.</param>
        [Theory]
        [InlineData(LogLevel.Trace, true)]
        [InlineData(LogLevel.Debug, true)]
        [InlineData(LogLevel.Information, true)]
        [InlineData(LogLevel.Warning, true)]
        [InlineData(LogLevel.Error, false)]
        [InlineData(LogLevel.Critical, false)]
        [InlineData(LogLevel.None, false)]
        public void LogWarnings_Levels(LogLevel logLevel, bool shouldLogInfo)
        {
            string correlationId = Guid.NewGuid().ToString();
            LoggerImpl logger = new LoggerImpl(logLevel);
            LogHelper.LogWarning("Warning", new LoggerContext(logger) { CorrelationId = correlationId });

            Assert.True(logger.GetLogEntries().Count == (shouldLogInfo ? 1 : 0));
            if (shouldLogInfo)
                Assert.Contains(correlationId, logger.GetLogEntries()[0].State.ToString());
        }

        /// <summary>
        /// Tests that the ActivityId and CorrelationId are logged correctly when logging warnings.
        /// </summary>
        /// <param name="useActivityId"> whether to use an ActivityId.</param>
        /// <param name="useCorrelationId"> whether to use a CorrelationId.</param>
        [Theory]
        [InlineData(true, true)]
        [InlineData(true, false)]
        public void ActivityCorrelationIds(bool useActivityId, bool useCorrelationId)
        {
            string correlationId = useCorrelationId ? Guid.NewGuid().ToString() : null;
            Guid activityId = useActivityId ? Guid.NewGuid() : Guid.Empty;
            LoggerImpl logger = new LoggerImpl(LogLevel.Warning);
            CallContext callContext = new CallContext(logger) { CorrelationId = correlationId, ActivityId = activityId };
            LogHelper.LogWarning("Warning", callContext);

            if (useCorrelationId)
                Assert.Contains(correlationId, logger.GetLogEntries()[0].State.ToString(), StringComparison.InvariantCulture);

            // CorrelationId overrides ActivityId
            if (useActivityId && !useCorrelationId)
                Assert.Contains(activityId.ToString(), logger.GetLogEntries()[0].State.ToString(), StringComparison.InvariantCulture);
        }

        /// <summary>
        /// Tests related to validating a JSON Web Token (JWT) that are not specific to validation stings like audience, issuer, lifetime, etc.
        /// </summary>
        [Theory, MemberData(nameof(ValidateJsonWebTokenAsyncTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateJsonWebTokenAsync(ValidateTokenTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync", theoryData);
            theoryData.ValidationParameters.InstancePropertyBag[TokenValidationParametersExtensions.s_callContextKey] = theoryData.CallContext;
            TokenValidationResult result =
                await theoryData.Handler.ValidateTokenAsync(theoryData.SecurityToken, theoryData.ValidationParameters);

            TestUtilities.AssertFailIfErrors(context);

            Assert.True(theoryData.Logger.GetLogEntries().Count > 0, "Expected log entries.");
            if (theoryData.LogValues.Count > 0)
            {
                int logCount = 0;
                foreach (string logValue in theoryData.LogValues)
                {
                    foreach (var logEntry in theoryData.Logger.GetLogEntries())
                    {
                        if (logEntry.State.ToString().Contains(logValue))
                            logCount++;
                    }
                }

                Assert.True(logCount == theoryData.LogValues.Count,
                    $"Expected log values count: '{theoryData.LogValues.Count}' to match actual count '{logCount}'.");
            }
        }

        public static TheoryData<ValidateTokenTheoryData> ValidateJsonWebTokenAsyncTestCases
        {
            get
            {
                TheoryData<ValidateTokenTheoryData> theoryData = new TheoryData<ValidateTokenTheoryData>();
                JsonWebTokenHandler handler = new JsonWebTokenHandler();
                LoggerImpl logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("TokenIsNotJsonWebToken")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "TokenIsNotJsonWebToken" },
                        SecurityToken = new DerivedSecurityToken(),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters()
                    }
                );

                return theoryData;
            }
        }

        /// <summary>
        /// Tests related to validating the audience of a JWT.
        /// </summary>
        [Theory, MemberData(nameof(ValidateJwtAudienceTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateJwtAudienceAsync(ValidateTokenTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync", theoryData);
            theoryData.ValidationParameters.InstancePropertyBag[TokenValidationParametersExtensions.s_callContextKey] = theoryData.CallContext;
            TokenValidationResult result =
                await theoryData.Handler.ValidateTokenAsync(theoryData.SecurityToken, theoryData.ValidationParameters);

            TestUtilities.AssertFailIfErrors(context);

            if (theoryData.LogValues.Count > 0)
            {
                Assert.True(theoryData.Logger.GetLogEntries().Count > 0, "Expected log entries.");

                int logCount = 0;
                foreach (string logValue in theoryData.LogValues)
                {
                    foreach (var logEntry in theoryData.Logger.GetLogEntries())
                    {
                        if (logEntry.State.ToString().Contains(logValue))
                            logCount++;
                    }
                }

                Assert.True(logCount == theoryData.LogValues.Count,
                    $"Expected log values count: '{theoryData.LogValues.Count}' to match actual count '{logCount}'.");
            }
        }

        public static TheoryData<ValidateTokenTheoryData> ValidateJwtAudienceTestCases
        {
            get
            {
                TheoryData<ValidateTokenTheoryData> theoryData = new TheoryData<ValidateTokenTheoryData>();
                JsonWebTokenHandler handler = new JsonWebTokenHandler();
                LoggerImpl logger = new LoggerImpl(LogLevel.Warning);

                SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    Issuer = Default.Issuer,
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Subject = new CaseSensitiveClaimsIdentity(ClaimSets.DefaultClaims)
                };

                string jwt = handler.CreateToken(securityTokenDescriptor);
                logger = new LoggerImpl(LogLevel.Warning);

                // Valid audience (success)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("ValidAudience")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "ValidAudience" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // No audience in token (failure)
                logger = new LoggerImpl(LogLevel.Warning);
                var noAudienceDescriptor = new SecurityTokenDescriptor
                {
                    Issuer = Default.Issuer,
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Subject = new CaseSensitiveClaimsIdentity(ClaimSets.DefaultClaims)
                };
                string jwtNoAudience = handler.CreateToken(noAudienceDescriptor);
                theoryData.Add(
                    new ValidateTokenTheoryData("NoAudienceInToken", new List<string> { "IDX10206:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "NoAudienceInToken" },
                        SecurityToken = new JsonWebToken(jwtNoAudience),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // RequireAudience = false and no audience (skipped)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("NoAudience_RequireAudienceFalse", new List<string> { "IDX10277:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "NoAudience_RequireAudienceFalse" },
                        SecurityToken = new JsonWebToken(jwtNoAudience),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                            RequireAudience = false
                        }
                    }
                );

                // RequireAudience = true and no audience
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(


                    new ValidateTokenTheoryData("NoAudience_RequireAudienceTrue", new List<string> { "IDX10206:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "NoAudience_RequireAudienceTrue" },
                        SecurityToken = new JsonWebToken(jwtNoAudience),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // ValidAudience and ValidAudiences both null (failure)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("NoValidAudienceOrAudiences", new List<string> { "IDX10208:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "NoValidAudienceOrAudiences" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = null,
                            ValidAudiences = null,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // Custom AudienceValidator (skipped, always returns true)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("CustomAudienceValidator_True")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "CustomAudienceValidator_True" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            AudienceValidator = (audiences, token, parameters) => true,
                            ValidAudience = "notused",
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // Custom AudienceValidator (skipped, always returns false)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("CustomAudienceValidator_False", new List<string> { { "IDX10231:" } })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "CustomAudienceValidator_False" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            AudienceValidator = (audiences, token, parameters) => false,
                            ValidAudience = "notused",
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                theoryData.Add(
                    new ValidateTokenTheoryData("DoNotValidateAudience", new List<string> { "IDX10233:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "DoNotValidateAudience" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Guid.NewGuid().ToString(),
                            ValidateAudience = false,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }

                    }
                );

                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData(
                        "DoNotValidateAudienceAndIssuer",
                        new List<string>
                        {
                            $"IDX10235",
                            $"IDX10233"
                        })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "DoNotValidateAudienceAndIssuer" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Guid.NewGuid().ToString(),
                            ValidIssuer = Guid.NewGuid().ToString(),
                            ValidateAudience = false,
                            ValidateIssuer = false,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }

                    }
                );

                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("InvalidAudience")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "InvalidAudience" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Guid.NewGuid().ToString(),
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                return theoryData;
            }
        }

        /// <summary>
        /// Tests related to validating the issuer of a JWT.
        /// </summary>
        [Theory, MemberData(nameof(ValidateJwtIssuerTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateJwtIssuerAsync(ValidateTokenTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidateJwtIssuerAsync", theoryData);
            theoryData.ValidationParameters.InstancePropertyBag[TokenValidationParametersExtensions.s_callContextKey] = theoryData.CallContext;
            TokenValidationResult result =
                await theoryData.Handler.ValidateTokenAsync(theoryData.SecurityToken, theoryData.ValidationParameters);

            if (theoryData.LogValues.Count > 0)
            {
                Assert.True(theoryData.Logger.GetLogEntries().Count > 0, "Expected log entries.");

                int logCount = 0;
                foreach (string logValue in theoryData.LogValues)
                {
                    foreach (var logEntry in theoryData.Logger.GetLogEntries())
                    {
                        if (logEntry.State.ToString().Contains(logValue))
                            logCount++;
                    }
                }

                Assert.True(logCount == theoryData.LogValues.Count,
                    $"Expected log values count: '{theoryData.LogValues.Count}' to match actual count '{logCount}'.");
            }
        }

        public static TheoryData<ValidateTokenTheoryData> ValidateJwtIssuerTestCases
        {
            get
            {
                TheoryData<ValidateTokenTheoryData> theoryData = new TheoryData<ValidateTokenTheoryData>();
                JsonWebTokenHandler handler = new JsonWebTokenHandler();
                LoggerImpl logger = new LoggerImpl(LogLevel.Warning);

                SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    Issuer = Default.Issuer,
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Subject = new CaseSensitiveClaimsIdentity(ClaimSets.DefaultClaims)
                };

                string jwt = handler.CreateToken(securityTokenDescriptor);
                logger = new LoggerImpl(LogLevel.Warning);

                theoryData.Add(
                    new ValidateTokenTheoryData("DoNotValidateIssuer", new List<string> { "IDX10235:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "DoNotValidateIssuer" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidateIssuer = false,
                            ValidIssuer = Guid.NewGuid().ToString(),
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }

                    }
                );

                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("InvalidIssuer")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "InvalidIssuer" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Guid.NewGuid().ToString(),
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // Valid issuer (success)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("ValidIssuer")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "ValidIssuer" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // Null/whitespace issuer (failure)
                logger = new LoggerImpl(LogLevel.Warning);
                var noIssuerDescriptor = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Subject = new CaseSensitiveClaimsIdentity(ClaimSets.DefaultClaims)
                };
                string jwtNoIssuer = handler.CreateToken(noIssuerDescriptor);
                theoryData.Add(
                    new ValidateTokenTheoryData("NullIssuer", new List<string> { "IDX10211:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "NullIssuer" },
                        SecurityToken = new JsonWebToken(jwtNoIssuer),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // ValidIssuer, ValidIssuers, configuration.Issuer all null/empty (failure)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("NoValidIssuerOrIssuers", new List<string> { "IDX10204:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "NoValidIssuerOrIssuers" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = null,
                            ValidIssuers = null,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // Issuer matches configuration.Issuer (success)
                logger = new LoggerImpl(LogLevel.Warning);
                var config = new OpenIdConnectConfiguration { Issuer = Default.Issuer };
                theoryData.Add(
                    new ValidateTokenTheoryData("IssuerMatchesConfiguration")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "IssuerMatchesConfiguration" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        Configuration = config,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = "not-the-issuer",
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // Issuer matches one of ValidIssuers (success)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("IssuerMatchesValidIssuers")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "IssuerMatchesValidIssuers" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = "not-the-issuer",
                            ValidIssuers = new[] { "foo", Default.Issuer, "bar" },
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // Custom IssuerValidator (success)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("CustomIssuerValidator_True")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "CustomIssuerValidator_True" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            IssuerValidator = (issuer, token, parameters) => issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // Custom IssuerValidator (failure)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("CustomIssuerValidator_False", new List<string> { "IDX10205:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "CustomIssuerValidator_False" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            IssuerValidator = (issuer, token, parameters) =>
                                throw new SecurityTokenInvalidIssuerException(
                                    LogHelper.FormatInvariant(
                                        Tokens.LogMessages.IDX10205,
                                        Default.Issuer,
                                        "Issuers",
                                        "Issuer",
                                        "CurrentConfiguration.Issuer")),
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // Custom IssuerValidatorAsync (success)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("CustomIssuerValidatorAsync_True")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "CustomIssuerValidatorAsync_True" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            IssuerValidatorAsync = (issuer, token, parameters) => new ValueTask<string>(issuer),
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // Custom IssuerValidatorAsync (failure)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("CustomIssuerValidatorAsync_False", new List<string> { "IDX10205:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "CustomIssuerValidatorAsync_False" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            IssuerValidatorAsync = (issuer, token, parameters) =>
                                throw new SecurityTokenInvalidIssuerException(
                                    LogHelper.FormatInvariant(
                                        Tokens.LogMessages.IDX10205,
                                        Default.Issuer,
                                        "Issuers",
                                        "Issuer",
                                        "CurrentConfiguration.Issuer")),
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // Custom IssuerValidatorUsingConfiguration (success)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("CustomIssuerValidatorUsingConfiguration_True")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "CustomIssuerValidatorUsingConfiguration_True" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        Configuration = config,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            IssuerValidatorUsingConfiguration = (issuer, token, parameters, conf) => issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // Custom IssuerValidatorUsingConfiguration (failure)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("CustomIssuerValidatorUsingConfiguration_False", new List<string> { "IDX10205:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "CustomIssuerValidatorUsingConfiguration_False" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        Configuration = config,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            IssuerValidatorUsingConfiguration = (issuer, token, parameters, conf) =>
                                throw new SecurityTokenInvalidIssuerException(
                                    LogHelper.FormatInvariant(
                                        Tokens.LogMessages.IDX10205,
                                        Default.Issuer,
                                        "Issuers",
                                        "Issuer",
                                        "CurrentConfiguration.Issuer")),
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                return theoryData;
            }
        }

        /// <summary>
        /// Tests related to validating the lifetime of a JWT.
        /// </summary>
        [Theory, MemberData(nameof(ValidateJwtLifetimeTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateJwtLifetimeAsync(ValidateTokenTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidateJwtLifetimeAsync", theoryData);
            theoryData.ValidationParameters.InstancePropertyBag[TokenValidationParametersExtensions.s_callContextKey] = theoryData.CallContext;
            TokenValidationResult result =
                await theoryData.Handler.ValidateTokenAsync(theoryData.SecurityToken, theoryData.ValidationParameters);

            int logCount = 0;

            if (theoryData.LogValues.Count > 0)
            {
                Assert.True(theoryData.Logger.GetLogEntries().Count > 0, "Expected log entries.");

                foreach (string logValue in theoryData.LogValues)
                {
                    foreach (var logEntry in theoryData.Logger.GetLogEntries())
                    {
                        if (logEntry.State.ToString().Contains(logValue))
                            logCount++;
                    }
                }
            }

            Assert.True(logCount == theoryData.LogValues.Count,
                $"Expected log values count: '{theoryData.LogValues.Count}' to match actual count '{logCount}'.");
        }

        public static TheoryData<ValidateTokenTheoryData> ValidateJwtLifetimeTestCases
        {
            get
            {
                TheoryData<ValidateTokenTheoryData> theoryData = new TheoryData<ValidateTokenTheoryData>();
                JsonWebTokenHandler handler = new JsonWebTokenHandler() { SetDefaultTimesOnTokenCreation = false };
                LoggerImpl logger = new LoggerImpl(LogLevel.Warning);
                SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    Issuer = Default.Issuer,
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Subject = new CaseSensitiveClaimsIdentity(ClaimSets.DefaultClaims),
                    Expires = DateTime.UtcNow.AddDays(-5),
                    NotBefore = DateTime.UtcNow.AddDays(-10)
                };

                string jwt = handler.CreateToken(securityTokenDescriptor);
                theoryData.Add(
                    new ValidateTokenTheoryData("ExpiredToken", new List<string> { { "IDX10223:" } })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "ExpiredToken" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Guid.NewGuid().ToString(),
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    Issuer = Default.Issuer,
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Subject = new CaseSensitiveClaimsIdentity(ClaimSets.DefaultClaims),
                    Expires = DateTime.UtcNow.AddDays(1)
                };

                jwt = handler.CreateToken(securityTokenDescriptor);
                logger = new LoggerImpl(LogLevel.Warning);

                theoryData.Add(
                    new ValidateTokenTheoryData("ValidLifetime")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "ValidLifetime" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    });

                // Not yet valid token
                securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    Issuer = Default.Issuer,
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Subject = new CaseSensitiveClaimsIdentity(ClaimSets.DefaultClaims),
                    NotBefore = DateTime.UtcNow.AddMinutes(10),
                    Expires = DateTime.UtcNow.AddMinutes(60)
                };

                jwt = handler.CreateToken(securityTokenDescriptor);
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("NotYetValidToken", new List<string> { "IDX10222:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "NotYetValidToken" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // NotBefore > Expires
                securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    Issuer = Default.Issuer,
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Subject = new CaseSensitiveClaimsIdentity(ClaimSets.DefaultClaims),
                    NotBefore = DateTime.UtcNow.AddMinutes(10),
                    Expires = DateTime.UtcNow.AddMinutes(5)
                };

                jwt = handler.CreateToken(securityTokenDescriptor);
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("NotBeforeAfterExpires", new List<string> { "IDX10224:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "NotBeforeAfterExpires" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                        }
                    }
                );

                // No expiration, RequireExpirationTime = true (should fail)
                securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    Issuer = Default.Issuer,
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Subject = new CaseSensitiveClaimsIdentity(ClaimSets.DefaultClaims),
                };

                jwt = handler.CreateToken(securityTokenDescriptor);
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("NoExpiration_RequireExpirationTimeTrue", new List<string> { "IDX10225:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "NoExpiration_RequireExpirationTimeTrue" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                            RequireExpirationTime = true
                        }
                    }
                );

                // No expiration, RequireExpirationTime = false (should succeed)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("NoExpiration_RequireExpirationTimeFalse", new List<string> { "IDX10238:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "NoExpiration_RequireExpirationTimeFalse" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                            ValidateLifetime = false
                        }
                    }
                );

                // ValidateLifetime = false (should skip validation)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("ValidateLifetimeFalse", new List<string> { "IDX10238:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "ValidateLifetimeFalse" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                            ValidateLifetime = false
                        }
                    }
                );

                // Custom LifetimeValidator returns true (should succeed)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("CustomLifetimeValidator_True")
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "CustomLifetimeValidator_True" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                            LifetimeValidator = (notBefore, expires, token, parameters) => true
                        }
                    }
                );

                // Custom LifetimeValidator returns false (should fail)
                logger = new LoggerImpl(LogLevel.Warning);
                theoryData.Add(
                    new ValidateTokenTheoryData("CustomLifetimeValidator_False", new List<string> { "IDX10230:" })
                    {
                        Logger = logger,
                        CallContext = new CallContext(logger) { DebugId = "CustomLifetimeValidator_False" },
                        SecurityToken = new JsonWebToken(jwt),
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                            LifetimeValidator = (notBefore, expires, token, parameters) => false
                        }
                    }
                );

                return theoryData;
            }
        }

        public class ValidateTokenTheoryData : TheoryDataBase
        {
            public ValidateTokenTheoryData(string testId) : base(testId) { }
            public ValidateTokenTheoryData(string testId, IList<string> logValues) : base(testId)
            {
                LogValues = logValues;
            }
            public BaseConfiguration Configuration { get; set; }
            public JsonWebTokenHandler Handler { get; set; } = new JsonWebTokenHandler();
            public LoggerImpl Logger { get; set; } = new LoggerImpl(LogLevel.Warning);
            public IList<string> LogValues { get; } = new List<string>();
            public SecurityToken SecurityToken { get; set; }
            public SigningCredentials SigningCredentials { get; set; }
            public TokenValidationParameters ValidationParameters { get; set; }
        }
    }
}
