// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    // Handler-level coverage for the #3455 logging contract on the SAML result-based pipeline: the string
    // entry point opens a drain scope and then calls the SecurityToken overload, which opens a second scope
    // on the same CallContext. With re-entrant scopes only the outermost drains, so a captured validator log
    // is emitted exactly once despite the nesting.
    [Collection("LogHelper.Logger Tests")]
    public class SamlSecurityTokenHandlerLoggingContractTests
    {
        [Fact]
        public async Task ValidateTokenAsync_StringEntryPoint_NestedScopes_EmitsCapturedLogExactlyOnce()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;

            try
            {
                var handler = new SamlSecurityTokenHandler();
                DateTime utcNow = DateTime.UtcNow;
                SecurityToken samlToken = handler.CreateToken(new SecurityTokenDescriptor
                {
                    Subject = Default.SamlClaimsIdentity,
                    Issuer = Default.Issuer,
                    Audience = Default.Audience,
                    SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                    IssuedAt = utcNow.AddHours(-1),
                    Expires = utcNow.AddHours(1),
                    NotBefore = utcNow.AddHours(-1),
                });
                string token = handler.WriteToken(samlToken);

                ValidationParameters validationParameters = ValidationUtils.CreateValidationParameters(
                    audiences: [Default.Audience],
                    issuers: [Default.Issuer],
                    signingKeys: [KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key]);
                var callContext = new CallContext();

                // Act - the string overload opens the outer drain scope and then calls the SecurityToken
                // overload, which opens a second scope on the SAME CallContext. Only the outermost scope drains.
                ValidationResult<ValidatedToken, ValidationError> validationResult =
                    await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, callContext, default);

                // Assert - the audience-match log (IDX10234) is captured once during validation and emitted
                // exactly once by the outermost scope, despite the nested string/SecurityToken scoping.
                Assert.True(validationResult.Succeeded);
                Assert.Equal(1, recorder.Messages.Count(m => m.Contains("IDX10234")));
                Assert.Empty(callContext.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        private sealed class RecordingLogger : IIdentityLogger
        {
            public List<string> Messages { get; } = new List<string>();

            public bool IsEnabled(EventLogLevel eventLogLevel) => true;

            public void Log(LogEntry entry) => Messages.Add(entry.Message);
        }
    }
}
