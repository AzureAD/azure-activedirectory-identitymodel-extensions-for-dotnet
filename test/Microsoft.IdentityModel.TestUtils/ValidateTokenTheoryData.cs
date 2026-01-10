// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
    public class ValidateTokenTheoryData : TheoryDataBase
    {
        public ValidateTokenTheoryData(string testId) : base(testId) { }

        public BaseConfiguration Configuration { get; internal set; }

        public bool DoNotScrubErrorMessages { get; set; }

        public ExpectedException ExpectedExceptionValidationParameters { get; set; } = ExpectedException.NoExceptionExpected;

        public bool IncludeInStackFrameCountTest { get; set; } = true;

        public JsonWebToken JwtToken { get; set; }

        public SecurityToken? SecurityToken { get; set; }

        /// <summary>
        /// The TokenValidation results for the exception vary between JWT and SAML tokens.
        /// This property is used to restrict the exception thrown for TVP validation errors.
        /// For the updated model using ValidationParameters, all tokens will provide the same exception for validation errors.
        /// </summary>
        public bool RelaxTVPException { get; set; } = false;

        public string? Token { get; set; } = string.Empty;

        internal TokenValidationParameters? TokenValidationParameters { get; set; }

        internal ITestingTokenHandler? TestingTokenHandler { get; set; }

        internal ValidationFailureType FailureType { get; set; } = ValidationFailureType.NullArgument;
        internal ValidationParameters? ValidationParameters { get; set; }
    }

    public class ValidateAlgorithmTheoryData : ValidateTokenTheoryData
    {
        public ValidateAlgorithmTheoryData(string testId) : base(testId) { }

        public string Algorithm { get; set; }

        public SecurityKey SecurityKey { get; set; }

        internal ValidationResult<string, AlgorithmValidationError> ValidationResult { get; set; }
    }

    public class ValidateAudienceTheoryData : ValidateTokenTheoryData
    {
        public ValidateAudienceTheoryData(string testId) : base(testId) { }

        public List<string> TokenAudiences { get; set; }

        public List<string> ValidAudiences { get; set; }

        internal ValidationResult<string, AudienceValidationError> ValidationResult { get; set; }
    }

    public class ValidateEncryptionTheoryData : ValidateTokenTheoryData
    {
        public ValidateEncryptionTheoryData(string testId) : base(testId) { }

        internal ValidationResult<string, ValidationError> ValidationResult { get; set; }
    }

    public class ValidateIssuerTheoryData : ValidateTokenTheoryData
    {
        public ValidateIssuerTheoryData(string testId) : base(testId) { }

        public string Issuer { get; set; }

        internal ValidationResult<ValidatedIssuer, IssuerValidationError> ValidationResult { get; set; }

        public string ValidIssuerToAdd { get; internal set; }
    }

    public class ValidateLifetimeTheoryData : ValidateTokenTheoryData
    {
        public ValidateLifetimeTheoryData(string testId) : base(testId) { }

        public DateTime? NotBefore { get; set; }

        public DateTime? Expires { get; set; }

        internal ValidationResult<ValidatedLifetime, LifetimeValidationError> ValidationResult { get; set; }
    }

    public class ValidateTokenReplayTheoryData : ValidateTokenTheoryData
    {
        public ValidateTokenReplayTheoryData(string testId) : base(testId) { }

        public DateTime? ExpirationTime { get; set; }

        public SecurityTokenHandler SecurityTokenHandler { get; set; }

        public SecurityKey SigningKey { get; set; }

        public TokenReplayValidator TokenReplayValidator { get; set; }

        internal ValidationResult<DateTime?, TokenReplayValidationError> ValidationResult { get; set; }

        public bool ValidateTokenReplay { get; set; }
    }

    public class ValidateSignatureTheoryData : ValidateTokenTheoryData
    {
        public ValidateSignatureTheoryData(string testId) : base(testId) { }

        internal ValidationResult<SecurityKey, ValidationError> ValidationResult { get; set; }
    }

    public class ValidateSigningKeyTheoryData : ValidateTokenTheoryData
    {
        public ValidateSigningKeyTheoryData(string testId) : base(testId) { }

        public SecurityKey SecurityKey { get; set; }

        internal ValidationResult<ValidatedSignatureKey, SignatureKeyValidationError> ValidationResult { get; set; }
    }
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
}
