// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Extensibility.Tests
{
    public class ExtensibilityTheoryData : TheoryDataBase
    {
        internal ExtensibilityTheoryData(
            string testId,
            TokenHandler tokenHandler,
            SecurityToken securityToken,
            IAlgorithmValidator algorithmValidator)
            : base(testId)
        {
            TokenHandler = tokenHandler;
            SecurityToken = securityToken;
            ValidationParameters.AlgorithmValidator = algorithmValidator;
            ValidationParameters.SigningKeys.Add(Default.SigningCredentials.Key);
            PropertiesToIgnoreWhenComparing.Add(typeof(CustomAlgorithmValidationError), new List<string> { "StackFramesCount" });
            PropertiesToIgnoreWhenComparing.Add(typeof(AlgorithmValidationError), new List<string> { "StackFramesCount" });
        }

        internal ExtensibilityTheoryData(
            string testId,
            TokenHandler tokenHandler,
            SecurityToken securityToken,
            IAudienceValidator audienceValidator)
            : base(testId)
        {
            TokenHandler = tokenHandler;
            SecurityToken = securityToken;
            ValidationParameters.AudienceValidator = audienceValidator;
            ValidationParameters.SigningKeys.Add(Default.SigningCredentials.Key);
            PropertiesToIgnoreWhenComparing.Add(typeof(CustomAudienceValidationError), new List<string> { "StackFramesCount" });
            PropertiesToIgnoreWhenComparing.Add(typeof(AudienceValidationError), new List<string> { "StackFramesCount" });
        }

        internal ExtensibilityTheoryData(
            string testId,
            TokenHandler tokenHandler,
            SecurityToken securityToken,
            IIssuerValidator issuerValidator)
    : base(testId)
        {
            TokenHandler = tokenHandler;
            SecurityToken = securityToken;
            ValidationParameters.IssuerValidatorAsync = issuerValidator;
            ValidationParameters.SigningKeys.Add(Default.SigningCredentials.Key);
            PropertiesToIgnoreWhenComparing.Add(typeof(CustomIssuerValidationError), new List<string> { "StackFramesCount" });
            PropertiesToIgnoreWhenComparing.Add(typeof(IssuerValidationError), new List<string> { "StackFramesCount" });
        }

        // TODO is there a IssuerSigningKeyResolver Error?
        internal ExtensibilityTheoryData(
            string testId,
            TokenHandler tokenHandler,
            SecurityToken securityToken,
            ISignatureKeyResolver signatureKeyResolver)
            : base(testId)
        {
            TokenHandler = tokenHandler;
            SecurityToken = securityToken;
            ValidationParameters.SignatureKeyResolver = signatureKeyResolver;
            ValidationParameters.SigningKeys.Add(Default.SigningCredentials.Key);
            PropertiesToIgnoreWhenComparing.Add(typeof(CustomIssuerSigningKeyValidationError), new List<string> { "StackFramesCount" });
            PropertiesToIgnoreWhenComparing.Add(typeof(SignatureKeyValidationError), new List<string> { "StackFramesCount" });
        }

        internal ExtensibilityTheoryData(
            string testId,
            TokenHandler tokenHandler,
            SecurityToken securityToken,
            ISignatureKeyValidator signatureKeyValidator)
            : base(testId)
        {
            TokenHandler = tokenHandler;
            SecurityToken = securityToken;
            ValidationParameters.SignatureKeyValidator = signatureKeyValidator;
            ValidationParameters.SigningKeys.Add(Default.SigningCredentials.Key);
            PropertiesToIgnoreWhenComparing.Add(typeof(CustomIssuerSigningKeyValidationError), new List<string> { "StackFramesCount" });
            PropertiesToIgnoreWhenComparing.Add(typeof(SignatureKeyValidationError), new List<string> { "StackFramesCount" });
        }

        internal ExtensibilityTheoryData(
            string testId,
            TokenHandler tokenHandler,
            SecurityToken securityToken,
            ILifetimeValidator lifetimeValidator)
            : base(testId)
        {
            TokenHandler = tokenHandler;
            SecurityToken = securityToken;
            ValidationParameters.LifetimeValidator = lifetimeValidator;
            ValidationParameters.SigningKeys.Add(Default.SigningCredentials.Key);
            PropertiesToIgnoreWhenComparing.Add(typeof(CustomLifetimeValidationError), new List<string> { "StackFramesCount" });
            PropertiesToIgnoreWhenComparing.Add(typeof(LifetimeValidationError), new List<string> { "StackFramesCount" });
        }

        internal ExtensibilityTheoryData(
            string testId,
            TokenHandler tokenHandler,
            SecurityToken securityToken,
            ISignatureValidator signatureValidator)
            : base(testId)
        {
            TokenHandler = tokenHandler;
            SecurityToken = securityToken;
            ValidationParameters.SignatureValidator = signatureValidator;
            ValidationParameters.SigningKeys.Add(Default.SigningCredentials.Key);
            PropertiesToIgnoreWhenComparing.Add(typeof(CustomSignatureValidationError), new List<string> { "StackFramesCount" });
            PropertiesToIgnoreWhenComparing.Add(typeof(SignatureValidationError), new List<string> { "StackFramesCount" });
        }

        internal ExtensibilityTheoryData(
            string testId,
            TokenHandler tokenHandler,
            SecurityToken securityToken,
            ITokenReplayValidator tokenReplayValidator)
            : base(testId)
        {
            TokenHandler = tokenHandler;
            SecurityToken = securityToken;
            ValidationParameters.TokenReplayValidator = tokenReplayValidator;
            ValidationParameters.SigningKeys.Add(Default.SigningCredentials.Key);
            PropertiesToIgnoreWhenComparing.Add(typeof(CustomTokenReplayValidationError), new List<string> { "StackFramesCount" });
            PropertiesToIgnoreWhenComparing.Add(typeof(TokenReplayValidationError), new List<string> { "StackFramesCount" });
        }

        internal ExtensibilityTheoryData(
            string testId,
            TokenHandler tokenHandler,
            SecurityToken securityToken,
            ITokenTypeValidator tokenTypeValidator)
            : base(testId)
        {
            TokenHandler = tokenHandler;
            SecurityToken = securityToken;
            ValidationParameters.TokenTypeValidator = tokenTypeValidator;
            ValidationParameters.SigningKeys.Add(Default.SigningCredentials.Key);
            PropertiesToIgnoreWhenComparing.Add(typeof(CustomTokenTypeValidationError), new List<string> { "StackFramesCount" });
            PropertiesToIgnoreWhenComparing.Add(typeof(TokenTypeValidationError), new List<string> { "StackFramesCount" });
        }

        public SecurityToken SecurityToken
        {
            get;
            set;
        }

        internal TokenHandler TokenHandler { get; }

        internal ValidationParameters ValidationParameters { get; } = new ValidationParameters
        {
            AlgorithmValidator = SkipValidationValidators.SkipAlgorithmValidation,
            AudienceValidator = SkipValidationValidators.SkipAudienceValidation,
            SignatureKeyValidator = SkipValidationValidators.SkipIssuerSigningKeyValidation,
            IssuerValidatorAsync = SkipValidationValidators.SkipIssuerValidation,
            LifetimeValidator = SkipValidationValidators.SkipLifetimeValidation,
            //SignatureValidator = SkipValidationValidators.SkipSignatureValidation,
            TokenReplayValidator = SkipValidationValidators.SkipTokenReplayValidation,
            TokenTypeValidator = SkipValidationValidators.SkipTokenTypeValidation
        };

        internal ValidationError? ValidationError { get; set; }

        internal ExpectedException? ExpectedInnerException { get; set; }
    }
}
#nullable restore
