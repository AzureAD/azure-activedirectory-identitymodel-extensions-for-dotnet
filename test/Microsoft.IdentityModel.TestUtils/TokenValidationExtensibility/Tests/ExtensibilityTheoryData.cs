// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Security.Claims;
using System;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public class ExtensibilityTheoryData : TheoryDataBase
    {
        string _tokenHandlerType;
        SecurityTokenDescriptor? _securityTokenDescriptor;

        internal ExtensibilityTheoryData(
            string testId,
            string tokenHandlerType,
            int extraStackFrames) : base(testId)
        {
            ExtraStackFrames = extraStackFrames;
            TokenHandler = CreateSecurityTokenHandlerForType(tokenHandlerType);
            _tokenHandlerType = tokenHandlerType;

            ValidationParameters = CreateValidationParametersSkippingValidations();
        }

        internal static ITestingTokenHandler CreateSecurityTokenHandlerForType(string tokenHandlerType)
        {
            return tokenHandlerType switch
            {
                "JWT" => new JsonWebTokenHandlerWithResult(),
                "SAML" => new SamlSecurityTokenHandlerWithResult(),
                "SAML2" => new Saml2SecurityTokenHandlerWithResult(),
                _ => throw new NotImplementedException(tokenHandlerType)
            };
        }

        private SecurityTokenDescriptor PopulateSubjectForSecurityTokenDescriptor(
            SecurityTokenDescriptor securityTokenDescriptor,
            string tokenHandlerType)
        {
            ClaimsIdentity subject = tokenHandlerType switch
            {
                "JWT" => Default.ClaimsIdentity,
                "SAML" or "SAML2" => Default.SamlClaimsIdentity,
                _ => throw new NotImplementedException(tokenHandlerType)
            };

            securityTokenDescriptor.Subject = subject;

            return securityTokenDescriptor;
        }

        private ValidationParameters CreateValidationParametersSkippingValidations()
        {
            var validationParameters = new ValidationParameters();

            validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
            validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
            validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
            validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
            validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
            validationParameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;
            validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
            validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

            return validationParameters;
        }

        public SecurityTokenDescriptor SecurityTokenDescriptor
        {
            get => _securityTokenDescriptor!;
            set => _securityTokenDescriptor = PopulateSubjectForSecurityTokenDescriptor(value, _tokenHandlerType);
        }

        internal ITestingTokenHandler TokenHandler { get; }

        public bool IsValid { get; set; }

        internal ValidationParameters ValidationParameters { get; }

        internal ValidationError? ValidationError { get; set; }

        internal int ExtraStackFrames { get; }

        internal ExpectedException? ExpectedInnerException { get; set; }
    }
}
#nullable restore
