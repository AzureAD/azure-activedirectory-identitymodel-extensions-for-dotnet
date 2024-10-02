﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

//TODO: Remove this file and use the one in TestUtils once new validation model is public.
#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public static class SkipValidationDelegates
    {
        internal static AlgorithmValidationDelegate SkipAlgorithmValidation = delegate (
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters
            validationParameters,
            CallContext callContext)
        {
            return algorithm;
        };

        internal static AudienceValidationDelegate SkipAudienceValidation = delegate (
            IList<string> audiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return "skipped"; // The audience that was validated.
        };

        internal static IssuerValidationDelegateAsync SkipIssuerValidation = delegate (
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new ValidatedIssuer(issuer, IssuerValidationSource.NotValidated)));
        };

        internal static IssuerSigningKeyValidationDelegate SkipIssuerSigningKeyValidation = delegate (
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext? callContext)
        {
            return new ValidatedSigningKeyLifetime(
                null, // ValidFrom
                null, // ValidTo
                null);// ValidationTime
        };

        internal static LifetimeValidationDelegate SkipLifetimeValidation = delegate (
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new ValidatedLifetime(notBefore, expires);
        };

        internal static SignatureValidationDelegate SkipSignatureValidation = delegate (
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext? callContext)
        {
            // This key is not used during the validation process. It is only used to satisfy the delegate signature.
            // Follow up PR will change this to remove the SecurityKey return value.
            return new(result: new JsonWebKey());
        };

        internal static TokenReplayValidationDelegate SkipTokenReplayValidation = delegate (
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return expirationTime;
        };

        internal static TokenTypeValidationDelegate SkipTokenTypeValidation = delegate (
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new ValidatedTokenType("skipped", 0);
        };
    }
}
#nullable restore
