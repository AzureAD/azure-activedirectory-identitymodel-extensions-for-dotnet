// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    public static partial class Validators
    {
        internal static AlgorithmValidatorDelegate SkipAlgorithmValidation = delegate (
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters
            validationParameters,
            CallContext callContext)
        {
            return algorithm;
        };

        internal static AudienceValidatorDelegate SkipAudienceValidation = delegate (
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

        internal static IssuerSigningKeyValidatorDelegate SkipIssuerSigningKeyValidation = delegate (
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

        internal static LifetimeValidatorDelegate SkipLifetimeValidation = delegate (
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new ValidatedLifetime(notBefore, expires);
        };

        internal static SignatureValidatorDelegate SkipSignatureValidation = delegate (
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext? callContext)
        {
            // This key is not used during the validation process. It is only used to satisfy the delegate signature.
            // Follow up PR will change this to remove the SecurityKey return value.
            return new(result: new JsonWebKey());
        };

        internal static TokenReplayValidatorDelegate SkipTokenReplayValidation = delegate (
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return expirationTime;
        };

        internal static TypeValidatorDelegate SkipTypeValidation = delegate (
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
