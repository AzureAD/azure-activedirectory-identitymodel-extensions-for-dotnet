// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomAudienceValidationValidators
    {
        internal static IAudienceValidator CustomValidationFailed = new CustomValidationFailedValidator();
        internal static IAudienceValidator AudienceDidNotMatch = new AudienceDidNotMatchValidator();
        internal static IAudienceValidator UnknownValidationFailure = new UnknownValidationFailureValidator();
        internal static IAudienceValidator WithoutGetExceptionOverrideDelegate = new WithoutGetExceptionOverrideDelegateValidator();
        internal static IAudienceValidator AudienceValidatorDelegate = new AudienceValidatorDelegateValidator();
        internal static IAudienceValidator AudienceValidatorThrows = new AudienceValidatorThrowsValidator();

        private class CustomValidationFailedValidator : IAudienceValidator
        {
            public ValidationResult<string, ValidationError> ValidateAudience(
                IList<string> tokenAudiences,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomAudienceValidationError(
                    new MessageDetail(nameof(CustomValidationFailed)),
                    CustomValidationFailure.AudienceValidationFailed,
                    Default.GetStackFrame(),
                    tokenAudiences,
                    null);
            }
        }

        private class AudienceDidNotMatchValidator : IAudienceValidator
        {
            public ValidationResult<string, ValidationError> ValidateAudience(
                IList<string> tokenAudiences,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomAudienceValidationError(
                    new MessageDetail(nameof(AudienceDidNotMatch)),
                    AudienceValidationFailure.AudienceDidNotMatch,
                    Default.GetStackFrame(),
                    tokenAudiences,
                    null);
            }
        }

        private class UnknownValidationFailureValidator : IAudienceValidator
        {
            public ValidationResult<string, ValidationError> ValidateAudience(
                IList<string> tokenAudiences,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomAudienceValidationError(
                    new MessageDetail(nameof(UnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame(),
                    tokenAudiences,
                    null);
            }
        }

        private class WithoutGetExceptionOverrideDelegateValidator : IAudienceValidator
        {
            public ValidationResult<string, ValidationError> ValidateAudience(
                IList<string> tokenAudiences,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomAudienceWithoutGetExceptionValidationOverrideError(
                    new MessageDetail(nameof(WithoutGetExceptionOverrideDelegate)),
                    Default.GetStackFrame(),
                    tokenAudiences,
                    null)
                    ;
            }
        }

        private class AudienceValidatorDelegateValidator : IAudienceValidator
        {
            public ValidationResult<string, ValidationError> ValidateAudience(
                IList<string> tokenAudiences,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new AudienceValidationError(
                    new MessageDetail(nameof(AudienceValidatorDelegate)),
                    AudienceValidationFailure.AudienceDidNotMatch,
                    Default.GetStackFrame(),
                    tokenAudiences,
                    null);
            }
        }

        private class AudienceValidatorThrowsValidator : IAudienceValidator
        {
            public ValidationResult<string, ValidationError> ValidateAudience(
                IList<string> tokenAudiences,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                throw new CustomSecurityTokenInvalidAudienceException(
                    nameof(AudienceValidatorThrows),
                    new AudienceValidationError(
                        new MessageDetail(nameof(AudienceValidatorDelegate)),
                        AudienceValidationFailure.AudienceDidNotMatch,
                        Default.GetStackFrame(),
                        tokenAudiences,
                        null),
                    null);
            }
        }
    }
}
#nullable restore
