// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomLifetimeValidationValidators
    {
        internal static ILifetimeValidator CustomLifetimeValidationFailed = new CustomLifetimeValidationFailedValidator();
        internal static ILifetimeValidator LifetimeValidationFailed = new LifetimeValidationFailedValidator();
        internal static ILifetimeValidator LifetimeValidator = new LifetimeValidatorValidator();
        internal static ILifetimeValidator CustomUnknownValidationFailure = new CustomUnknownValidationFailureValidator();
        internal static ILifetimeValidator ValidatorDelegate = new ValidatorDelegateValidator();
        internal static ILifetimeValidator ValidatorThrows = new ValidatorThrowsValidator();

        private class CustomLifetimeValidationFailedValidator : ILifetimeValidator
        {
            public ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
                DateTime? notBefore,
                DateTime? expires,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomLifetimeValidationError(
                    new MessageDetail(nameof(CustomLifetimeValidationFailed)),
                    CustomValidationFailure.LifetimeValidationFailed,
                    Default.GetStackFrame(),
                    notBefore,
                    expires,
                    null);
            }
        }

        private class LifetimeValidationFailedValidator : ILifetimeValidator
        {
            public ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
                DateTime? notBefore,
                DateTime? expires,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new LifetimeValidationError(
                    new MessageDetail(nameof(LifetimeValidationFailure.ValidationFailed)),
                    LifetimeValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    notBefore,
                    expires,
                    null);
            }
        }

        private class LifetimeValidatorValidator : ILifetimeValidator
        {
            public ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
                DateTime? notBefore,
                DateTime? expires,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new LifetimeValidationError(
                    new MessageDetail(nameof(LifetimeValidator)),
                    LifetimeValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    notBefore,
                    expires);
            }
        }

        private class CustomUnknownValidationFailureValidator : ILifetimeValidator
        {
            public ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
                DateTime? notBefore,
                DateTime? expires,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomLifetimeValidationError(
                    new MessageDetail(nameof(CustomUnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame(),
                    notBefore,
                    expires,
                    null);
            }
        }

        private class ValidatorDelegateValidator : ILifetimeValidator
        {
            public ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
                DateTime? notBefore,
                DateTime? expires,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new LifetimeValidationError(
                    new MessageDetail(nameof(ValidatorDelegate)),
                    LifetimeValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    notBefore,
                    expires,
                    null);
            }
        }

        private class ValidatorThrowsValidator : ILifetimeValidator
        {
            public ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
                DateTime? notBefore,
                DateTime? expires,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                throw new CustomSecurityTokenInvalidLifetimeException(
                    nameof(ValidatorThrows),
                    new LifetimeValidationError(
                        new MessageDetail(nameof(ValidatorThrows)),
                        LifetimeValidationFailure.ValidatorThrew,
                        Default.GetStackFrame(),
                        notBefore,
                        expires,
                        null),
                    null);
            }
        }
    }
}
#nullable restore
