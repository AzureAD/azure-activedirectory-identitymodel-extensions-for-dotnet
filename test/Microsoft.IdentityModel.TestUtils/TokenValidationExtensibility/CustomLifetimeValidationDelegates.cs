// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomLifetimeValidationDelegates
    {
        internal static ValidationResult<ValidatedLifetime> CustomLifetimeValidatorDelegate(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            // Returns a CustomLifetimeValidationError : LifetimeValidationError
            return new CustomLifetimeValidationError(
                new MessageDetail(nameof(CustomLifetimeValidatorDelegate), null),
                ValidationFailureType.LifetimeValidationFailed,
                typeof(SecurityTokenInvalidLifetimeException),
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires,
                null);
        }

        internal static ValidationResult<ValidatedLifetime> CustomLifetimeValidatorCustomExceptionDelegate(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomLifetimeValidationError(
                new MessageDetail(nameof(CustomLifetimeValidatorCustomExceptionDelegate), null),
                ValidationFailureType.LifetimeValidationFailed,
                typeof(CustomSecurityTokenInvalidLifetimeException),
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires,
                null);
        }

        internal static ValidationResult<ValidatedLifetime> CustomLifetimeValidatorCustomExceptionCustomFailureTypeDelegate(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomLifetimeValidationError(
                new MessageDetail(nameof(CustomLifetimeValidatorCustomExceptionCustomFailureTypeDelegate), null),
                CustomLifetimeValidationError.CustomLifetimeValidationFailureType,
                typeof(CustomSecurityTokenInvalidLifetimeException),
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires);
        }

        internal static ValidationResult<ValidatedLifetime> CustomLifetimeValidatorUnknownExceptionDelegate(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomLifetimeValidationError(
                new MessageDetail(nameof(CustomLifetimeValidatorUnknownExceptionDelegate), null),
                ValidationFailureType.LifetimeValidationFailed,
                typeof(NotSupportedException),
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires,
                null);
        }

        internal static ValidationResult<ValidatedLifetime> CustomLifetimeValidatorWithoutGetExceptionOverrideDelegate(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomLifetimeWithoutGetExceptionValidationOverrideError(
                new MessageDetail(nameof(CustomLifetimeValidatorWithoutGetExceptionOverrideDelegate), null),
                ValidationFailureType.LifetimeValidationFailed,
                typeof(CustomSecurityTokenInvalidLifetimeException),
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires,
                null);
        }

        internal static ValidationResult<ValidatedLifetime> LifetimeValidatorDelegate(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new LifetimeValidationError(
                new MessageDetail(nameof(LifetimeValidatorDelegate), null),
                ValidationFailureType.LifetimeValidationFailed,
                typeof(SecurityTokenInvalidLifetimeException),
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires,
                null);
        }

        internal static ValidationResult<ValidatedLifetime> LifetimeValidatorThrows(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            throw new CustomSecurityTokenInvalidLifetimeException(nameof(LifetimeValidatorThrows), null);
        }

        internal static ValidationResult<ValidatedLifetime> LifetimeValidatorCustomLifetimeExceptionTypeDelegate(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new LifetimeValidationError(
                new MessageDetail(nameof(LifetimeValidatorCustomLifetimeExceptionTypeDelegate), null),
                ValidationFailureType.LifetimeValidationFailed,
                typeof(CustomSecurityTokenInvalidLifetimeException),
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires,
                null);
        }

        internal static ValidationResult<ValidatedLifetime> LifetimeValidatorCustomExceptionTypeDelegate(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new LifetimeValidationError(
                new MessageDetail(nameof(LifetimeValidatorCustomExceptionTypeDelegate), null),
                ValidationFailureType.LifetimeValidationFailed,
                typeof(CustomSecurityTokenException),
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires,
                null);
        }
    }
}
#nullable restore
