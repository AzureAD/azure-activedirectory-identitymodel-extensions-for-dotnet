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
                typeof(CustomSecurityTokenInvalidLifetimeException),
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires,
                CustomLifetimeValidationError.CustomLifetimeValidationFailureType);
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
                typeof(CustomSecurityTokenException),
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires,
                null);
        }
    }
}
#nullable restore
