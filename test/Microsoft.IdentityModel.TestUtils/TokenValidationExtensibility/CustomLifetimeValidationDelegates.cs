// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomLifetimeValidationDelegates
    {
        internal static OperationResult<ValidatedLifetime, ValidationError> CustomLifetimeValidatorDelegate(
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

        internal static OperationResult<ValidatedLifetime, ValidationError> CustomLifetimeValidatorCustomExceptionDelegate(
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

        internal static OperationResult<ValidatedLifetime, ValidationError> CustomLifetimeValidatorCustomExceptionCustomFailureTypeDelegate(
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

        internal static OperationResult<ValidatedLifetime, ValidationError> CustomLifetimeValidatorUnknownExceptionDelegate(
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

        internal static OperationResult<ValidatedLifetime, ValidationError> CustomLifetimeValidatorWithoutGetExceptionOverrideDelegate(
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

        internal static OperationResult<ValidatedLifetime, ValidationError> LifetimeValidatorDelegate(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new LifetimeValidationError(
                new MessageDetail(nameof(LifetimeValidatorDelegate), null),
                ValidationFailureType.LifetimeValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires,
                null);
        }

        internal static OperationResult<ValidatedLifetime, ValidationError> LifetimeValidatorThrows(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            throw new CustomSecurityTokenInvalidLifetimeException(
                nameof(LifetimeValidatorThrows),
                new LifetimeValidationError(
                    new MessageDetail(nameof(LifetimeValidatorDelegate), null),
                    ValidationFailureType.LifetimeValidationFailed,
                    ValidationError.GetCurrentStackFrame(),
                    notBefore,
                    expires,
                    null),
                null);
        }

        internal static OperationResult<ValidatedLifetime, ValidationError> LifetimeValidatorCustomLifetimeExceptionTypeDelegate(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new LifetimeValidationError(
                new MessageDetail(nameof(LifetimeValidatorCustomLifetimeExceptionTypeDelegate), null),
                ValidationFailureType.LifetimeValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires,
                null);
        }

        internal static OperationResult<ValidatedLifetime, ValidationError> LifetimeValidatorCustomExceptionTypeDelegate(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new LifetimeValidationError(
                new MessageDetail(nameof(LifetimeValidatorCustomExceptionTypeDelegate), null),
                ValidationFailureType.LifetimeValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                notBefore,
                expires,
                null);
        }
    }
}
#nullable restore
