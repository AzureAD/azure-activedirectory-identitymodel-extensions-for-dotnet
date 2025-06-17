// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomAudienceValidationDelegates
    {
        internal static OperationResult<string, ValidationError> CustomAudienceValidatorDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            // Returns a CustomAudienceValidationError : AudienceValidationError
            return new CustomAudienceValidationError(
                new MessageDetail(nameof(CustomAudienceValidatorDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                typeof(SecurityTokenInvalidAudienceException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static OperationResult<string, ValidationError> CustomAudienceValidatorCustomExceptionDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAudienceValidationError(
                new MessageDetail(nameof(CustomAudienceValidatorCustomExceptionDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                typeof(CustomSecurityTokenInvalidAudienceException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static OperationResult<string, ValidationError> CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAudienceValidationError(
                new MessageDetail(nameof(CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate), null),
                CustomAudienceValidationError.CustomAudienceValidationFailureType,
                typeof(CustomSecurityTokenInvalidAudienceException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static OperationResult<string, ValidationError> CustomAudienceValidatorUnknownExceptionDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAudienceValidationError(
                new MessageDetail(nameof(CustomAudienceValidatorUnknownExceptionDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                typeof(NotSupportedException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static OperationResult<string, ValidationError> CustomAudienceValidatorWithoutGetExceptionOverrideDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAudienceWithoutGetExceptionValidationOverrideError(
                new MessageDetail(nameof(CustomAudienceValidatorWithoutGetExceptionOverrideDelegate), null),
                typeof(CustomSecurityTokenInvalidAudienceException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null)
                ;
        }

        internal static OperationResult<string, ValidationError> AudienceValidatorDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new AudienceValidationError(
                new MessageDetail(nameof(AudienceValidatorDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static OperationResult<string, ValidationError> AudienceValidatorThrows(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            throw new CustomSecurityTokenInvalidAudienceException(
                nameof(AudienceValidatorThrows),
                new AudienceValidationError(
                    new MessageDetail(nameof(AudienceValidatorDelegate), null),
                    ValidationFailureType.AudienceValidationFailed,
                    ValidationError.GetCurrentStackFrame(),
                    tokenAudiences,
                    null),
                null);
        }

        internal static OperationResult<string, ValidationError> AudienceValidatorCustomAudienceExceptionTypeDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new AudienceValidationError(
                new MessageDetail(nameof(AudienceValidatorCustomAudienceExceptionTypeDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static OperationResult<string, ValidationError> AudienceValidatorCustomExceptionTypeDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new AudienceValidationError(
                new MessageDetail(nameof(AudienceValidatorCustomExceptionTypeDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }
    }
}
#nullable restore
