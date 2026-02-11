// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomIssuerValidationValidators
    {
        internal static IIssuerValidator CustomValidationFailed = new CustomValidationFailedValidator();
        internal static IIssuerValidator IssuerValidationFailed = new IssuerValidationFailedValidator();
        internal static IIssuerValidator UnknownValidationFailure = new UnknownValidationFailureValidator();
        internal static IIssuerValidator IssuerValidatorDelegateAsync = new IssuerValidatorDelegateAsyncValidator();
        internal static IIssuerValidator IssuerValidatorThrows = new IssuerValidatorThrowsValidator();

        private class CustomValidationFailedValidator : IIssuerValidator
        {
            public Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
                string issuer,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext,
                CancellationToken cancellationToken)
            {
                return Task.FromResult(new ValidationResult<ValidatedIssuer, ValidationError>(
                    new CustomIssuerValidationError(
                        new MessageDetail(nameof(CustomValidationFailed)),
                        CustomValidationFailure.IssuerValidationFailed,
                        Default.GetStackFrame(),
                        issuer)));
            }
        }

        private class IssuerValidationFailedValidator : IIssuerValidator
        {
            public Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
                string issuer,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext,
                CancellationToken cancellationToken)
            {
                return Task.FromResult(new ValidationResult<ValidatedIssuer, ValidationError>(
                    new CustomIssuerValidationError(
                        new MessageDetail(nameof(IssuerValidationFailed)),
                        IssuerValidationFailure.ValidationFailed,
                        Default.GetStackFrame(),
                        issuer)));
            }
        }

        private class UnknownValidationFailureValidator : IIssuerValidator
        {
            public Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
                string issuer,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext,
                CancellationToken cancellationToken)
            {
                return Task.FromResult(new ValidationResult<ValidatedIssuer, ValidationError>(
                    new CustomIssuerValidationError(
                        new MessageDetail(nameof(UnknownValidationFailure)),
                        AlgorithmValidationFailure.AlgorithmIsNotSupported,
                        Default.GetStackFrame(),
                        issuer)));
            }
        }

        private class IssuerValidatorDelegateAsyncValidator : IIssuerValidator
        {
            public Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
                string issuer,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext,
                CancellationToken cancellationToken)
            {
                return Task.FromResult(new ValidationResult<ValidatedIssuer, ValidationError>(
                    new IssuerValidationError(
                        new MessageDetail(nameof(IssuerValidatorDelegateAsync)),
                        IssuerValidationFailure.ValidationFailed,
                        Default.GetStackFrame(),
                        issuer)));
            }
        }

        private class IssuerValidatorThrowsValidator : IIssuerValidator
        {
            public Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
                string issuer,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext,
                CancellationToken cancellationToken)
            {
                throw new CustomSecurityTokenInvalidIssuerException(
                    nameof(IssuerValidatorThrows),
                    new IssuerValidationError(
                        new MessageDetail(nameof(IssuerValidatorThrows)),
                        IssuerValidationFailure.ValidationFailed,
                        Default.GetStackFrame(),
                        issuer),
                    null);
            }
        }
    }
}
#nullable restore
