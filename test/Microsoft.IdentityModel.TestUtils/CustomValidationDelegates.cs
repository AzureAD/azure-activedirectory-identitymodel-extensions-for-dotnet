// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomSecurityTokenInvalidIssuerException : SecurityTokenInvalidIssuerException
    {
        public CustomSecurityTokenInvalidIssuerException(string message)
            : base(message)
        {
        }
    }

    internal class UnknownSecurityTokenInvalidIssuerException : SecurityTokenInvalidIssuerException
    {
        public UnknownSecurityTokenInvalidIssuerException(string message)
            : base(message)
        {
        }
    }

    internal class CustomIssuerValidationError : IssuerValidationError
    {
        public CustomIssuerValidationError(MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidIssuer) :
            base(messageDetail, exceptionType, stackFrame, invalidIssuer)
        {
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(CustomSecurityTokenInvalidIssuerException))
                return new CustomSecurityTokenInvalidIssuerException(MessageDetail.Message) { InvalidIssuer = InvalidIssuer };

            return base.GetException();
        }
    }

    internal class CustomIssuerWithoutGetExceptionValidationError : IssuerValidationError
    {
        public CustomIssuerWithoutGetExceptionValidationError(MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidIssuer) :
            base(messageDetail, exceptionType, stackFrame, invalidIssuer)
        {
        }
    }

    internal class CustomIssuerValidatorDelegates
    {
        internal static StackFrame? CustomIssuerValidationCustomExceptionStackFrame;
        internal static StackFrame? CustomIssuerValidationStackFrame;
        internal static StackFrame? CustomIssuerValidationUnknownExceptionStackFrame;
        internal static StackFrame? CustomIssuerValidationWithoutGetExceptionDelegateStackFrame;
        internal static StackFrame? IssuerValidationStackFrame;
        internal static StackFrame? IssuerValidationUnknownExceptionTypeStackFrame;

        public CustomIssuerValidatorDelegates() { }

        static CustomIssuerValidatorDelegates()
        {
            CustomIssuerValidationCustomExceptionStackFrame = new StackFrame(true);
            CustomIssuerValidationStackFrame = new StackFrame(true);
            CustomIssuerValidationUnknownExceptionStackFrame = new StackFrame(true);
            CustomIssuerValidationWithoutGetExceptionDelegateStackFrame = new StackFrame(true);
            IssuerValidationStackFrame = new StackFrame(true);
            IssuerValidationUnknownExceptionTypeStackFrame = new StackFrame(true);
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> CustomIssuerValidationDelegate(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            CustomIssuerValidationStackFrame ??= new StackFrame(true);
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidationDelegate), null),
                    typeof(SecurityTokenInvalidIssuerException),
                    CustomIssuerValidationStackFrame,
                    issuer)));
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> CustomIssuerValidationCustomExceptionDelegate(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            CustomIssuerValidationCustomExceptionStackFrame ??= new StackFrame(true);
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidationCustomExceptionDelegate), null),
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    CustomIssuerValidationCustomExceptionStackFrame,
                    issuer)));
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> CustomIssuerValidationUnknownExceptionDelegate(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            CustomIssuerValidationCustomExceptionStackFrame ??= new StackFrame(true);
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidationUnknownExceptionDelegate), null),
                    typeof(NotSupportedException),
                    CustomIssuerValidationCustomExceptionStackFrame,
                    issuer)));
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> CustomIssuerValidationWithoutGetExceptionDelegate(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            CustomIssuerValidationCustomExceptionStackFrame ??= new StackFrame(true);
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new CustomIssuerWithoutGetExceptionValidationError(
                    new MessageDetail(nameof(CustomIssuerValidationUnknownExceptionDelegate), null),
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    CustomIssuerValidationCustomExceptionStackFrame,
                    issuer)));
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> IssuerValidationDelegate(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            IssuerValidationStackFrame ??= new StackFrame(true);
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new IssuerValidationError(
                    new MessageDetail(nameof(IssuerValidationDelegate), null),
                    typeof(SecurityTokenInvalidIssuerException),
                    IssuerValidationStackFrame,
                    issuer)));
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> IssuerValidationThrows(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            if (issuer == "Throws")
                throw new SecurityTokenInvalidIssuerException(nameof(IssuerValidationThrows));

            IssuerValidationUnknownExceptionTypeStackFrame ??= new StackFrame(true);
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new IssuerValidationError(
                    new MessageDetail(nameof(IssuerValidationUnknownExceptionTypeDelegate), null),
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    IssuerValidationUnknownExceptionTypeStackFrame,
                    issuer)));
        }

        internal static void ThrowException()
        {
            throw new SecurityTokenInvalidIssuerException();
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> IssuerValidationUnknownExceptionTypeDelegate(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            IssuerValidationUnknownExceptionTypeStackFrame ??= new StackFrame(true);
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new IssuerValidationError(
                    new MessageDetail(nameof(IssuerValidationUnknownExceptionTypeDelegate), null),
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    IssuerValidationUnknownExceptionTypeStackFrame,
                    issuer)));
        }
    }
}
#nullable restore
