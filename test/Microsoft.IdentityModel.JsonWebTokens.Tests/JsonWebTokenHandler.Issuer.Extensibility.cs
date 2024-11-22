// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens.Tests;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Json.Tests;
using Xunit;

#nullable enable
namespace Microsoft.IdentityModel.JsonWebTokens.Extensibility.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(Issuer_ExtensibilityTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_IssuerValidator_Extensibility(IssuerExtensibilityTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.{nameof(ValidateTokenAsync_IssuerValidator_Extensibility)}", theoryData);
            context.IgnoreType = false;
            for (int i = 1; i < theoryData.StackFrames.Count; i++)
                theoryData.IssuerValidationError!.AddStackFrame(theoryData.StackFrames[i]);

            try
            {
                ValidationResult<ValidatedToken> validationResult = await theoryData.JsonWebTokenHandler.ValidateTokenAsync(
                    theoryData.JsonWebToken!,
                    theoryData.ValidationParameters!,
                    theoryData.CallContext,
                    CancellationToken.None);

                if (validationResult.IsValid)
                {
                    ValidatedToken validatedToken = validationResult.UnwrapResult();
                    if (validatedToken.ValidatedIssuer.HasValue)
                        IdentityComparer.AreValidatedIssuersEqual(validatedToken.ValidatedIssuer.Value, theoryData.ValidatedIssuer, context);
                }
                else
                {
                    ValidationError validationError = validationResult.UnwrapError();
                    IdentityComparer.AreValidationErrorsEqual(validationError, theoryData.IssuerValidationError, context);
                    theoryData.ExpectedException.ProcessException(validationError.GetException(), context);
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<IssuerExtensibilityTheoryData> Issuer_ExtensibilityTestCases
        {
            get
            {
                var theoryData = new TheoryData<IssuerExtensibilityTheoryData>();
                CallContext callContext = new CallContext();
                string issuerGuid = Guid.NewGuid().ToString();

                #region return CustomIssuerValidationError
                // Test cases where delegate is overridden and return an CustomIssuerValidationError
                // CustomIssuerValidationError : IssuerValidationError, ExceptionType: SecurityTokenInvalidIssuerException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "CustomIssuerValidatorDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.CustomIssuerValidatorDelegateAsync,
                    [
                        new StackFrame("CustomIssuerValidationDelegates", 88),
                        new StackFrame(false),
                        new StackFrame(false)
                    ])
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorDelegateAsync)),
                    IssuerValidationError = new CustomIssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorDelegateAsync), null),
                        ValidationFailureType.IssuerValidationFailed,
                        typeof(SecurityTokenInvalidIssuerException),
                        new StackFrame("CustomIssuerValidationDelegates", 88),
                        issuerGuid)
                });

                // CustomIssuerValidationError : IssuerValidationError, ExceptionType: CustomSecurityTokenInvalidIssuerException : SecurityTokenInvalidIssuerException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "CustomIssuerValidatorCustomExceptionDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionDelegateAsync,
                    [
                        new StackFrame("CustomIssuerValidationDelegates", 107),
                        new StackFrame(false),
                        new StackFrame(false)
                    ])
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionDelegateAsync)),
                    IssuerValidationError = new CustomIssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionDelegateAsync), null),
                        ValidationFailureType.IssuerValidationFailed,
                        typeof(CustomSecurityTokenInvalidIssuerException),
                        new StackFrame("CustomIssuerValidationDelegates", 107),
                        issuerGuid),
                });

                // CustomIssuerValidationError : IssuerValidationError, ExceptionType: NotSupportedException : SystemException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "CustomIssuerValidatorUnknownExceptionDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.CustomIssuerValidatorUnknownExceptionDelegateAsync,
                    [
                        new StackFrame("CustomIssuerValidationDelegates", 139),
                        new StackFrame(false),
                        new StackFrame(false)
                    ])
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenException),
                        nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorUnknownExceptionDelegateAsync)),
                    IssuerValidationError = new CustomIssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorUnknownExceptionDelegateAsync), null),
                        ValidationFailureType.IssuerValidationFailed,
                        typeof(NotSupportedException),
                        new StackFrame("CustomIssuerValidationDelegates", 139),
                        issuerGuid),
                });

                // CustomIssuerValidationError : IssuerValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomIssuerValidationFailureType
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync,
                    [
                        new StackFrame("CustomIssuerValidationDelegates", 123),
                        new StackFrame(false),
                        new StackFrame(false)
                    ])
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync)),
                    IssuerValidationError = new CustomIssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync), null),
                        CustomIssuerValidationError.CustomIssuerValidationFailureType,
                        typeof(CustomSecurityTokenInvalidIssuerException),
                        new StackFrame("CustomIssuerValidationDelegates", 123),
                        issuerGuid,
                        null),
                });
                #endregion

                #region return IssuerValidationError
                // Test cases where delegate is overridden and return an IssuerValidationError
                // IssuerValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidIssuerException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "IssuerValidatorDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.IssuerValidatorDelegateAsync,
                    [
                        new StackFrame("CustomIssuerValidationDelegates", 169),
                        new StackFrame(false),
                        new StackFrame(false)
                    ])
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidationDelegates.IssuerValidatorDelegateAsync)),
                    IssuerValidationError = new IssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.IssuerValidatorDelegateAsync), null),
                        ValidationFailureType.IssuerValidationFailed,
                        typeof(SecurityTokenInvalidIssuerException),
                        new StackFrame("CustomIssuerValidationDelegates", 169),
                        issuerGuid)
                });

                // IssuerValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidIssuerException : SecurityTokenInvalidIssuerException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "IssuerValidatorCustomIssuerExceptionTypeDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.IssuerValidatorCustomIssuerExceptionTypeDelegateAsync,
                    [
                        new StackFrame("CustomIssuerValidationDelegates", 196),
                        new StackFrame(false),
                        new StackFrame(false)
                    ])
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenException),
                        nameof(CustomIssuerValidationDelegates.IssuerValidatorCustomIssuerExceptionTypeDelegateAsync)),
                    IssuerValidationError = new IssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.IssuerValidatorCustomIssuerExceptionTypeDelegateAsync), null),
                        ValidationFailureType.IssuerValidationFailed,
                        typeof(CustomSecurityTokenInvalidIssuerException),
                        new StackFrame("CustomIssuerValidationDelegates", 196),
                        issuerGuid)
                });

                // IssuerValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "IssuerValidatorCustomExceptionTypeDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.IssuerValidatorCustomExceptionTypeDelegateAsync,
                    [
                        new StackFrame("CustomIssuerValidationDelegates", 210),
                        new StackFrame(false),
                        new StackFrame(false)
                    ])
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenException),
                        nameof(CustomIssuerValidationDelegates.IssuerValidatorCustomExceptionTypeDelegateAsync)),
                    IssuerValidationError = new IssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.IssuerValidatorCustomExceptionTypeDelegateAsync), null),
                        ValidationFailureType.IssuerValidationFailed,
                        typeof(CustomSecurityTokenException),
                        new StackFrame("CustomIssuerValidationDelegates", 210),
                        issuerGuid)
                });

                // IssuerValidationError : ValidationError, ExceptionType: SecurityTokenInvalidIssuerException, inner: CustomSecurityTokenInvalidIssuerException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "IssuerValidatorThrows",
                    issuerGuid,
                    CustomIssuerValidationDelegates.IssuerValidatorThrows,
                    [
                        new StackFrame("JsonWebTokenHandler.ValidateToken.Internal.cs", 300),
                        new StackFrame(false)
                    ])
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidIssuerException),
                        string.Format(Tokens.LogMessages.IDX10269),
                        typeof(CustomSecurityTokenInvalidIssuerException)),
                    IssuerValidationError = new IssuerValidationError(
                        new MessageDetail(
                            string.Format(Tokens.LogMessages.IDX10269), null),
                        ValidationFailureType.IssuerValidatorThrew,
                        typeof(SecurityTokenInvalidIssuerException),
                        new StackFrame("JsonWebTokenHandler.ValidateToken.Internal.cs", 300),
                        issuerGuid,
                        new SecurityTokenInvalidIssuerException(nameof(CustomIssuerValidationDelegates.IssuerValidatorThrows))
                    )
                });
                #endregion

                return theoryData;
            }
        }

        public class IssuerExtensibilityTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            internal IssuerExtensibilityTheoryData(string testId, string issuer, IssuerValidationDelegateAsync issuerValidator, IList<StackFrame> stackFrames) : base(testId)
            {
                JsonWebToken = JsonUtilities.CreateUnsignedJsonWebToken("iss", issuer);
                ValidationParameters = new ValidationParameters
                {
                    AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation,
                    AudienceValidator = SkipValidationDelegates.SkipAudienceValidation,
                    IssuerValidatorAsync = issuerValidator,
                    IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation,
                    LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation,
                    SignatureValidator = SkipValidationDelegates.SkipSignatureValidation,
                    TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation,
                    TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation
                };

                StackFrames = stackFrames;
            }

            public JsonWebToken JsonWebToken { get; }

            public JsonWebTokenHandler JsonWebTokenHandler { get; } = new JsonWebTokenHandler();

            public bool IsValid { get; set; }

            internal ValidatedIssuer ValidatedIssuer { get; set; }

            internal IssuerValidationError? IssuerValidationError { get; set; }

            internal IList<StackFrame> StackFrames { get; }
        }
    }
}
#nullable restore
