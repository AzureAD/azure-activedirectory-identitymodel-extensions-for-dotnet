// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens.Tests;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Json.Tests;
using Xunit;

#nullable enable
namespace Microsoft.IdentityModel.JsonWebTokens.Extensibility.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(TokenType_ExtensibilityTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_TokenTypeValidator_Extensibility(TokenTypeExtensibilityTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.{nameof(ValidateTokenAsync_TokenTypeValidator_Extensibility)}", theoryData);
            context.IgnoreType = false;
            for (int i = 0; i < theoryData.ExtraStackFrames; i++)
                theoryData.TokenTypeValidationError!.AddStackFrame(new StackFrame(false));

            try
            {
                ValidationResult<ValidatedToken> validationResult = await theoryData.JsonWebTokenHandler.ValidateTokenAsync(
                    theoryData.JsonWebToken!,
                    theoryData.ValidationParameters!,
                    theoryData.CallContext,
                    CancellationToken.None);

                if (validationResult.IsValid)
                {
                    context.Diffs.Add("validationResult.IsValid is true, expected false");
                }
                else
                {
                    ValidationError validationError = validationResult.UnwrapError();
                    IdentityComparer.AreValidationErrorsEqual(validationError, theoryData.TokenTypeValidationError, context);
                    theoryData.ExpectedException.ProcessException(validationError.GetException(), context);
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<TokenTypeExtensibilityTheoryData> TokenType_ExtensibilityTestCases
        {
            get
            {
                var theoryData = new TheoryData<TokenTypeExtensibilityTheoryData>();
                CallContext callContext = new CallContext();

                #region return CustomTokenTypeValidationError
                // Test cases where delegate is overridden and return a CustomTokenTypeValidationError
                // CustomTokenTypeValidationError : TokenTypeValidationError, ExceptionType: SecurityTokenInvalidTypeException
                theoryData.Add(new TokenTypeExtensibilityTheoryData(
                    "CustomTokenTypeValidatorDelegate",
                    CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidTypeException),
                        nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorDelegate)),
                    TokenTypeValidationError = new CustomTokenTypeValidationError(
                        new MessageDetail(
                            nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorDelegate), null),
                        ValidationFailureType.TokenTypeValidationFailed,
                        typeof(SecurityTokenInvalidTypeException),
                        new StackFrame("CustomTokenTypeValidationDelegates.cs", 160),
                        "JWT")
                });

                // CustomTokenTypeValidationError : TokenTypeValidationError, ExceptionType: CustomSecurityTokenInvalidTypeException : SecurityTokenInvalidTypeException
                theoryData.Add(new TokenTypeExtensibilityTheoryData(
                    "CustomTokenTypeValidatorCustomExceptionDelegate",
                    CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorCustomExceptionDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidTypeException),
                        nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorCustomExceptionDelegate)),
                    TokenTypeValidationError = new CustomTokenTypeValidationError(
                        new MessageDetail(
                            nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorCustomExceptionDelegate), null),
                        ValidationFailureType.TokenTypeValidationFailed,
                        typeof(CustomSecurityTokenInvalidTypeException),
                        new StackFrame("CustomTokenTypeValidationDelegates.cs", 175),
                        "JWT")
                });

                // CustomTokenTypeValidationError : TokenTypeValidationError, ExceptionType: NotSupportedException : SystemException
                theoryData.Add(new TokenTypeExtensibilityTheoryData(
                    "CustomTokenTypeValidatorUnknownExceptionDelegate",
                    CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorUnknownExceptionDelegate,
                    extraStackFrames: 2)
                {
                    // CustomTokenTypeValidationError does not handle the exception type 'NotSupportedException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(NotSupportedException),
                            nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorUnknownExceptionDelegate))),
                    TokenTypeValidationError = new CustomTokenTypeValidationError(
                        new MessageDetail(
                            nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorUnknownExceptionDelegate), null),
                        ValidationFailureType.TokenTypeValidationFailed,
                        typeof(NotSupportedException),
                        new StackFrame("CustomTokenTypeValidationDelegates.cs", 205),
                        "JWT")
                });

                // CustomTokenTypeValidationError : TokenTypeValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomAudienceValidationFailureType
                theoryData.Add(new TokenTypeExtensibilityTheoryData(
                    "CustomTokenTypeValidatorCustomExceptionCustomFailureTypeDelegate",
                    CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorCustomExceptionCustomFailureTypeDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidTypeException),
                        nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorCustomExceptionCustomFailureTypeDelegate)),
                    TokenTypeValidationError = new CustomTokenTypeValidationError(
                        new MessageDetail(
                            nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorCustomExceptionCustomFailureTypeDelegate), null),
                        CustomTokenTypeValidationError.CustomTokenTypeValidationFailureType,
                        typeof(CustomSecurityTokenInvalidTypeException),
                        new StackFrame("CustomTokenTypeValidationDelegates.cs", 190),
                        "JWT"),
                });
                #endregion

                #region return TokenTypeValidationError
                // Test cases where delegate is overridden and return an TokenTypeValidationError
                // TokenTypeValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidTypeException
                theoryData.Add(new TokenTypeExtensibilityTheoryData(
                    "TokenTypeValidatorDelegate",
                    CustomTokenTypeValidationDelegates.TokenTypeValidatorDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidTypeException),
                        nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorDelegate)),
                    TokenTypeValidationError = new TokenTypeValidationError(
                        new MessageDetail(
                            nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorDelegate), null),
                        ValidationFailureType.TokenTypeValidationFailed,
                        typeof(SecurityTokenInvalidTypeException),
                        new StackFrame("CustomTokenTypeValidationDelegates.cs", 235),
                        "JWT")
                });

                // TokenTypeValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidTypeException : SecurityTokenInvalidTypeException
                theoryData.Add(new TokenTypeExtensibilityTheoryData(
                    "TokenTypeValidatorCustomTokenTypeExceptionTypeDelegate",
                    CustomTokenTypeValidationDelegates.TokenTypeValidatorCustomTokenTypeExceptionTypeDelegate,
                    extraStackFrames: 2)
                {
                    // TokenTypeValidationError does not handle the exception type 'CustomSecurityTokenInvalidTypeException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(CustomSecurityTokenInvalidTypeException),
                            nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorCustomTokenTypeExceptionTypeDelegate))),
                    TokenTypeValidationError = new TokenTypeValidationError(
                        new MessageDetail(
                            nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorCustomTokenTypeExceptionTypeDelegate), null),
                        ValidationFailureType.TokenTypeValidationFailed,
                        typeof(CustomSecurityTokenInvalidTypeException),
                        new StackFrame("CustomTokenTypeValidationDelegates.cs", 259),
                        "JWT")
                });

                // TokenTypeValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
                theoryData.Add(new TokenTypeExtensibilityTheoryData(
                    "TokenTypeValidatorCustomExceptionTypeDelegate",
                    CustomTokenTypeValidationDelegates.TokenTypeValidatorCustomExceptionTypeDelegate,
                    extraStackFrames: 2)
                {
                    // TokenTypeValidationError does not handle the exception type 'CustomSecurityTokenException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(CustomSecurityTokenException),
                            nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorCustomExceptionTypeDelegate))),
                    TokenTypeValidationError = new TokenTypeValidationError(
                        new MessageDetail(
                            nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorCustomExceptionTypeDelegate), null),
                        ValidationFailureType.TokenTypeValidationFailed,
                        typeof(CustomSecurityTokenException),
                        new StackFrame("CustomTokenTypeValidationDelegates.cs", 274),
                        "JWT")
                });

                // TokenTypeValidationError : ValidationError, ExceptionType: SecurityTokenInvalidTypeException, inner: CustomSecurityTokenInvalidTypeException
                theoryData.Add(new TokenTypeExtensibilityTheoryData(
                    "TokenTypeValidatorThrows",
                    CustomTokenTypeValidationDelegates.TokenTypeValidatorThrows,
                    extraStackFrames: 1)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidTypeException),
                        string.Format(Tokens.LogMessages.IDX10275),
                        typeof(CustomSecurityTokenInvalidTypeException)),
                    TokenTypeValidationError = new TokenTypeValidationError(
                        new MessageDetail(
                            string.Format(Tokens.LogMessages.IDX10275), null),
                        ValidationFailureType.TokenTypeValidatorThrew,
                        typeof(SecurityTokenInvalidTypeException),
                        new StackFrame("JsonWebTokenHandler.ValidateToken.Internal.cs", 250),
                        "JWT",
                        new SecurityTokenInvalidTypeException(nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorThrows))
                    )
                });
                #endregion

                return theoryData;
            }
        }

        public class TokenTypeExtensibilityTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            internal TokenTypeExtensibilityTheoryData(string testId, TokenTypeValidationDelegate tokenTypeValidator, int extraStackFrames) : base(testId)
            {
                JsonWebToken = JsonUtilities.CreateUnsignedJsonWebToken("iss", "issuer");

                ValidationParameters = new ValidationParameters
                {
                    AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation,
                    AudienceValidator = SkipValidationDelegates.SkipAudienceValidation,
                    IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation,
                    IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation,
                    LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation,
                    SignatureValidator = SkipValidationDelegates.SkipSignatureValidation,
                    TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation,
                    TokenTypeValidator = tokenTypeValidator
                };

                ExtraStackFrames = extraStackFrames;
            }

            public JsonWebToken JsonWebToken { get; }

            public JsonWebTokenHandler JsonWebTokenHandler { get; } = new JsonWebTokenHandler();

            public bool IsValid { get; set; }

            internal ValidatedTokenType ValidatedTokenType { get; set; }

            internal TokenTypeValidationError? TokenTypeValidationError { get; set; }

            internal int ExtraStackFrames { get; }
        }
    }
}
#nullable restore
