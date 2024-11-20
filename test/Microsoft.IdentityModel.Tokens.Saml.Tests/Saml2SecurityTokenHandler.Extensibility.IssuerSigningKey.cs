// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;

using Xunit;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml2.Extensibility.Tests
{
    public partial class Saml2SecurityTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(IssuerSigningKey_ExtensibilityTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_IssuerSigningKeyValidator_Extensibility(IssuerSigningKeyExtensibilityTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.{nameof(ValidateTokenAsync_IssuerSigningKeyValidator_Extensibility)}", theoryData);
            context.IgnoreType = false;
            for (int i = 0; i < theoryData.ExtraStackFrames; i++)
                theoryData.IssuerSigningKeyValidationError!.AddStackFrame(new StackFrame(false));

            try
            {
                ValidationResult<ValidatedToken> validationResult = await theoryData.Saml2SecurityTokenHandler.ValidateTokenAsync(
                    theoryData.Saml2Token!,
                    theoryData.ValidationParameters!,
                    theoryData.CallContext,
                    CancellationToken.None);

                if (validationResult.IsValid)
                {
                    context.AddDiff("validationResult.IsValid is true, expected false");
                }
                else
                {
                    ValidationError validationError = validationResult.UnwrapError();
                    IdentityComparer.AreValidationErrorsEqual(validationError, theoryData.IssuerSigningKeyValidationError, context);
                    theoryData.ExpectedException.ProcessException(validationError.GetException(), context);
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<IssuerSigningKeyExtensibilityTheoryData> IssuerSigningKey_ExtensibilityTestCases
        {
            get
            {
                var theoryData = new TheoryData<IssuerSigningKeyExtensibilityTheoryData>();
                CallContext callContext = new CallContext();
                var utcNow = DateTime.UtcNow;
                var utcPlusOneHour = utcNow + TimeSpan.FromHours(1);

                #region return CustomIssuerSigningKeyValidationError
                // Test cases where delegate is overridden and return a CustomIssuerSigningKeyValidationError
                // CustomIssuerSigningKeyValidationError : IssuerSigningKeyValidationError, ExceptionType: SecurityTokenInvalidIssuerSigningKeyException
                theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                    "CustomIssuerSigningKeyValidatorDelegate",
                    utcNow,
                    CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorDelegate,
                    extraStackFrames: 1)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidSigningKeyException),
                        nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorDelegate)),
                    IssuerSigningKeyValidationError = new CustomIssuerSigningKeyValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorDelegate), null),
                        typeof(SecurityTokenInvalidSigningKeyException),
                        new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 160),
                        null,
                        ValidationFailureType.SigningKeyValidationFailed)
                });

                // CustomIssuerSigningKeyValidationError : IssuerSigningKeyValidationError, ExceptionType: CustomSecurityTokenInvalidIssuerSigningKeyException : SecurityTokenInvalidIssuerSigningKeyException
                theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                    "CustomIssuerSigningKeyValidatorCustomExceptionDelegate",
                    utcNow,
                    CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorCustomExceptionDelegate,
                    extraStackFrames: 1)
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidSigningKeyException),
                        nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorCustomExceptionDelegate)),
                    IssuerSigningKeyValidationError = new CustomIssuerSigningKeyValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorCustomExceptionDelegate), null),
                        typeof(CustomSecurityTokenInvalidSigningKeyException),
                        new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 175),
                        null,
                        ValidationFailureType.SigningKeyValidationFailed),
                });

                // CustomIssuerSigningKeyValidationError : IssuerSigningKeyValidationError, ExceptionType: NotSupportedException : SystemException
                theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                    "CustomIssuerSigningKeyValidatorUnknownExceptionDelegate",
                    utcNow,
                    CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorUnknownExceptionDelegate,
                    extraStackFrames: 1)
                {
                    // CustomIssuerSigningKeyValidationError does not handle the exception type 'NotSupportedException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(NotSupportedException),
                            nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorUnknownExceptionDelegate))),
                    IssuerSigningKeyValidationError = new CustomIssuerSigningKeyValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorUnknownExceptionDelegate), null),
                        typeof(NotSupportedException),
                        new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 205),
                        null,
                        ValidationFailureType.SigningKeyValidationFailed),
                });

                // CustomIssuerSigningKeyValidationError : IssuerSigningKeyValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomAudienceValidationFailureType
                theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                    "CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate",
                    utcNow,
                    CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate,
                    extraStackFrames: 1)
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidSigningKeyException),
                        nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate)),
                    IssuerSigningKeyValidationError = new CustomIssuerSigningKeyValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate), null),
                        typeof(CustomSecurityTokenInvalidSigningKeyException),
                        new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 190),
                        null,
                        CustomIssuerSigningKeyValidationError.CustomIssuerSigningKeyValidationFailureType),
                });
                #endregion

                #region return IssuerSigningKeyValidationError
                // Test cases where delegate is overridden and return an IssuerSigningKeyValidationError
                // IssuerSigningKeyValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidIssuerSigningKeyException
                theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                    "IssuerSigningKeyValidatorDelegate",
                    utcNow,
                    CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorDelegate,
                    extraStackFrames: 1)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidSigningKeyException),
                        nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorDelegate)),
                    IssuerSigningKeyValidationError = new IssuerSigningKeyValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorDelegate), null),
                        typeof(SecurityTokenInvalidSigningKeyException),
                        new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 235),
                        null,
                        ValidationFailureType.SigningKeyValidationFailed)
                });

                // IssuerSigningKeyValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidIssuerSigningKeyException : SecurityTokenInvalidIssuerSigningKeyException
                theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                    "IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate",
                    utcNow,
                    CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate,
                    extraStackFrames: 1)
                {
                    // IssuerSigningKeyValidationError does not handle the exception type 'CustomSecurityTokenInvalidIssuerSigningKeyException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(CustomSecurityTokenInvalidSigningKeyException),
                            nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate))),
                    IssuerSigningKeyValidationError = new IssuerSigningKeyValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate), null),
                        typeof(CustomSecurityTokenInvalidSigningKeyException),
                        new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 259),
                        null,
                        ValidationFailureType.SigningKeyValidationFailed)
                });

                // IssuerSigningKeyValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
                theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                    "IssuerSigningKeyValidatorCustomExceptionTypeDelegate",
                    utcNow,
                    CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorCustomExceptionTypeDelegate,
                    extraStackFrames: 1)
                {
                    // IssuerSigningKeyValidationError does not handle the exception type 'CustomSecurityTokenException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(CustomSecurityTokenException),
                            nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorCustomExceptionTypeDelegate))),
                    IssuerSigningKeyValidationError = new IssuerSigningKeyValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorCustomExceptionTypeDelegate), null),
                        typeof(CustomSecurityTokenException),
                        new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 274),
                        null,
                        ValidationFailureType.SigningKeyValidationFailed)
                });

                // IssuerSigningKeyValidationError : ValidationError, ExceptionType: SecurityTokenInvalidIssuerSigningKeyException, inner: CustomSecurityTokenInvalidIssuerSigningKeyException
                theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                    "IssuerSigningKeyValidatorThrows",
                    utcNow,
                    CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorThrows,
                    extraStackFrames: 0)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidSigningKeyException),
                        string.Format(Tokens.LogMessages.IDX10274),
                        typeof(CustomSecurityTokenInvalidSigningKeyException)),
                    IssuerSigningKeyValidationError = new IssuerSigningKeyValidationError(
                        new MessageDetail(
                            string.Format(Tokens.LogMessages.IDX10274), null),
                        typeof(SecurityTokenInvalidSigningKeyException),
                        new StackFrame("Saml2SecurityTokenHandler.ValidateToken.Internal.cs", 250),
                        null,
                        ValidationFailureType.IssuerSigningKeyValidatorThrew,
                        new SecurityTokenInvalidSigningKeyException(nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorThrows))
                    )
                });
                #endregion

                return theoryData;
            }
        }

        public class IssuerSigningKeyExtensibilityTheoryData : TheoryDataBase
        {
            internal IssuerSigningKeyExtensibilityTheoryData(string testId, DateTime utcNow, IssuerSigningKeyValidationDelegate issuerSigningKeyValidator, int extraStackFrames) : base(testId)
            {
                Saml2Token = (Saml2SecurityToken)Saml2SecurityTokenHandler.CreateToken(
                    new SecurityTokenDescriptor()
                    {
                        Subject = Default.SamlClaimsIdentity,
                        Issuer = Default.Issuer,
                    });

                ValidationParameters = new ValidationParameters
                {
                    AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation,
                    AudienceValidator = SkipValidationDelegates.SkipAudienceValidation,
                    IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation,
                    IssuerSigningKeyValidator = issuerSigningKeyValidator,
                    LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation,
                    SignatureValidator = (SecurityToken token, ValidationParameters validationParameters, BaseConfiguration? configuration, CallContext? callContext) =>
                    {
                        token.SigningKey = SigningKey;

                        return SigningKey;
                    },
                    TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation,
                    TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation
                };

                ExtraStackFrames = extraStackFrames;
            }

            public Saml2SecurityToken Saml2Token { get; }

            public Saml2SecurityTokenHandler Saml2SecurityTokenHandler { get; } = new Saml2SecurityTokenHandler();

            public bool IsValid { get; set; }

            public SecurityKey SigningKey { get; set; } = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key;

            internal ValidationParameters? ValidationParameters { get; set; }

            internal IssuerSigningKeyValidationError? IssuerSigningKeyValidationError { get; set; }

            internal int ExtraStackFrames { get; }
        }
    }
}
#nullable restore
