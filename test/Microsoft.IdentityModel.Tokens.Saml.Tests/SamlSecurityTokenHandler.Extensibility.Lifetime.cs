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
namespace Microsoft.IdentityModel.Tokens.Saml.Extensibility.Tests
{
    public partial class SamlSecurityTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(Lifetime_ExtensibilityTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_LifetimeValidator_Extensibility(LifetimeExtensibilityTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.{nameof(ValidateTokenAsync_LifetimeValidator_Extensibility)}", theoryData);
            context.IgnoreType = false;
            for (int i = 0; i < theoryData.ExtraStackFrames; i++)
                theoryData.LifetimeValidationError!.AddStackFrame(new StackFrame(false));

            try
            {
                ValidationResult<ValidatedToken> validationResult = await theoryData.SamlSecurityTokenHandler.ValidateTokenAsync(
                    theoryData.SamlToken!,
                    theoryData.ValidationParameters!,
                    theoryData.CallContext,
                    CancellationToken.None);

                if (validationResult.IsValid)
                {
                    ValidatedToken validatedToken = validationResult.UnwrapResult();
                    if (validatedToken.ValidatedLifetime is not null)
                        IdentityComparer.AreValidatedLifetimesEqual((ValidatedLifetime)validatedToken.ValidatedLifetime, theoryData.ValidatedLifetime, context);
                }
                else
                {
                    ValidationError validationError = validationResult.UnwrapError();
                    IdentityComparer.AreValidationErrorsEqual(validationError, theoryData.LifetimeValidationError, context);
                    theoryData.ExpectedException.ProcessException(validationError.GetException(), context);
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<LifetimeExtensibilityTheoryData> Lifetime_ExtensibilityTestCases
        {
            get
            {
                var theoryData = new TheoryData<LifetimeExtensibilityTheoryData>();
                CallContext callContext = new CallContext();
                var utcNow = DateTime.UtcNow;
                var utcPlusOneHour = utcNow + TimeSpan.FromHours(1);

                #region return CustomLifetimeValidationError
                // Test cases where delegate is overridden and return a CustomLifetimeValidationError
                // CustomLifetimeValidationError : LifetimeValidationError, ExceptionType: SecurityTokenInvalidLifetimeException
                theoryData.Add(new LifetimeExtensibilityTheoryData(
                    "CustomLifetimeValidatorDelegate",
                    utcNow,
                    CustomLifetimeValidationDelegates.CustomLifetimeValidatorDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidLifetimeException),
                        nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorDelegate)),
                    LifetimeValidationError = new CustomLifetimeValidationError(
                        new MessageDetail(
                            nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorDelegate), null),
                        typeof(SecurityTokenInvalidLifetimeException),
                        new StackFrame("CustomLifetimeValidationDelegates.cs", 160),
                        utcNow,
                        utcPlusOneHour,
                        ValidationFailureType.LifetimeValidationFailed),
                });

                // CustomLifetimeValidationError : LifetimeValidationError, ExceptionType: CustomSecurityTokenInvalidLifetimeException : SecurityTokenInvalidLifetimeException
                theoryData.Add(new LifetimeExtensibilityTheoryData(
                    "CustomLifetimeValidatorCustomExceptionDelegate",
                    utcNow,
                    CustomLifetimeValidationDelegates.CustomLifetimeValidatorCustomExceptionDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidLifetimeException),
                        nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorCustomExceptionDelegate)),
                    LifetimeValidationError = new CustomLifetimeValidationError(
                        new MessageDetail(
                            nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorCustomExceptionDelegate), null),
                        typeof(CustomSecurityTokenInvalidLifetimeException),
                        new StackFrame("CustomLifetimeValidationDelegates.cs", 175),
                        utcNow,
                        utcPlusOneHour,
                        ValidationFailureType.LifetimeValidationFailed),
                });

                // CustomLifetimeValidationError : LifetimeValidationError, ExceptionType: NotSupportedException : SystemException
                theoryData.Add(new LifetimeExtensibilityTheoryData(
                    "CustomLifetimeValidatorUnknownExceptionDelegate",
                    utcNow,
                    CustomLifetimeValidationDelegates.CustomLifetimeValidatorUnknownExceptionDelegate,
                    extraStackFrames: 2)
                {
                    // CustomLifetimeValidationError does not handle the exception type 'NotSupportedException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(NotSupportedException),
                            nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorUnknownExceptionDelegate))),
                    LifetimeValidationError = new CustomLifetimeValidationError(
                        new MessageDetail(
                            nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorUnknownExceptionDelegate), null),
                        typeof(NotSupportedException),
                        new StackFrame("CustomLifetimeValidationDelegates.cs", 205),
                        utcNow,
                        utcPlusOneHour,
                        ValidationFailureType.LifetimeValidationFailed),
                });

                // CustomLifetimeValidationError : LifetimeValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomAudienceValidationFailureType
                theoryData.Add(new LifetimeExtensibilityTheoryData(
                    "CustomLifetimeValidatorCustomExceptionCustomFailureTypeDelegate",
                    utcNow,
                    CustomLifetimeValidationDelegates.CustomLifetimeValidatorCustomExceptionCustomFailureTypeDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidLifetimeException),
                        nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorCustomExceptionCustomFailureTypeDelegate)),
                    LifetimeValidationError = new CustomLifetimeValidationError(
                        new MessageDetail(
                            nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorCustomExceptionCustomFailureTypeDelegate), null),
                        typeof(CustomSecurityTokenInvalidLifetimeException),
                        new StackFrame("CustomLifetimeValidationDelegates.cs", 190),
                        utcNow,
                        utcPlusOneHour,
                        CustomLifetimeValidationError.CustomLifetimeValidationFailureType),
                });
                #endregion

                #region return LifetimeValidationError
                // Test cases where delegate is overridden and return an LifetimeValidationError
                // LifetimeValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidLifetimeException
                theoryData.Add(new LifetimeExtensibilityTheoryData(
                    "LifetimeValidatorDelegate",
                    utcNow,
                    CustomLifetimeValidationDelegates.LifetimeValidatorDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidLifetimeException),
                        nameof(CustomLifetimeValidationDelegates.LifetimeValidatorDelegate)),
                    LifetimeValidationError = new LifetimeValidationError(
                        new MessageDetail(
                            nameof(CustomLifetimeValidationDelegates.LifetimeValidatorDelegate), null),
                        typeof(SecurityTokenInvalidLifetimeException),
                        new StackFrame("CustomLifetimeValidationDelegates.cs", 235),
                        utcNow,
                        utcPlusOneHour,
                        ValidationFailureType.LifetimeValidationFailed),
                });

                // LifetimeValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidLifetimeException : SecurityTokenInvalidLifetimeException
                theoryData.Add(new LifetimeExtensibilityTheoryData(
                    "LifetimeValidatorCustomLifetimeExceptionTypeDelegate",
                    utcNow,
                    CustomLifetimeValidationDelegates.LifetimeValidatorCustomLifetimeExceptionTypeDelegate,
                    extraStackFrames: 2)
                {
                    // LifetimeValidationError does not handle the exception type 'CustomSecurityTokenInvalidLifetimeException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(CustomSecurityTokenInvalidLifetimeException),
                            nameof(CustomLifetimeValidationDelegates.LifetimeValidatorCustomLifetimeExceptionTypeDelegate))),
                    LifetimeValidationError = new LifetimeValidationError(
                        new MessageDetail(
                            nameof(CustomLifetimeValidationDelegates.LifetimeValidatorCustomLifetimeExceptionTypeDelegate), null),
                        typeof(CustomSecurityTokenInvalidLifetimeException),
                        new StackFrame("CustomLifetimeValidationDelegates.cs", 259),
                        utcNow,
                        utcPlusOneHour,
                        ValidationFailureType.LifetimeValidationFailed),
                });

                // LifetimeValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
                theoryData.Add(new LifetimeExtensibilityTheoryData(
                    "LifetimeValidatorCustomExceptionTypeDelegate",
                    utcNow,
                    CustomLifetimeValidationDelegates.LifetimeValidatorCustomExceptionTypeDelegate,
                    extraStackFrames: 2)
                {
                    // LifetimeValidationError does not handle the exception type 'CustomSecurityTokenException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(CustomSecurityTokenException),
                            nameof(CustomLifetimeValidationDelegates.LifetimeValidatorCustomExceptionTypeDelegate))),
                    LifetimeValidationError = new LifetimeValidationError(
                        new MessageDetail(
                            nameof(CustomLifetimeValidationDelegates.LifetimeValidatorCustomExceptionTypeDelegate), null),
                        typeof(CustomSecurityTokenException),
                        new StackFrame("CustomLifetimeValidationDelegates.cs", 274),
                        utcNow,
                        utcPlusOneHour,
                        ValidationFailureType.LifetimeValidationFailed),
                });

                // LifetimeValidationError : ValidationError, ExceptionType: SecurityTokenInvalidLifetimeException, inner: CustomSecurityTokenInvalidLifetimeException
                theoryData.Add(new LifetimeExtensibilityTheoryData(
                    "LifetimeValidatorThrows",
                    utcNow,
                    CustomLifetimeValidationDelegates.LifetimeValidatorThrows,
                    extraStackFrames: 1)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidLifetimeException),
                        string.Format(Tokens.LogMessages.IDX10271),
                        typeof(CustomSecurityTokenInvalidLifetimeException)),
                    LifetimeValidationError = new LifetimeValidationError(
                        new MessageDetail(
                            string.Format(Tokens.LogMessages.IDX10271), null),
                        typeof(SecurityTokenInvalidLifetimeException),
                        new StackFrame("SamlSecurityTokenHandler.ValidateToken.Internal.cs", 250),
                        utcNow,
                        utcPlusOneHour,
                        ValidationFailureType.LifetimeValidatorThrew,
                        new SecurityTokenInvalidLifetimeException(nameof(CustomLifetimeValidationDelegates.LifetimeValidatorThrows))
                    )
                });
                #endregion

                return theoryData;
            }
        }

        public class LifetimeExtensibilityTheoryData : TheoryDataBase
        {
            internal LifetimeExtensibilityTheoryData(string testId, DateTime utcNow, LifetimeValidationDelegate lifetimeValidator, int extraStackFrames) : base(testId)
            {
                SamlToken = (SamlSecurityToken)SamlSecurityTokenHandler.CreateToken(
                    new SecurityTokenDescriptor()
                    {
                        Subject = Default.SamlClaimsIdentity,
                        Issuer = Default.Issuer,
                        IssuedAt = utcNow,
                        NotBefore = utcNow,
                        Expires = utcNow + TimeSpan.FromHours(1),
                    });

                ValidationParameters = new ValidationParameters
                {
                    AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation,
                    AudienceValidator = SkipValidationDelegates.SkipAudienceValidation,
                    IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation,
                    IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation,
                    LifetimeValidator = lifetimeValidator,
                    SignatureValidator = SkipValidationDelegates.SkipSignatureValidation,
                    TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation,
                    TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation
                };

                ExtraStackFrames = extraStackFrames;
            }

            public SamlSecurityToken SamlToken { get; }

            public SamlSecurityTokenHandler SamlSecurityTokenHandler { get; } = new SamlSecurityTokenHandler();

            public bool IsValid { get; set; }

            internal ValidatedLifetime ValidatedLifetime { get; set; }

            internal ValidationParameters ValidationParameters { get; }

            internal LifetimeValidationError? LifetimeValidationError { get; set; }

            internal int ExtraStackFrames { get; }
        }
    }
}
#nullable restore
