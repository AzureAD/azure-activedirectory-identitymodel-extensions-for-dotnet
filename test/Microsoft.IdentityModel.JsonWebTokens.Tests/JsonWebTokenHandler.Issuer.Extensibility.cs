// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens.Tests;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Json.Tests;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Extensibility.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(Issuer_ExtensibilityTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_IssuerValidator_Extensibility(IssuerExtensibilityTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.{nameof(ValidateTokenAsync_IssuerValidator_Extensibility)}", theoryData);

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
                    IdentityComparer.AreValidationErrorsEqual(validationError, theoryData.ValidationError, context);
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

                // CustomIssuerValidationError : IssuerValidationError, SecurityTokenInvalidIssuerException
                IssuerExtensibilityTheoryData testCase = new IssuerExtensibilityTheoryData("CustomIssuerValidationDelegate", issuerGuid);
                testCase.ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidatorDelegates.CustomIssuerValidationDelegate));
                testCase.ValidationParameters!.IssuerValidator = CustomIssuerValidatorDelegates.CustomIssuerValidationDelegate;
                testCase.ValidationError = new CustomIssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidatorDelegates.CustomIssuerValidationDelegate), null),
                    typeof(SecurityTokenInvalidIssuerException),
                    CustomIssuerValidatorDelegates.CustomIssuerValidationStackFrame!,
                    issuerGuid);
                theoryData.Add(testCase);

                // CustomIssuerValidationError : IssuerValidationError, CustomSecurityTokenInvalidIssuerException : SecurityTokenInvalidIssuerException
                testCase = new IssuerExtensibilityTheoryData("CustomIssuerValidationCustomExceptionDelegate", issuerGuid);
                testCase.ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidatorDelegates.CustomIssuerValidationCustomExceptionDelegate));
                testCase.ValidationParameters!.IssuerValidator = CustomIssuerValidatorDelegates.CustomIssuerValidationCustomExceptionDelegate;
                testCase.ValidationError = new CustomIssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidatorDelegates.CustomIssuerValidationCustomExceptionDelegate), null),
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    CustomIssuerValidatorDelegates.CustomIssuerValidationStackFrame!,
                    issuerGuid);
                theoryData.Add(testCase);

                // CustomIssuerValidationError : IssuerValidationError, UnknownCustomSecurityTokenInvalidIssuerException derived from SecurityTokenInvalidIssuerException
                testCase = new IssuerExtensibilityTheoryData("CustomIssuerValidationUnknownExceptionDelegate", issuerGuid);
                testCase.ExpectedException = new ExpectedException(
                        typeof(SecurityTokenException),
                        nameof(CustomIssuerValidatorDelegates.CustomIssuerValidationUnknownExceptionDelegate));
                testCase.ValidationParameters!.IssuerValidator = CustomIssuerValidatorDelegates.CustomIssuerValidationUnknownExceptionDelegate;
                testCase.ValidationError = new CustomIssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidatorDelegates.CustomIssuerValidationUnknownExceptionDelegate), null),
                    typeof(NotSupportedException),
                    CustomIssuerValidatorDelegates.CustomIssuerValidationStackFrame!,
                    issuerGuid);
                theoryData.Add(testCase);

                // IssuerValidationError with exception type CustomSecurityTokenInvalidIssuerException
                testCase = new IssuerExtensibilityTheoryData("IssuerValidationUnknownExceptionTypeDelegate", issuerGuid);
                testCase.ExpectedException = new ExpectedException(
                        typeof(SecurityTokenException),
                        nameof(CustomIssuerValidatorDelegates.IssuerValidationUnknownExceptionTypeDelegate));
                testCase.ValidationParameters!.IssuerValidator = CustomIssuerValidatorDelegates.IssuerValidationUnknownExceptionTypeDelegate;
                testCase.ValidationError = new IssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidatorDelegates.IssuerValidationUnknownExceptionTypeDelegate), null),
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    CustomIssuerValidatorDelegates.CustomIssuerValidationStackFrame!,
                    issuerGuid);
                theoryData.Add(testCase);

                // IssuerValidationError with exception type SecurityTokenInvalidIssuerException
                testCase = new IssuerExtensibilityTheoryData("IssuerValidationDelegate", issuerGuid);
                testCase.ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidatorDelegates.IssuerValidationDelegate));
                testCase.ValidationParameters!.IssuerValidator = CustomIssuerValidatorDelegates.IssuerValidationDelegate;
                testCase.ValidationError = new IssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidatorDelegates.IssuerValidationDelegate), null),
                    typeof(SecurityTokenInvalidIssuerException),
                    CustomIssuerValidatorDelegates.IssuerValidationStackFrame!,
                    issuerGuid);
                theoryData.Add(testCase);

                // Delegate throws SecurityTokenInvalidIssuerException
                testCase = new IssuerExtensibilityTheoryData("IssuerValidationThrows", "Throws");
                testCase.ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidatorDelegates.IssuerValidationThrows));
                testCase.ValidationParameters!.IssuerValidator = CustomIssuerValidatorDelegates.IssuerValidationThrows;
                testCase.ValidationError = new IssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidatorDelegates.IssuerValidationThrows), null),
                    typeof(SecurityTokenInvalidIssuerException),
                    CustomIssuerValidatorDelegates.IssuerValidationStackFrame!,
                    issuerGuid);
                theoryData.Add(testCase);

                return theoryData;
            }
        }

        public class IssuerExtensibilityTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public IssuerExtensibilityTheoryData(string testId, string issuer) : base(testId)
            {
                JsonWebToken = JsonUtilities.CreateUnsignedJsonWebToken("iss", issuer);
            }

            public JsonWebToken JsonWebToken { get; }

            public JsonWebTokenHandler JsonWebTokenHandler { get; } = new JsonWebTokenHandler();

            public string ValidIssuer { get; } = Default.Issuer;

            public bool IsValid { get; set; }

            internal override ValidationParameters? ValidationParameters { get; set; } = new ValidationParameters
            {
                AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation,
                AudienceValidator = SkipValidationDelegates.SkipAudienceValidation,
                IssuerValidator = SkipValidationDelegates.SkipIssuerValidation,
                IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation,
                LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation,
                SignatureValidator = SkipValidationDelegates.SkipSignatureValidation,
                TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation,
                TypeValidator = SkipValidationDelegates.SkipTokenTypeValidation
            };

            internal ValidatedIssuer ValidatedIssuer { get; set; }

            internal ValidationError? ValidationError { get; set; }
        }
    }
}
#nullable restore
