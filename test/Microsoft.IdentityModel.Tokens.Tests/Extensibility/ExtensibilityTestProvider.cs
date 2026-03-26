// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Extensibility.Tests
{
    /// <summary>
    /// These extensibility tests are designed to show consistency across different token handlers for the different validation steps.
    /// Coverage is provided for the following:
    /// 1. The delegates throwing
    /// 2. The delegates return a xxxValidationError, with a ValidationFailureType that is known to the xxxValidationError and one that is not known.
    /// 3. The delegates return a CustomxxxValidationError, with a ValidationFailureType that is known to the CustomxxxValidationError and one that is not known.
    /// 4. The delegates sets a ValidationFailureType that is NOT known to the xxxValidationError or the CustomxxxValidationError.
    /// </summary>
    public class ExtensibilityTestProvider
    {
        #region Algorithm
        public static TheoryData<ExtensibilityTheoryData> GenerateInvalidAlgorithmTestCases(
            TokenHandler tokenHandler,
            SecurityToken securityToken,
            string algorithm = "algorithm")
        {
            TheoryData<ExtensibilityTheoryData> theoryData = new();
            CallContext callContext = new CallContext();

            #region CustomAlgorithmValidationError
            // Delegate sets ValidationFailureType to a value that is known to CustomAlgorithmValidationError
            // ValidationError: CustomAlgorithmValidationError
            // FailureType: CustomValidationFailure.ValidationFailed
            // Exception: CustomSecurityTokenInvalidAlgorithmException
            theoryData.Add(new ExtensibilityTheoryData(
                "CustomAlgorithmValidationFailed",
                tokenHandler,
                securityToken,
                CustomAlgorithmValidationValidators.CustomAlgorithmValidationFailed)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidAlgorithmException),
                    nameof(CustomAlgorithmValidationValidators.CustomAlgorithmValidationFailed)),
                ValidationError = new CustomAlgorithmValidationError(
                    new MessageDetail(nameof(CustomAlgorithmValidationValidators.CustomAlgorithmValidationFailed)),
                    CustomValidationFailure.AlgorithmValidationFailed,
                    Default.GetStackFrame(),
                    $"{algorithm}")
            });

            // Delegate sets ValidationFailureType to a value that is known to AlgorithmValidationError
            // ValidationError: AlgorithmValidationError
            // FailureType: AlgorithmValidationFailure.ValidationFailed
            // Exception: SecurityTokenInvalidAlgorithmException
            theoryData.Add(new ExtensibilityTheoryData(
                "AlgorithmValidationFailed",
                tokenHandler,
                securityToken,
                CustomAlgorithmValidationValidators.AlgorithmValidationFailed)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidAlgorithmException(
                    nameof(CustomAlgorithmValidationValidators.AlgorithmValidationFailed)),
                ValidationError = new CustomAlgorithmValidationError(
                    new MessageDetail(nameof(CustomAlgorithmValidationValidators.AlgorithmValidationFailed)),
                    AlgorithmValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    $"{algorithm}"),
            });

            // Delegate sets ValidationFailureType to a value that is NOT known to AlgorithmValidationError or CustomAlgorithnmValidationError
            // ValidationError: CustomAlgorithmValidationError
            // FailureType: AudienceValidationFailure.AudienceDidNotMatch
            // Exception: SecurityTokenValidationException
            theoryData.Add(new ExtensibilityTheoryData(
                "AlgorithmUnknownValidationFailure",
                tokenHandler,
                securityToken,
                CustomAlgorithmValidationValidators.UnknownValidationFailure)
            {
                ExpectedException = ExpectedException.SecurityTokenValidationException(
                    nameof(CustomAlgorithmValidationValidators.UnknownValidationFailure)),
                ValidationError = new CustomAlgorithmValidationError(
                    new MessageDetail(nameof(CustomAlgorithmValidationValidators.UnknownValidationFailure)),
                    AudienceValidationFailure.AudienceDidNotMatch,
                    Default.GetStackFrame(),
                    $"{algorithm}"),
            });
            #endregion

            #region AlgorithmValidationError
            // Delegate returns AlgorithmValidationError and sets ValidationFailureType to a value that is known to AlgorithmValidationError
            // ValidationError: AlgorithmValidationError
            // FailureType: AlgorithmValidationFailure.ValidationFailed
            // Exception:  SecurityTokenInvalidAlgorithmException
            theoryData.Add(new ExtensibilityTheoryData(
                "AlgorithmValidatorDelegate",
                tokenHandler,
                securityToken,
                CustomAlgorithmValidationValidators.AlgorithmValidatorDelegate)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidAlgorithmException(
                    nameof(CustomAlgorithmValidationValidators.AlgorithmValidatorDelegate)),
                ValidationError = new AlgorithmValidationError(
                    new MessageDetail(nameof(CustomAlgorithmValidationValidators.AlgorithmValidatorDelegate)),
                    AlgorithmValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    $"{algorithm}")
            });

            // Delegate throws CustomSecurityTokenAlgorithmException
            // ValidationError: AlgorithmValidationError
            // Exception: SecurityInvalidAlgorithmException
            // FailureType: AlgorithmValidationFailure.ValidatorThrew
            // InnerException: CustomSecurityTokenInvalidAlgorithmException
            ExtensibilityTheoryData testCase = new ExtensibilityTheoryData(
                "AlgorithmValidatorThrows",
                tokenHandler,
                securityToken,
                CustomAlgorithmValidationValidators.AlgorithmValidatorThrows)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidAlgorithmException(
                    LogMessages.IDX10273,
                    typeof(CustomSecurityTokenInvalidAlgorithmException)),
                ValidationError = new AlgorithmValidationError(
                    new MessageDetail(LogMessages.IDX10273),
                    AlgorithmValidationFailure.ValidatorThrew,
                    Default.GetStackFrame(),
                    $"{algorithm}",
                    new CustomSecurityTokenInvalidAlgorithmException(nameof(CustomAlgorithmValidationValidators.AlgorithmValidatorThrows), null)
                )
            };

            // throwing makes the StackFramesCount and StackFrames properties different, so we ignore them when comparing
            testCase.PropertiesToIgnoreWhenComparing[typeof(AlgorithmValidationError)] = new List<string> { "StackFramesCount", "StackFrames" };
            theoryData.Add(testCase);
            #endregion

            return theoryData;
        }
        #endregion

        #region Audience
        public static TheoryData<ExtensibilityTheoryData> GenerateAudienceTestCases(
            TokenHandler tokenHandler,
            SecurityToken securityToken)
        {
            var theoryData = new TheoryData<ExtensibilityTheoryData>();
            var audience = Default.Audience;
            List<string> tokenAudiences = [audience];

            #region CustomAudienceValidationError
            // Delegate sets ValidationFailureType to a value that is known to CustomAudienceValidationError
            // ValidationError: CustomAudienceValidationError
            // FailureType: CustomValidationFailure.AudienceValidationFailed
            // Exception: CustomSecurityTokenInvalidAudienceException
            theoryData.Add(new ExtensibilityTheoryData(
                "CustomAudiencdValidationFailed",
                tokenHandler,
                securityToken,
                CustomAudienceValidationValidators.CustomValidationFailed)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidAudienceException),
                    nameof(CustomAudienceValidationValidators.CustomValidationFailed)),
                ValidationError = new CustomAudienceValidationError(
                    new MessageDetail(nameof(CustomAudienceValidationValidators.CustomValidationFailed)),
                    CustomValidationFailure.AudienceValidationFailed,
                    Default.GetStackFrame(),
                    tokenAudiences,
                    null)
            });

            // Delegate sets ValidationFailureType to a value that is known to AudienceValidationError
            // ValidationError: CustomAudienceValidationError
            // FailureType: AudienceValidationFailure.AudienceDidNotMatch
            // Exception: SecurityTokenInvalidAudienceException
            theoryData.Add(new ExtensibilityTheoryData(
                "AudienceDidNotMatch",
                tokenHandler,
                securityToken,
                CustomAudienceValidationValidators.AudienceDidNotMatch)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException(
                    nameof(CustomAudienceValidationValidators.AudienceDidNotMatch)),
                ValidationError = new CustomAudienceValidationError(
                    new MessageDetail(nameof(CustomAudienceValidationValidators.AudienceDidNotMatch)),
                    AudienceValidationFailure.AudienceDidNotMatch,
                    Default.GetStackFrame(),
                    tokenAudiences,
                    null),
            });

            // Delegate sets ValidationFailureType to a value that is NOT known to AudienceValidationError or CustomAudienceValidationError
            // ValidationError: CustomAudienceValidationError
            // FailureType: ValidationFailureType.AlgorithmIsNotSupported
            // Exception: SecurityTokenValidationException
            theoryData.Add(new ExtensibilityTheoryData(
                "AudienceUnknownAudienceValidationFailure",
                tokenHandler,
                securityToken,
                CustomAudienceValidationValidators.UnknownValidationFailure)
            {
                ExpectedException = ExpectedException.SecurityTokenValidationException(
                    nameof(CustomAudienceValidationValidators.UnknownValidationFailure)),
                ValidationError = new CustomAudienceValidationError(
                    new MessageDetail(nameof(CustomAudienceValidationValidators.UnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame(),
                    tokenAudiences,
                    null),
            });
            #endregion

            #region AudienceValidationError
            // Delegate returns AudienceValidationError and sets ValidationFailureType to a value that is known to AudienceValidationError
            // ValidationError: AudienceValidationError
            // FailureType: AudienceValidationFailure.AudienceDidNotMatch
            // Exception:  SecurityTokenInvalidAudienceException
            theoryData.Add(new ExtensibilityTheoryData(
                "AudienceDidNotMatch",
                tokenHandler,
                securityToken,
                CustomAudienceValidationValidators.AudienceValidatorDelegate)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException(
                    nameof(CustomAudienceValidationValidators.AudienceValidatorDelegate)),
                ValidationError = new AudienceValidationError(
                    new MessageDetail(nameof(CustomAudienceValidationValidators.AudienceValidatorDelegate)),
                    AudienceValidationFailure.AudienceDidNotMatch,
                    Default.GetStackFrame(),
                    tokenAudiences,
                    null)
            });

            // Delegate throws CustomSecurityTokenInvalidAudienceException
            // ValidationError: AudienceValidationError
            // Exception: SecurityTokenInvalidAudienceException
            // FailureType: AudienceValidationFailure.ValidatorThrew
            // InnerException: CustomSecurityTokenInvalidAudienceException
            ExtensibilityTheoryData testCase = new ExtensibilityTheoryData(
                "AudienceValidatorThrows",
                tokenHandler,
                securityToken,
                CustomAudienceValidationValidators.AudienceValidatorThrows)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException(
                    LogMessages.IDX10270,
                    typeof(CustomSecurityTokenInvalidAudienceException)),
                ValidationError = new AudienceValidationError(
                    new MessageDetail(LogMessages.IDX10270),
                    AudienceValidationFailure.ValidatorThrew,
                    Default.GetStackFrame(),
                    tokenAudiences,
                    null,
                    new SecurityTokenInvalidAudienceException(nameof(CustomAudienceValidationValidators.AudienceValidatorThrows))
                )
            };

            // throwing makes the StackFramesCount and StackFrames properties different, so we ignore them when comparing
            testCase.PropertiesToIgnoreWhenComparing[typeof(AudienceValidationError)] = new List<string> { "StackFramesCount", "StackFrames" };
            theoryData.Add(testCase);
            #endregion

            return theoryData;
        }
        #endregion

        #region Issuer
        public static TheoryData<ExtensibilityTheoryData> GenerateInvalidIssuerTestCases(
            TokenHandler tokenHandler,
            SecurityToken securityToken)
        {
            var theoryData = new TheoryData<ExtensibilityTheoryData>();
            CallContext callContext = new CallContext();
            string issuerGuid = Guid.NewGuid().ToString();

            #region return CustomIssuerValidationError
            // Delegate sets ValidationFailureType to a value that is known to CustomIssuerValidationError
            // ValidationError: CustomIssuerValidationError
            // FailureType: CustomValidationError.ValidationFailed
            // Exception: CustomSecurityTokenInvalidIssuerException
            theoryData.Add(new ExtensibilityTheoryData(
                "CustomIssuerValidationFailed",
                tokenHandler,
                securityToken,
                CustomIssuerValidationValidators.CustomValidationFailed)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    nameof(CustomIssuerValidationValidators.CustomValidationFailed)),
                ValidationError = new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidationValidators.CustomValidationFailed)),
                    CustomValidationFailure.IssuerValidationFailed,
                    Default.GetStackFrame(),
                    issuerGuid)
            });

            // Delegate sets ValidationFailureType to a value that is known to IssuerValidationError
            // ValidationError: CustomIssuerValidationError
            // FailureType: IssuerValidationFailure.ValidationFailed
            // Exception: SecurityTokenInvalidIssuerException
            theoryData.Add(new ExtensibilityTheoryData(
                "IssuerValidationFailed",
                tokenHandler,
                securityToken,
                CustomIssuerValidationValidators.IssuerValidationFailed)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException(
                    nameof(CustomIssuerValidationValidators.IssuerValidationFailed)),
                ValidationError = new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidationValidators.IssuerValidationFailed)),
                    IssuerValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    issuerGuid),
            });

            // Delegate sets ValidationFailureType to a value that is not known to IssuerValidationError or CustomIssuerValidationError
            // ValidationError: CustomIssuerValidationError
            // FailureType: AlgorithmValidationFailure.AlgorithmIsNotSupported
            // Exception: SecurityTokenValidationException
            theoryData.Add(new ExtensibilityTheoryData(
                "IssuerUnknownValidationFailure",
                tokenHandler,
                securityToken,
                CustomIssuerValidationValidators.UnknownValidationFailure)
            {
                ExpectedException = ExpectedException.SecurityTokenValidationException(
                    nameof(CustomIssuerValidationValidators.UnknownValidationFailure)),
                ValidationError = new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidationValidators.UnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame(),
                    issuerGuid),
            });
            #endregion

            #region return IssuerValidationError
            // Delegate returns IssuerValidationError and sets ValidationFailureType to a value that is known to IssuerValidationError
            // ValidationError: IssuerValidationError
            // FailureType: IssuerValidationFailure.ValidationFailed
            // Exception:  SecurityTokenInvalidIssuerException
            theoryData.Add(new ExtensibilityTheoryData(
                "IssuerValidatorDelegate",
                tokenHandler,
                securityToken,
                CustomIssuerValidationValidators.IssuerValidatorDelegateAsync)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException(
                    nameof(CustomIssuerValidationValidators.IssuerValidatorDelegateAsync)),
                ValidationError = new IssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidationValidators.IssuerValidatorDelegateAsync)),
                    IssuerValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    issuerGuid)
            });

            // Delegate throws CustomSecurityTokenInvalidIssuerException
            // ValidationError: IssuerValidationError
            // Exception: SecurityTokenInvalidIssuerException
            // FailureType: IssuerValidationFailure.ValidatorThrew
            // InnerException: CustomSecurityTokenInvalidIssuerException
            ExtensibilityTheoryData testCase = new ExtensibilityTheoryData(
                "IssuerValidatorThrows",
                tokenHandler,
                securityToken,
                CustomIssuerValidationValidators.IssuerValidatorThrows)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException(
                        LogMessages.IDX10269,
                        typeof(CustomSecurityTokenInvalidIssuerException)),
                ValidationError = new IssuerValidationError(
                    new MessageDetail(LogMessages.IDX10269),
                    IssuerValidationFailure.ValidatorThrew,
                    Default.GetStackFrame(),
                    issuerGuid)
            };

            // throwing makes the StackFramesCount and StackFrames properties different, so we ignore them when comparing
            testCase.PropertiesToIgnoreWhenComparing[typeof(IssuerValidationError)] = new List<string> { "StackFramesCount", "StackFrames" };
            theoryData.Add(testCase);
            #endregion

            return theoryData;
        }
        #endregion

        #region IssuerSigningKey
        public static TheoryData<ExtensibilityTheoryData> GenerateInvalidIssuerSigningKeyTestCases(
            TokenHandler tokenHandler,
            SecurityToken securityToken)
        {
            var theoryData = new TheoryData<ExtensibilityTheoryData>();
            CallContext callContext = new CallContext();
            string issuerGuid = Guid.NewGuid().ToString();

            #region return CustomIssuerSigningKeyValidationError
            // Delegate sets ValidationFailureType to a value that is known to CustomIssuerSigningKeyValidationError
            // ValidationError: CustomIssuerSigningKeyValidationError
            // FailureType: CustomValidationFailure.ValidationFailed
            // Exception: CustomSecurityTokenInvalidSigningKeyException
            theoryData.Add(new ExtensibilityTheoryData(
                "CustomIssuerSigningKeyValidationFailed",
                tokenHandler,
                securityToken,
                CustomIssuerSigningKeyValidationValidators.CustomValidationFailed)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidSigningKeyException),
                    nameof(CustomIssuerSigningKeyValidationValidators.CustomValidationFailed)),
                ValidationError = new CustomIssuerSigningKeyValidationError(
                    new MessageDetail(nameof(CustomIssuerSigningKeyValidationValidators.CustomValidationFailed)),
                    CustomValidationFailure.IssuerSigningKeyValidationFailed,
                    Default.GetStackFrame(),
                    null)
            });

            // Delegate sets ValidationFailureType to a value that is known to SignatureKeyValidationError
            // ValidationError: CustomIssuerSigningKeyValidationError
            // FailureType: ValidationFailureType.ValidationFailed
            // Exception: SecurityTokenInvalidIssuerSigningKeyException
            theoryData.Add(new ExtensibilityTheoryData(
                "IssuerSigningKeyValidationFailed",
                tokenHandler,
                securityToken,
                CustomIssuerSigningKeyValidationValidators.IssuerSigningKeyValidationFailed)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(
                    nameof(CustomIssuerSigningKeyValidationValidators.IssuerSigningKeyValidationFailed)),
                ValidationError = new CustomIssuerSigningKeyValidationError(
                    new MessageDetail(nameof(CustomIssuerSigningKeyValidationValidators.IssuerSigningKeyValidationFailed)),
                    SignatureKeyValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    null)
            });

            // Delegate sets ValidationFailureType to a value that is NOT known to SignatureKeyValidationError or CustomIssuerSigningKeyValidationError
            // ValidationError: CustomIssuerSigningKeyValidationError
            // FailureType: ValidationFailureType.AlgorithmIsNotSupported
            // Exception: SecurityTokenValidationException
            theoryData.Add(new ExtensibilityTheoryData(
                "IssuerSigningKeyUnknownValidationFailure",
                tokenHandler,
                securityToken,
                CustomIssuerSigningKeyValidationValidators.UnknownValidationFailure)
            {
                ExpectedException = ExpectedException.SecurityTokenValidationException("UnknownValidationFailure"),
                ValidationError = new CustomIssuerSigningKeyValidationError(
                    new MessageDetail(nameof(CustomIssuerSigningKeyValidationValidators.UnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame(),
                    null)
            });
            #endregion

            #region SignatureKeyValidationError
            // Delegate returns SignatureKeyValidationError and sets ValidationFailureType to a value that is known to SignatureKeyValidationError
            // ValidationError: SignatureKeyValidationError
            // FailureType: ValidationFailureType.ValidationFailed
            // Exception:  SecurityTokenInvalidIssuerSigningKeyException
            theoryData.Add(new ExtensibilityTheoryData(
                "IssuerSigningKeyDelegate",
                tokenHandler,
                securityToken,
                CustomIssuerSigningKeyValidationValidators.IssuerSigningKeyDelegate)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(
                    nameof(CustomIssuerSigningKeyValidationValidators.IssuerSigningKeyDelegate)),
                ValidationError = new CustomIssuerSigningKeyValidationError(
                    new MessageDetail(nameof(CustomIssuerSigningKeyValidationValidators.IssuerSigningKeyDelegate)),
                    SignatureKeyValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    null),
            });

            // Delegate throws CustomSecurityTokenInvalidIssuerSigningKeyException
            // ValidationError: SignatureKeyValidationError
            // Exception: SecurityTokenInvalidIssuerSigningKeyException
            // FailureType: ValidationFailureType.ValidatorThrew
            // InnerException: CustomSecurityTokenInvalidSigningKeyException
            ExtensibilityTheoryData testCase = new ExtensibilityTheoryData(
            "IssuerSigningKeyValidatorThrows",
            tokenHandler,
            securityToken,
            CustomIssuerSigningKeyValidationValidators.IssuerSigningKeyValidatorThrows)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(
                    LogMessages.IDX10274,
                    typeof(CustomSecurityTokenInvalidSigningKeyException)),
                ValidationError = new SignatureKeyValidationError(
                new MessageDetail(LogMessages.IDX10274),
                SignatureKeyValidationFailure.ValidatorThrew,
                Default.GetStackFrame(),
                null,
                new SecurityTokenInvalidSigningKeyException(nameof(CustomIssuerSigningKeyValidationValidators.IssuerSigningKeyValidatorThrows))
            )
            };

            // throwing makes the StackFramesCount and StackFrames properties different, so we ignore them when comparing
            testCase.PropertiesToIgnoreWhenComparing[typeof(SignatureKeyValidationError)] = new List<string> { "StackFramesCount", "StackFrames" };
            theoryData.Add(testCase);
            #endregion

            return theoryData;
        }
        #endregion

        #region Lifetime
        public static TheoryData<ExtensibilityTheoryData> GenerateInvalidLifetimeTestCases(
            TokenHandler tokenHandler,
            SecurityToken securityToken)
        {
            TheoryData<ExtensibilityTheoryData> theoryData = new();
            CallContext callContext = new CallContext();
            DateTime utcNow = DateTime.UtcNow;
            DateTime utcPlusOneHour = utcNow.AddHours(1);

            #region return CustomLifetimeValidationError
            // Delegate sets ValidationFailureType to a value that is known to CustomLifetimeValidationError
            // ValidationError: CustomLifetimeValidationError
            // FailureType: CustomValidationFailure.LifetimeValidationFailed
            // Exception: CustomSecurityTokenInvalidLifetimeException
            theoryData.Add(new ExtensibilityTheoryData(
                "CustomLifetimeValidatorDelegate",
                tokenHandler,
                securityToken,
                CustomLifetimeValidationValidators.CustomLifetimeValidationFailed)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidLifetimeException),
                    nameof(CustomLifetimeValidationValidators.CustomLifetimeValidationFailed)),
                ValidationError = new CustomLifetimeValidationError(
                    new MessageDetail(
                        nameof(CustomLifetimeValidationValidators.CustomLifetimeValidationFailed)),
                    CustomValidationFailure.LifetimeValidationFailed,
                    Default.GetStackFrame(),
                    utcNow,
                    utcPlusOneHour)
            });

            // Delegate sets ValidationFailureType to a value that is known to LifetimeValidationError
            // ValidationError: LifetimeValidationError
            // FailureType: LifetimeValidationFailure.ValidationFailed
            // Exception: SecurityTokenInvalidLifetimeException
            theoryData.Add(new ExtensibilityTheoryData(
                "LifetimeValidationFailed",
                tokenHandler,
                securityToken,
                CustomLifetimeValidationValidators.LifetimeValidationFailed)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException(
                    nameof(LifetimeValidationFailure.ValidationFailed)),
                ValidationError = new LifetimeValidationError(
                    new MessageDetail(
                        nameof(LifetimeValidationFailure.ValidationFailed)),
                    LifetimeValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    utcNow,
                    utcPlusOneHour),
            });

            // Delegate sets ValidationFailureType to a value that is NOT known to LifetimeValidationError or CustomLifetimeValidationError
            // ValidationError: CustomLifetimeValidationError
            // FailureType: ValidationFailureType.AlgorithmIsNotSupported
            // Exception: SecurityTokenValidationException
            theoryData.Add(new ExtensibilityTheoryData(
                "LifetimeUnknownValidationFailure",
                tokenHandler,
                securityToken,
                CustomLifetimeValidationValidators.CustomUnknownValidationFailure)
            {
                ExpectedException = ExpectedException.SecurityTokenValidationException(
                        nameof(CustomLifetimeValidationValidators.CustomUnknownValidationFailure)),
                ValidationError = new CustomLifetimeValidationError(
                    new MessageDetail(
                        nameof(CustomLifetimeValidationValidators.CustomUnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame(),
                    utcNow,
                    utcPlusOneHour),
            });
            #endregion

            #region return IssuerSigningKeyValidationError
            // Delegate returns LifetimeValidationError and sets ValidationFailureType to a value that is known to LifetimeValidationError
            // ValidationError: LifetimeValidationError
            // FailureType: LifetimeValidationFailure.ValidationFailed
            // Exception:  SecurityTokenLifetimeSigningKeyException
            theoryData.Add(new ExtensibilityTheoryData(
                "LifetimeValidator",
                tokenHandler,
                securityToken,
                CustomLifetimeValidationValidators.LifetimeValidator)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException(
                    nameof(CustomLifetimeValidationValidators.LifetimeValidator)),
                ValidationError = new LifetimeValidationError(
                    new MessageDetail(nameof(CustomLifetimeValidationValidators.LifetimeValidator)),
                    LifetimeValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    utcNow,
                    utcPlusOneHour),
            });

            // Delegate throws CustomSecurityTokenInvalidLifetimeException
            // ValidationError: LifetimeValidationError
            // Exception: SecurityTokenInvalidLifetimeException
            // FailureType: LifetimeValidationFailure.ValidatorThrew
            // InnerException: CustomSecurityTokenInvalidLifetimeException
            ExtensibilityTheoryData testCase = new ExtensibilityTheoryData(
                "LifetimeValidatorThrows",
                tokenHandler,
                securityToken,
                CustomLifetimeValidationValidators.ValidatorThrows)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException(
                    LogMessages.IDX10271,
                    typeof(CustomSecurityTokenInvalidLifetimeException)),
                ValidationError = new LifetimeValidationError(
                    new MessageDetail(LogMessages.IDX10271),
                    LifetimeValidationFailure.ValidatorThrew,
                    Default.GetStackFrame(),
                    utcNow,
                    utcPlusOneHour,
                    new SecurityTokenInvalidLifetimeException(nameof(CustomLifetimeValidationValidators.ValidatorThrows))
                )
            };

            // throwing makes the StackFramesCount and StackFrames properties different, so we ignore them when comparing
            testCase.PropertiesToIgnoreWhenComparing[typeof(LifetimeValidationError)] = new List<string> { "StackFramesCount", "StackFrames" };

            theoryData.Add(testCase);
            #endregion

            return theoryData;
        }

        #endregion

        #region Signature
        public static TheoryData<ExtensibilityTheoryData> GenerateInvalidSignatureTestCases(
            TokenHandler tokenHandler,
            SecurityToken securityToken)
        {
            var theoryData = new TheoryData<ExtensibilityTheoryData>();
            CallContext callContext = new CallContext();
            string issuerGuid = Guid.NewGuid().ToString();

            #region return CustomSignatureValidationError
            // Delegate sets ValidationFailureType to a value that is known to CustomSignatureValidationError
            // ValidationError: CustomSignatureValidationError
            // FailureType: CustomValidationFailures.ValidationFailed
            // Exception: CustomSecurityTokenInvalidSignatureException
            theoryData.Add(new ExtensibilityTheoryData(
                "CustomSignatureValidationFailed",
                tokenHandler,
                securityToken,
                CustomSignatureValidationValidators.CustomSignatureValidationFailed)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidSignatureException),
                    nameof(CustomSignatureValidationValidators.CustomSignatureValidationFailed)),
                ValidationError = new CustomSignatureValidationError(
                    new MessageDetail(nameof(CustomSignatureValidationValidators.CustomSignatureValidationFailed)),
                    CustomValidationFailure.SignatureValidationFailed,
                    Default.GetStackFrame())
            });

            // Delegate sets ValidationFailureType to a value that is known to SignatureValidationError
            // ValidationError: SignatureValidationError
            // FailureType: ValidationFailureType.ValidationFailed
            // Exception: SecurityTokenInvalidSignatureException
            theoryData.Add(new ExtensibilityTheoryData(
                "SignatureValidationFailed",
                tokenHandler,
                securityToken,
                CustomSignatureValidationValidators.SignatureValidationFailed)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(
                        nameof(CustomSignatureValidationValidators.SignatureValidationFailed)),
                ValidationError = new CustomSignatureValidationError(
                    new MessageDetail(nameof(CustomSignatureValidationValidators.SignatureValidationFailed)),
                    SignatureValidationFailure.ValidationFailed,
                    Default.GetStackFrame()),
            });

            // Delegate sets ValidationFailureType to a value that is NOT known to SignatureValidationError or CustomSignatureValidationError
            // ValidationError: CustomLifetimeValidationError
            // FailureType: ValidationFailureType.AlgorithmIsNotSupported
            // Exception: SecurityTokenValidationException
            theoryData.Add(new ExtensibilityTheoryData(
                "SignatureUnknownValidationFailure",
                tokenHandler,
                securityToken,
                CustomSignatureValidationValidators.UnknownValidationFailure)
            {
                ExpectedException = ExpectedException.SecurityTokenValidationException(
                    nameof(CustomSignatureValidationValidators.UnknownValidationFailure)),
                ValidationError = new CustomSignatureValidationError(
                    new MessageDetail(nameof(CustomSignatureValidationValidators.UnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame()),
            });
            #endregion

            #region return SignatureValidationError
            // Delegate returns SignatureValidationError and sets ValidationFailureType to a value that is known to SignatureValidationError
            // ValidationError: SignatureValidationError
            // FailureType: SignatureValidationFailure.ValidationFailed
            // Exception:  SecurityTokenInvalidSignatureException
            theoryData.Add(new ExtensibilityTheoryData(
                "SignatureValidatorDelegate",
                tokenHandler,
                securityToken,
                CustomSignatureValidationValidators.SignatureValidatorDelegate)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(
                    nameof(CustomSignatureValidationValidators.SignatureValidatorDelegate)),
                ValidationError = new SignatureValidationError(
                    new MessageDetail(nameof(CustomSignatureValidationValidators.SignatureValidatorDelegate)),
                    SignatureValidationFailure.ValidationFailed,
                    Default.GetStackFrame())
            });

            // Delegate throws CustomSecurityTokenInvalidSignatureException
            // ValidationError: SignatureValidationError
            // Exception: SecurityTokenInvalidSignatureException
            // FailureType: ValidationFailureType.ValidatorThrew
            // InnerException: CustomSecurityTokenInvalidSignatureException
            ExtensibilityTheoryData testCase = new ExtensibilityTheoryData(
                "SignatureValidatorThrows",
                tokenHandler,
                securityToken,
                CustomSignatureValidationValidators.SignatureValidatorThrows)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(
                        LogMessages.IDX10272,
                        typeof(CustomSecurityTokenInvalidSignatureException)),
                ValidationError = new SignatureValidationError(
                    new MessageDetail(LogMessages.IDX10272),
                    SignatureValidationFailure.ValidatorThrew,
                    Default.GetStackFrame())
            };

            // throwing makes the StackFramesCount and StackFrames properties different, so we ignore them when comparing
            testCase.PropertiesToIgnoreWhenComparing[typeof(SignatureValidationError)] = new List<string> { "StackFramesCount", "StackFrames" };

            theoryData.Add(testCase);
            #endregion

            return theoryData;
        }
        #endregion

        #region TokenReplay
        public static TheoryData<ExtensibilityTheoryData> GenerateInvalidTokenReplayTestCases(
            TokenHandler tokenHandler,
            SecurityToken securityToken)
        {
            var theoryData = new TheoryData<ExtensibilityTheoryData>();
            CallContext callContext = new CallContext();
            DateTime expirationTime = DateTime.UtcNow + TimeSpan.FromHours(1);

            #region return CustomTokenReplayValidationError
            // Delegate sets ValidationFailureType to a value that is known to CustomTokenReplayValidationError
            // ValidationError: CustomTokenReplayValidationError
            // FailureType: CustomValidationFailure.ValidationFailed
            // Exception: CustomSecurityTokenReplayDetectedException
            theoryData.Add(new ExtensibilityTheoryData(
                "CustomTokenReplayValidationDelegate",
                tokenHandler,
                securityToken,
                CustomTokenReplayValidationValidators.CustomTokenReplayValidationFailed)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenReplayDetectedException),
                    nameof(CustomTokenReplayValidationValidators.CustomTokenReplayValidationFailed)),
                ValidationError = new CustomTokenReplayValidationError(
                    new MessageDetail(nameof(CustomTokenReplayValidationValidators.CustomTokenReplayValidationFailed)),
                    CustomValidationFailure.TokenReplayValidationFailed,
                    Default.GetStackFrame(),
                    expirationTime)
            });

            // Delegate sets ValidationFailureType to a value that is known to TokenReplayDetectedError
            // ValidationError: TokenReplayValidationError
            // FailureType: TokenReplayValidationFailure.ValidationFailed
            // Exception: SecurityTokenReplayDetectedException
            theoryData.Add(new ExtensibilityTheoryData(
                "TokenReplayValidationFailed",
                tokenHandler,
                securityToken,
                CustomTokenReplayValidationValidators.TokenReplayValidationFailed)
            {
                ExpectedException = ExpectedException.SecurityTokenReplayDetectedException(
                    nameof(CustomTokenReplayValidationValidators.TokenReplayValidationFailed)),
                ValidationError = new CustomTokenReplayValidationError(
                    new MessageDetail(nameof(CustomTokenReplayValidationValidators.TokenReplayValidationFailed)),
                    TokenReplayValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    expirationTime),
            });

            // Delegate sets ValidationFailureType to a value that is NOT known to
            //   TokenReplayValidationError or CustomTokenReplayValidationError
            // ValidationError: CustomTokenReplayValidationError
            // FailureType: ValidationFailureType.AlgorithmIsNotSupported
            // Exception: SecurityTokenValidationException
            theoryData.Add(new ExtensibilityTheoryData(
                "TokenReplayUnknownValidationFailure",
                tokenHandler,
                securityToken,
                CustomTokenReplayValidationValidators.UnknownValidationFailure)
            {
                ExpectedException = ExpectedException.SecurityTokenValidationException(
                        nameof(CustomTokenReplayValidationValidators.UnknownValidationFailure)),
                ValidationError = new CustomTokenReplayValidationError(
                    new MessageDetail(nameof(CustomTokenReplayValidationValidators.UnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame(),
                    expirationTime)
            });
            #endregion

            #region return TokenReplayValidationError
            // Delegate returns TokenReplayValidationError and sets ValidationFailureType to a value that is known to TokenReplayValidationError
            // ValidationError: TokenReplayValidationError
            // FailureType: TokenReplayValidationFailure.ValidationFailed
            // Exception:  SecurityTokenReplayDetectedException
            theoryData.Add(new ExtensibilityTheoryData(
                "TokenReplayValidationDelegate",
                tokenHandler,
                securityToken,
                CustomTokenReplayValidationValidators.TokenReplayValidationDelegate)
            {
                ExpectedException = ExpectedException.SecurityTokenReplayDetectedException(
                    nameof(CustomTokenReplayValidationValidators.TokenReplayValidationDelegate)),
                ValidationError = new TokenReplayValidationError(
                    new MessageDetail(nameof(CustomTokenReplayValidationValidators.TokenReplayValidationDelegate)),
                    TokenReplayValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    expirationTime)
            });

            // Delegate throws CustomSecurityTokenTokenReplayDetectedException
            // ValidationError: TokenReplayValidationError
            // Exception: SecurityTokenReplayDetectedException
            // FailureType: TokenReplayValidationFailure.ValidatorThrew
            // InnerException: CustomSecurityTokenReplayDetectedException
            ExtensibilityTheoryData testCase = new ExtensibilityTheoryData(
                "TokenReplayValidatorThrows",
                tokenHandler,
                securityToken,
                CustomTokenReplayValidationValidators.TokenReplayValidatorThrows)
            {
                ExpectedException = ExpectedException.SecurityTokenReplayDetectedException(
                    LogMessages.IDX10276,
                    typeof(CustomSecurityTokenReplayDetectedException)),
                ValidationError = new TokenReplayValidationError(
                    new MessageDetail(LogMessages.IDX10276),
                    TokenReplayValidationFailure.ValidatorThrew,
                    Default.GetStackFrame(),
                    expirationTime,
                    new CustomSecurityTokenReplayDetectedException(
                        nameof(CustomTokenReplayValidationValidators.TokenReplayValidatorThrows),
                        new TokenReplayValidationError(
                            new MessageDetail(nameof(CustomTokenReplayValidationValidators.TokenReplayValidatorThrows)),
                            TokenReplayValidationFailure.ValidatorThrew,
                            Default.GetStackFrame(),
                            expirationTime),
                        null)
                )
            };

            // throwing makes the StackFramesCount and StackFrames properties different, so we ignore them when comparing
            testCase.PropertiesToIgnoreWhenComparing[typeof(TokenReplayValidationError)] = new List<string> { "StackFramesCount", "StackFrames" };

            theoryData.Add(testCase);

            #endregion

            return theoryData;
        }
        #endregion

        #region TokenType
        public static TheoryData<ExtensibilityTheoryData> GenerateInvalidTokenTypeTestCases(
            TokenHandler tokenHandler,
            SecurityToken securityToken)
        {
            var theoryData = new TheoryData<ExtensibilityTheoryData>();
            CallContext callContext = new CallContext();
            string tokenType = "NOTJWT";

            #region return CustomTokenTypeValidationError
            // Delegate sets ValidationFailureType to a value that is known to CustomTokenTypeValidationError
            // ValidationError: CustomTokenTypeValidationError
            // FailureType: CustomValidationFailure.ValidationFailed
            // Exception: CustomSecurityTokenInvalidTypeException
            theoryData.Add(new ExtensibilityTheoryData(
                "CustomTokenTypeValidationFailed",
                tokenHandler,
                securityToken,
                CustomTokenTypeValidationValidators.CustomTokenTypeValidationFailed)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidTypeException),
                    nameof(CustomTokenTypeValidationValidators.CustomTokenTypeValidationFailed)),
                ValidationError = new CustomTokenTypeValidationError(
                    new MessageDetail(nameof(CustomTokenTypeValidationValidators.CustomTokenTypeValidationFailed)),
                    CustomValidationFailure.TokenTypeValidationFailed,
                    Default.GetStackFrame(),
                    tokenType)
            });

            // Delegate sets ValidationFailureType to a value that is known to TokenTypeValidationError
            // ValidationError: TokenTypeValidationError
            // FailureType: TokenTypeValidationFailure.ValidationFailed
            // Exception: SecurityTokenInvalidTypeException
            theoryData.Add(new ExtensibilityTheoryData(
                "TokenTypeValidationFailed",
                tokenHandler,
                securityToken,
                CustomTokenTypeValidationValidators.TokenTypeValidationFailed)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidTypeException(
                    nameof(CustomTokenTypeValidationValidators.TokenTypeValidationFailed)),
                ValidationError = new CustomTokenTypeValidationError(
                    new MessageDetail(nameof(CustomTokenTypeValidationValidators.TokenTypeValidationFailed)),
                    TokenTypeValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    tokenType)
            });

            // Delegate sets ValidationFailureType to a value that is NOT known to TokenTypeValidationError or CustomTokenTypeValidationError
            // ValidationError: CustomTokenTypeValidationError
            // FailureType: ValidationFailureType.AlgorithmIsNotSupported
            // Exception: SecurityTokenValidationException
            theoryData.Add(new ExtensibilityTheoryData(
                "TokenTypeUnknownValidationFailure",
                tokenHandler,
                securityToken,
                CustomTokenTypeValidationValidators.UnknownValidationFailure)
            {
                ExpectedException = ExpectedException.SecurityTokenValidationException(
                    nameof(CustomTokenTypeValidationValidators.UnknownValidationFailure)),
                ValidationError = new CustomTokenTypeValidationError(
                    new MessageDetail(nameof(CustomTokenTypeValidationValidators.UnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame(),
                    tokenType),
            });
            #endregion

            #region return TokenTypeValidationError
            // Delegate returns TokenTypeValidationError and sets ValidationFailureType to a value that is known to TokenTypeValidationError
            // ValidationError: TokenTypeValidationError
            // FailureType: TokenTypeValidationFailure.ValidationFailed
            // Exception:  SecurityTokenInvalidTokenTypeException
            theoryData.Add(new ExtensibilityTheoryData(
                "TokenTypeValidatorDelegate",
                tokenHandler,
                securityToken,
                CustomTokenTypeValidationValidators.TokenTypeValidatorDelegate)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidTypeException(
                    nameof(CustomTokenTypeValidationValidators.TokenTypeValidatorDelegate)),
                ValidationError = new TokenTypeValidationError(
                    new MessageDetail(nameof(CustomTokenTypeValidationValidators.TokenTypeValidatorDelegate)),
                    TokenTypeValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    tokenType)
            });

            // Delegate throws CustomSecurityTokenInvalidTypeException
            // ValidationError: TokenTypeValidationError
            // Exception: SecurityTokenInvalidTypeException
            // FailureType: TokenTypeValidationFailure.ValidatorThrew
            // InnerException: CustomSecurityTokenInvalidTypeException
            ExtensibilityTheoryData testCase = new ExtensibilityTheoryData(
                "TokenTypeValidatorThrows",
                tokenHandler,
                securityToken,
                CustomTokenTypeValidationValidators.TokenTypeValidatorThrows)
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidTypeException(
                    LogMessages.IDX10275,
                    typeof(CustomSecurityTokenInvalidTypeException)),
                ValidationError = new TokenTypeValidationError(
                    new MessageDetail(LogMessages.IDX10275),
                    TokenTypeValidationFailure.ValidatorThrew,
                    Default.GetStackFrame(),
                    tokenType,
                    new SecurityTokenInvalidTypeException(nameof(CustomTokenTypeValidationValidators.TokenTypeValidatorThrows))
                )
            };

            // throwing makes the StackFramesCount and StackFrames properties different, so we ignore them when comparing
            testCase.PropertiesToIgnoreWhenComparing[typeof(TokenTypeValidationError)] = new List<string> { "StackFramesCount", "StackFrames" };

            theoryData.Add(testCase);

            #endregion

            return theoryData;
        }
        #endregion
    }
}
#nullable restore
