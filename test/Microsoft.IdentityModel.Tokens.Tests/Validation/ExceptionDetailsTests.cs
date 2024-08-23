// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.


using System;
using System.Linq;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class ExceptionDetailsTests
    {
        [Theory, MemberData(nameof(ExceptionDetailsTestCases), DisableDiscoveryEnumeration = true)]
        public void ExceptionDetails(ExceptionDetailsTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ExceptionDetails", theoryData);
            ExceptionDetail exceptionDetail = new ExceptionDetail(
                new MessageDetail(""),
                theoryData.ExceptionType,
                null);

            theoryData.ExpectedException.ProcessException(exceptionDetail.GetException(), context);

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void ExceptionDetails_UnknownType_Throws()
        {
            ExceptionDetail exceptionDetail = new ExceptionDetail(
                new MessageDetail(""),
                ValidationErrorType.Unknown,
                null);

            Assert.Throws<ArgumentException>(() => exceptionDetail.GetException());
        }

        [Fact]
        public void All_ExceptionDetails_HaveTests()
        {
            // If this test fails, we are missing a test for a new ValidationErrorType
            Assert.Equal(((int)ValidationErrorType.ExceptionTypeCount), ExceptionDetailsTestCases.Count());
        }

        public static TheoryData<ExceptionDetailsTheoryData> ExceptionDetailsTestCases
        {
            get
            {
                return new()
                {
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "ArgumentNull",
                        ExceptionType = ValidationErrorType.ArgumentNull,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "InvalidArgument",
                        ExceptionType = ValidationErrorType.InvalidArgument,
                        ExpectedException = ExpectedException.ArgumentException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "InvalidOperation",
                        ExceptionType = ValidationErrorType.InvalidOperation,
                        ExpectedException = ExpectedException.InvalidOperationException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityToken",
                        ExceptionType = ValidationErrorType.SecurityToken,
                        ExpectedException = ExpectedException.SecurityTokenException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenDecompressionFailed",
                        ExceptionType = ValidationErrorType.SecurityTokenDecompressionFailed,
                        ExpectedException = ExpectedException.SecurityTokenDecompressionFailedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenDecryptionFailed",
                        ExceptionType = ValidationErrorType.SecurityTokenDecryptionFailed,
                        ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenExpired",
                        ExceptionType = ValidationErrorType.SecurityTokenExpired,
                        ExpectedException = ExpectedException.SecurityTokenExpiredException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidAudience",
                        ExceptionType = ValidationErrorType.SecurityTokenInvalidAudience,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidAlgorithm",
                        ExceptionType = ValidationErrorType.SecurityTokenInvalidAlgorithm,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAlgorithmException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidIssuer",
                        ExceptionType = ValidationErrorType.SecurityTokenInvalidIssuer,
                        ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidLifetime",
                        ExceptionType = ValidationErrorType.SecurityTokenInvalidLifetime,
                        ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidSigningKey",
                        ExceptionType = ValidationErrorType.SecurityTokenInvalidSigningKey,
                        ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidSignature",
                        ExceptionType = ValidationErrorType.SecurityTokenInvalidSignature,
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidType",
                        ExceptionType = ValidationErrorType.SecurityTokenInvalidType,
                        ExpectedException = ExpectedException.SecurityTokenInvalidTypeException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenKeyWrap",
                        ExceptionType = ValidationErrorType.SecurityTokenKeyWrap,
                        ExpectedException = ExpectedException.SecurityTokenKeyWrapException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenMalformed",
                        ExceptionType = ValidationErrorType.SecurityTokenMalformed,
                        ExpectedException = ExpectedException.SecurityTokenMalformedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenNoExpiration",
                        ExceptionType = ValidationErrorType.SecurityTokenNoExpiration,
                        ExpectedException = ExpectedException.SecurityTokenNoExpirationException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenNotYetValid",
                        ExceptionType = ValidationErrorType.SecurityTokenNotYetValid,
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenReplayDetected",
                        ExceptionType = ValidationErrorType.SecurityTokenReplayDetected,
                        ExpectedException = ExpectedException.SecurityTokenReplayDetectedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenReplayAddFailed",
                        ExceptionType = ValidationErrorType.SecurityTokenReplayAddFailed,
                        ExpectedException = ExpectedException.SecurityTokenReplayAddFailedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenSignatureKeyNotFound",
                        ExceptionType = ValidationErrorType.SecurityTokenSignatureKeyNotFound,
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException(),
                    },
                };
            }
        }
    }

    public class ExceptionDetailsTheoryData : TheoryDataBase
    {
        internal ValidationErrorType ExceptionType { get; set; }
    }
}
