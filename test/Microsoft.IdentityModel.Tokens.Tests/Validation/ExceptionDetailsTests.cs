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
                theoryData.ExceptionType);

            theoryData.ExpectedException.ProcessException(exceptionDetail.GetException(), context);

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void ExceptionDetails_UnknownType_Throws()
        {
            ExceptionDetail exceptionDetail = new ExceptionDetail(
                new MessageDetail(""),
                ExceptionDetail.ExceptionType.Unknown);

            Assert.Throws<ArgumentException>(() => exceptionDetail.GetException());
        }

        [Fact]
        public void All_ExceptionDetails_HaveTests()
        {
            // If this test fails, we are missing a test for a new ExceptionDetail.ExceptionType
            Assert.Equal(((int)ExceptionDetail.ExceptionType.ExceptionTypeCount), ExceptionDetailsTestCases.Count());
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
                        ExceptionType = ExceptionDetail.ExceptionType.ArgumentNull,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "InvalidOperation",
                        ExceptionType = ExceptionDetail.ExceptionType.InvalidOperation,
                        ExpectedException = ExpectedException.InvalidOperationException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityToken",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityToken,
                        ExpectedException = ExpectedException.SecurityTokenException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenDecompressionFailed",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenDecompressionFailed,
                        ExpectedException = ExpectedException.SecurityTokenDecompressionFailedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenDecryptionFailed",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenDecryptionFailed,
                        ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenExpired",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenExpired,
                        ExpectedException = ExpectedException.SecurityTokenExpiredException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidAudience",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidAlgorithm",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenInvalidAlgorithm,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAlgorithmException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidIssuer",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenInvalidIssuer,
                        ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidLifetime",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenInvalidLifetime,
                        ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidSigningKey",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenInvalidSigningKey,
                        ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidSignature",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenInvalidSignature,
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidType",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenInvalidType,
                        ExpectedException = ExpectedException.SecurityTokenInvalidTypeException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenKeyWrap",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenKeyWrap,
                        ExpectedException = ExpectedException.SecurityTokenKeyWrapException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenMalformed",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenMalformed,
                        ExpectedException = ExpectedException.SecurityTokenMalformedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenNoExpiration",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenNoExpiration,
                        ExpectedException = ExpectedException.SecurityTokenNoExpirationException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenNotYetValid",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenNotYetValid,
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenReplayDetected",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenReplayDetected,
                        ExpectedException = ExpectedException.SecurityTokenReplayDetectedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenReplayAddFailed",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenReplayAddFailed,
                        ExpectedException = ExpectedException.SecurityTokenReplayAddFailedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenSignatureKeyNotFound",
                        ExceptionType = ExceptionDetail.ExceptionType.SecurityTokenSignatureKeyNotFound,
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
