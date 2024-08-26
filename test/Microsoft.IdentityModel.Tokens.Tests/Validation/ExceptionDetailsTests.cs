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
                ValidationFailureType.NullArgument,
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
                ValidationFailureType.NullArgument,
                ExceptionType.Unknown,
                null);

            Assert.Throws<ArgumentException>(() => exceptionDetail.GetException());
        }

        [Fact]
        public void All_ExceptionDetails_HaveTests()
        {
            // If this test fails, we are missing a test for a new ExceptionType
            Assert.Equal(((int)ExceptionType.ExceptionTypeCount), ExceptionDetailsTestCases.Count());
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
                        ExceptionType = ExceptionType.ArgumentNull,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "InvalidArgument",
                        ExceptionType = ExceptionType.InvalidArgument,
                        ExpectedException = ExpectedException.ArgumentException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "InvalidOperation",
                        ExceptionType = ExceptionType.InvalidOperation,
                        ExpectedException = ExpectedException.InvalidOperationException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityToken",
                        ExceptionType = ExceptionType.SecurityToken,
                        ExpectedException = ExpectedException.SecurityTokenException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenDecompressionFailed",
                        ExceptionType = ExceptionType.SecurityTokenDecompressionFailed,
                        ExpectedException = ExpectedException.SecurityTokenDecompressionFailedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenDecryptionFailed",
                        ExceptionType = ExceptionType.SecurityTokenDecryptionFailed,
                        ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenExpired",
                        ExceptionType = ExceptionType.SecurityTokenExpired,
                        ExpectedException = ExpectedException.SecurityTokenExpiredException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidAudience",
                        ExceptionType = ExceptionType.SecurityTokenInvalidAudience,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidAlgorithm",
                        ExceptionType = ExceptionType.SecurityTokenInvalidAlgorithm,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAlgorithmException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidIssuer",
                        ExceptionType = ExceptionType.SecurityTokenInvalidIssuer,
                        ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidLifetime",
                        ExceptionType = ExceptionType.SecurityTokenInvalidLifetime,
                        ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidSigningKey",
                        ExceptionType = ExceptionType.SecurityTokenInvalidSigningKey,
                        ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidSignature",
                        ExceptionType = ExceptionType.SecurityTokenInvalidSignature,
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidType",
                        ExceptionType = ExceptionType.SecurityTokenInvalidType,
                        ExpectedException = ExpectedException.SecurityTokenInvalidTypeException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenKeyWrap",
                        ExceptionType = ExceptionType.SecurityTokenKeyWrap,
                        ExpectedException = ExpectedException.SecurityTokenKeyWrapException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenMalformed",
                        ExceptionType = ExceptionType.SecurityTokenMalformed,
                        ExpectedException = ExpectedException.SecurityTokenMalformedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenNoExpiration",
                        ExceptionType = ExceptionType.SecurityTokenNoExpiration,
                        ExpectedException = ExpectedException.SecurityTokenNoExpirationException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenNotYetValid",
                        ExceptionType = ExceptionType.SecurityTokenNotYetValid,
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenReplayDetected",
                        ExceptionType = ExceptionType.SecurityTokenReplayDetected,
                        ExpectedException = ExpectedException.SecurityTokenReplayDetectedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenReplayAddFailed",
                        ExceptionType = ExceptionType.SecurityTokenReplayAddFailed,
                        ExpectedException = ExpectedException.SecurityTokenReplayAddFailedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenSignatureKeyNotFound",
                        ExceptionType = ExceptionType.SecurityTokenSignatureKeyNotFound,
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException(),
                    },
                };
            }
        }
    }

    public class ExceptionDetailsTheoryData : TheoryDataBase
    {
        internal ExceptionType ExceptionType { get; set; }
    }
}
