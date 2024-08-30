// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.


using System;
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

        public static TheoryData<ExceptionDetailsTheoryData> ExceptionDetailsTestCases
        {
            get
            {
                return new()
                {
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "ArgumentNull",
                        ExceptionType = typeof(ArgumentNullException),
                        ExpectedException = ExpectedException.ArgumentNullException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "InvalidArgument",
                        ExceptionType = typeof(ArgumentException),
                        ExpectedException = ExpectedException.ArgumentException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "InvalidOperation",
                        ExceptionType = typeof(InvalidOperationException),
                        ExpectedException = ExpectedException.InvalidOperationException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityToken",
                        ExceptionType = typeof(SecurityTokenException),
                        ExpectedException = ExpectedException.SecurityTokenException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenDecompressionFailed",
                        ExceptionType = typeof(SecurityTokenDecompressionFailedException),
                        ExpectedException = ExpectedException.SecurityTokenDecompressionFailedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenDecryptionFailed",
                        ExceptionType = typeof(SecurityTokenDecryptionFailedException),
                        ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenExpired",
                        ExceptionType = typeof(SecurityTokenExpiredException),
                        ExpectedException = ExpectedException.SecurityTokenExpiredException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidAudience",
                        ExceptionType = typeof(SecurityTokenInvalidAudienceException),
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidAlgorithm",
                        ExceptionType = typeof(SecurityTokenInvalidAlgorithmException),
                        ExpectedException = ExpectedException.SecurityTokenInvalidAlgorithmException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidIssuer",
                        ExceptionType = typeof(SecurityTokenInvalidIssuerException),
                        ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidLifetime",
                        ExceptionType = typeof(SecurityTokenInvalidLifetimeException),
                        ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidSigningKey",
                        ExceptionType = typeof(SecurityTokenInvalidSigningKeyException),
                        ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidSignature",
                        ExceptionType = typeof(SecurityTokenInvalidSignatureException),
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenInvalidType",
                        ExceptionType = typeof(SecurityTokenInvalidTypeException),
                        ExpectedException = ExpectedException.SecurityTokenInvalidTypeException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenKeyWrap",
                        ExceptionType = typeof(SecurityTokenKeyWrapException),
                        ExpectedException = ExpectedException.SecurityTokenKeyWrapException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenMalformed",
                        ExceptionType = typeof(SecurityTokenMalformedException),
                        ExpectedException = ExpectedException.SecurityTokenMalformedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenNoExpiration",
                        ExceptionType = typeof(SecurityTokenNoExpirationException),
                        ExpectedException = ExpectedException.SecurityTokenNoExpirationException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenNotYetValid",
                        ExceptionType = typeof(SecurityTokenNotYetValidException),
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenReplayDetected",
                        ExceptionType = typeof(SecurityTokenReplayDetectedException),
                        ExpectedException = ExpectedException.SecurityTokenReplayDetectedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenReplayAddFailed",
                        ExceptionType = typeof(SecurityTokenReplayAddFailedException),
                        ExpectedException = ExpectedException.SecurityTokenReplayAddFailedException(),
                    },
                    new ExceptionDetailsTheoryData
                    {
                        TestId = "SecurityTokenSignatureKeyNotFound",
                        ExceptionType = typeof(SecurityTokenSignatureKeyNotFoundException),
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException(),
                    },
                };
            }
        }
    }

    public class ExceptionDetailsTheoryData : TheoryDataBase
    {
        internal Type ExceptionType { get; set; }
    }
}
