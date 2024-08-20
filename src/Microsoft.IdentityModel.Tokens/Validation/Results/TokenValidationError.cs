// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable

using System;

namespace Microsoft.IdentityModel.Tokens
{
    internal interface ITokenValidationError
    {
        ValidationErrorType ErrorType { get; }
        MessageDetail MessageDetail { get; }
        int Tag { get; }

        Exception? InnerException { get; }
    }

    internal record struct TokenValidationError(
        ValidationErrorType ErrorType,
        MessageDetail MessageDetail,
        int Tag,
        Exception? InnerException) : ITokenValidationError
    {
    }

    /// <summary>
    /// 
    /// </summary>
    public static class TokenValidationErrorCommon
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="parameterName"></param>
        /// <param name="tag"></param>
        /// <returns></returns>
        internal static TokenValidationError NullParameter(string parameterName, int tag)
            => new(ValidationErrorType.ArgumentNull, MessageDetail.NullParameter(parameterName), tag, null);
    }

    internal enum ValidationErrorType
    {
        Unknown = -1,
        ArgumentNull,
        InvalidArgument,
        InvalidOperation,
        SecurityToken,
        SecurityTokenDecompressionFailed,
        SecurityTokenDecryptionFailed,
        SecurityTokenExpired,
        SecurityTokenInvalidAudience,
        SecurityTokenInvalidAlgorithm,
        SecurityTokenInvalidIssuer,
        SecurityTokenInvalidLifetime,
        SecurityTokenInvalidSigningKey,
        SecurityTokenInvalidSignature,
        SecurityTokenInvalidType,
        SecurityTokenKeyWrap,
        SecurityTokenMalformed,
        SecurityTokenNoExpiration,
        SecurityTokenNotYetValid,
        SecurityTokenReplayDetected,
        SecurityTokenReplayAddFailed,
        SecurityTokenSignatureKeyNotFound,
        ExceptionTypeCount
    }
}
#nullable restore
