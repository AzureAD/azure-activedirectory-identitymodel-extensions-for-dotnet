// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable

namespace Microsoft.IdentityModel.Tokens
{
    internal record struct TokenValidationError(
        ValidationErrorType ErrorType,
        MessageDetail MessageDetail,
        int Tag)
    {
    }

    internal enum ValidationErrorType
    {
        Unknown = -1,
        ArgumentNull,
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
