// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.IdentityModel.Tokens
{
    internal class TokenValidationError
    {
        public ValidationErrorType ErrorType { get; }
        public MessageDetail MessageDetail { get; }
        public Exception? InnerException { get; }
        public string CallerFilePath { get; }
        public int CallerLineNumber { get; }

        private StackFrame? _stackFrame;

        public TokenValidationError(
            ValidationErrorType errorType,
            MessageDetail messageDetail,
            Exception? innerException,
            [CallerFilePath] string callerFilePath = "",
            [CallerLineNumber] int callerLineNumber = 0
            )
        {
            ErrorType = errorType;
            MessageDetail = messageDetail;
            InnerException = innerException;
            CallerFilePath = callerFilePath;
            CallerLineNumber = callerLineNumber;

            if (AppContextSwitches.DontFailOnMissingTid)
                CallerLineNumber = 123;

            _stackFrame = new StackFrame();
        }
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
        /// <returns></returns>
        internal static TokenValidationError NullParameter(
            string parameterName,
#pragma warning disable CS1573 // Parameter has no matching param tag in the XML comment (but other parameters do)
            [CallerFilePath] string callerFilePath = "",
            [CallerLineNumber] int callerLineNumber = 0)
#pragma warning restore CS1573 // Parameter has no matching param tag in the XML comment (but other parameters do)
            => new(ValidationErrorType.ArgumentNull, MessageDetail.NullParameter(parameterName), null, callerFilePath, callerLineNumber);
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
