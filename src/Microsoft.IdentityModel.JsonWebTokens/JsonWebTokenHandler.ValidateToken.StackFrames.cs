// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics;
using Microsoft.IdentityModel.Tokens;

#nullable enable

namespace Microsoft.IdentityModel.JsonWebTokens
{
    public partial class JsonWebTokenHandler : TokenHandler
    {
        // Cached stack frames to build exceptions from validation errors
        internal static class StackFrames
        {
            // ValidateTokenAsync from string
            internal static StackFrame? TokenStringNull;
            internal static StackFrame? TokenStringValidationParametersNull;
            internal static StackFrame? InvalidTokenLength;
            internal static StackFrame? TokenStringValidationFailed;
            internal static StackFrame? TokenStringReadFailed;
            // ValidateTokenAsync from SecurityToken
            internal static StackFrame? TokenNull;
            internal static StackFrame? TokenValidationParametersNull;
            internal static StackFrame? TokenNotJWT;
            internal static StackFrame? TokenValidationFailedNullConfigurationManager;
            internal static StackFrame? TokenValidationFailed;
            // ValidateJWEAsync
            internal static StackFrame? DecryptionFailed;
            internal static StackFrame? DecryptedReadFailed;
            internal static StackFrame? JWEValidationFailed;
            // ValidateJWSAsync
            internal static StackFrame? LifetimeValidationFailed;
            internal static StackFrame? AudienceValidationFailed;
            internal static StackFrame? IssuerValidationFailed;
            internal static StackFrame? ReplayValidationFailed;
            internal static StackFrame? ActorReadFailed;
            internal static StackFrame? ActorValidationFailed;
            internal static StackFrame? TypeValidationFailed;
            internal static StackFrame? SignatureValidationFailed;
            internal static StackFrame? IssuerSigningKeyValidationFailed;
            // DecryptToken
            internal static StackFrame? DecryptionTokenNull;
            internal static StackFrame? DecryptionValidationParametersNull;
            internal static StackFrame? DecryptionHeaderMissing;
            internal static StackFrame? DecryptionGetEncryptionKeys;
            internal static StackFrame? DecryptionNoKeysTried;
            internal static StackFrame? DecryptionKeyUnwrapFailed;
            // ReadToken
            internal static StackFrame? ReadTokenNullOrEmpty;
            internal static StackFrame? ReadTokenMalformed;
            // ValidateSignature
            internal static StackFrame? KidNotMatchedNoTryAll;
            internal static StackFrame? NoKeysProvided;
        }
    }
}
#nullable restore
