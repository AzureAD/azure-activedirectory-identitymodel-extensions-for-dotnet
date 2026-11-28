// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest
{
    /// <summary>Identifies the SHR validation stage that failed.</summary>
    public sealed class SignedHttpRequestValidationFailure : ValidationFailureType
    {
        private SignedHttpRequestValidationFailure(string name) : base(name) { }

        /// <summary>The embedded access token is missing, invalid, or could not be validated.</summary>
        public static readonly SignedHttpRequestValidationFailure AccessToken = new("SignedHttpRequestAccessToken");

        /// <summary>The confirmation claim is missing or malformed.</summary>
        public static readonly SignedHttpRequestValidationFailure ConfirmationClaim = new("SignedHttpRequestConfirmationClaim");

        /// <summary>The PoP key could not be resolved.</summary>
        public static readonly SignedHttpRequestValidationFailure PopKey = new("SignedHttpRequestPopKey");

        /// <summary>The SHR signature is invalid.</summary>
        public static readonly SignedHttpRequestValidationFailure Signature = new("SignedHttpRequestSignature");

        /// <summary>The nonce validator rejected the SHR.</summary>
        public static readonly SignedHttpRequestValidationFailure Nonce = new("SignedHttpRequestNonce");

        /// <summary>The replay validator rejected the SHR.</summary>
        public static readonly SignedHttpRequestValidationFailure Replay = new("SignedHttpRequestReplay");

        /// <summary>An HTTP request binding claim is missing, malformed, or does not match.</summary>
        public static readonly SignedHttpRequestValidationFailure Claim = new("SignedHttpRequestClaim");
    }
}
