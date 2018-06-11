//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

// Microsoft.IdentityModel.Tokens.Jwt
// Range: 14000 - 14999

namespace Microsoft.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// Log messages and codes
    /// </summary>
    internal static class LogMessages
    {
        #pragma warning disable 1591

        // signature creation / validation
        internal const string IDX14000 = "IDX1400: Signing JWT is not supported for: Algorithm: '{0}', SecurityKey: '{1}'.";

        // JWT messages
        internal const string IDX14100 = "IDX14100: JWT is not well formed: '{0}'.\nThe token needs to be in JWS or JWE Compact Serialization Format. (JWS): 'EncodedHeader.EndcodedPayload.EncodedSignature'. (JWE): 'EncodedProtectedHeader.EncodedEncryptedKey.EncodedInitializationVector.EncodedCiphertext.EncodedAuthenticationTag'.";
        internal const string IDX14101 = "IDX14101: Unable to decode the payload '{0}' as Base64Url encoded string. jwtEncodedString: '{1}'.";
        internal const string IDX14102 = "IDX14102: Unable to decode the header '{0}' as Base64Url encoded string. jwtEncodedString: '{1}'.";
        internal const string IDX14103 = "IDX14103: Failed to create the token encryption provider.";
        internal const string IDX14104 = "IDX14104: Unable to obtain a CryptoProviderFactory, both EncryptingCredentials.CryptoProviderFactory and EncryptingCredentials.Key.CrypoProviderFactory are both null.";
        internal const string IDX14105 = "IDX14105: Header.Cty != null, assuming JWS. Cty: '{0}'.";
        internal const string IDX14106 = "IDX14106: Decoding token: '{0}' into header, payload and signature.";
        internal const string IDX14107 = "IDX14107: Token string does not match the token formats: JWE (header.encryptedKey.iv.ciphertext.tag) or JWS (header.payload.signature)";

        // logging
        internal const string IDX14200 = "IDX14200: Creating raw signature using the signature credentials.";
#pragma warning restore 1591
    }
}
