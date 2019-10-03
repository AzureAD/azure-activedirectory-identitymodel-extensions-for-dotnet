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

//  Microsoft.IdentityModel.Protocols.Pop
// Range: 23000 - 23999.
// SignedHttpRequest range: 23000 - 23199.

namespace Microsoft.IdentityModel.Protocols.Pop
{
    /// <summary>
    /// Log messages and codes
    /// </summary>
    internal static class LogMessages
    {
        public const string IDX23000 = "IDX23000: CryptoProviderFactory returned null for key: '{0}', signatureAlgorithm: '{1}'.";
        public const string IDX23001 = "IDX23001: HttpRequestUri must be absolute when creating or validating the 'u' claim. HttpRequestUri: '{0}'.";
        public const string IDX23002 = "IDX23002: The HTTP Method must be an uppercase HTTP verb. HttpMethod: '{0}'.";
        public const string IDX23003 = "IDX23003: The signed http request does not contain the '{0}' claim or the claim value is null. This claim is required to validate a signed http request.";
        public const string IDX23004 = "IDX23004: The following query parameters will not be processed as they are repeated: '{0}'.";
        public const string IDX23005 = "IDX23005: The following headers will not be processed as they are repeated: '{0}'.";
        public const string IDX23006 = "IDX23006: The address specified '{0}' is not valid as per the HTTPS scheme. Please specify an https address for security reasons. For testing with an http address, set the RequireHttpsForJkuResourceRetrieval property on SignedHttpRequestValidationPolicy to false.";
        public const string IDX23007 = "IDX23007: HttpRequestUri is an invalid relative URI: '{0}'.";
        public const string IDX23008 = "IDX23008: Exception caught while creating the '{0}' claim. Inner exception: '{1}'.";
        public const string IDX23009 = "IDX23009: Signed http request signature validation failed.";
        public const string IDX23010 = "IDX23010: Lifetime validation of the signed http request failed. Current time: '{0}', signed http request is valid until: '{1}'.";
        public const string IDX23011 = "IDX23011: The '{0}' claim validation failed. Expected value: '{1}', value found: '{2}'.";
        public const string IDX23012 = "IDX23012: The '{0}' claim validation failed. Expected values: '{1}' or '{2}', value found: '{3}'.";
        public const string IDX23013 = "IDX23013: The 'at' token validation failed. Inner exception: '{0}'.";
        public const string IDX23014 = "IDX23014: Unable to resolve a PoP key. The 'cnf' object must have one of the following claims: 'jwk', 'jwe', 'jku', 'kid'. The 'cnf' claim value: '{0}'.";
        public const string IDX23015 = "IDX23015: A security key resolved from the 'jwk' claim is not an asymmetric key. Resolved key type: '{0}'.";
        public const string IDX23016 = "IDX23016: Unable to convert the key found in the 'jwk' claim to a security key. JsonWebKey: '{0}'.";
        public const string IDX23017 = "IDX23017: No decryption keys found. Unable to decrypt a key found in the 'jwe' claim without decryption keys.";
        public const string IDX23018 = "IDX23018: Unable to decrypt a 'jwe' claim. Decryption keys used: '{0}'. Inner exception: '{1}'.";
        public const string IDX23019 = "IDX23019: A security key resolved from the 'jwe' claim is not a symmetric key. Resolved key type: '{0}'.";
        public const string IDX23020 = "IDX23020: Only one PoP key should be resolved using the 'jku' claim. Number of resolved keys: '{0}'.";
        public const string IDX23021 = "IDX23021: Unable to resolve a PoP key from the 'jku' claim. Unable to match kid '{0}' against '{1}'.";
        public const string IDX23022 = "IDX23022: Exception caught while retrieving a jwk set from: '{0}'. Inner exception: '{1}'.";
        public const string IDX23023 = "IDX23023: To resolve a security key using only the 'kid' claim, set the 'PopKeyResolverFromKeyIdentifierAsync' delegate on SignedHttpRequestValidationPolicy.";
        public const string IDX23024 = "IDX23024: Unable to parse the '{0}' claim: '{1}'. Inner exception: '{2}'.";
        public const string IDX23025 = "IDX23025: Exception caught while validating the '{0}' claim. Inner exception: '{1}'.";
        public const string IDX23026 = "IDX23026: The request contains uncovered headers and SignedHttpRequestValidationPolicy.AcceptUncoveredHeaders is set to 'false'. Uncovered headers: '{0}'.";
        public const string IDX23027 = "IDX23027: Header: '{0}' was not found in the request headers: '{1}'. Unable to validate the 'h' claim.";
        public const string IDX23028 = "IDX23028: Query parameter: '{0}' was not found in the request query parameters: '{1}'. Unable to validate the 'q' claim.";
        public const string IDX23029 = "IDX23029: The request contains uncovered query parameters and SignedHttpRequestValidationPolicy.AcceptUncoveredQueryParameters is set to 'false'. Uncovered query parameters: '{0}'.";
        public const string IDX23030 = "IDX23030: Resolved PoP key is null. Unable to validate a signed http request signature without a PoP key.";
        public const string IDX23031 = "IDX23031: Unable to cast a '{0}' into a '{1}'. '{0}': '{2}'.";
        public const string IDX23032 = "IDX23032: Unable to resolve a PoP key from the 'jku' claim. GetPopKeysFromJkuAsync method returned null..";
    }
}
