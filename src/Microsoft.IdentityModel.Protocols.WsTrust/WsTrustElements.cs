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

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Provides elements for WS-Trust Feb2005, 1.3 and 1.4.
    /// </summary>
    public static class WsTrustElements
    {
        public const string ActAs = "ActAs";
        public const string AllowPostdating = "AllowPostdating";
        public const string AuthenticationType = "AuthenticationType";
        public const string BinaryExchange = "BinaryExchange";
        public const string BinarySecret = "BinarySecret";
        public const string CancelTarget = "CancelTarget";
        public const string Claims = "Claims";
        public const string Challenge = "Challenge";
        public const string Created = "Created";
        public const string CanonicalizationAlgorithm = "CanonicalizationAlgorithm";
        public const string ComputedKey = "ComputedKey";
        public const string ComputedKeyAlgorithm = "ComputedKeyAlgorithm";
        public const string Context = "Context";
        public const string Code = "Code";
        public const string Delegatable = "Delegatable";
        public const string DelegateTo = "DelegateTo";
        public const string EncryptionAlgorithm = "EncryptionAlgorithm";
        public const string EncryptWith = "EncryptWith";
        public const string Entropy = "Entropy";
        public const string Expires = "Expires";
        public const string Forwardable = "Forwardable";
        public const string IssuedTokens = "IssuedTokens";
        public const string Issuer = "Issuer";
        public const string KeySize = "KeySize";
        public const string KeyType = "KeyType";
        public const string KeyWrapAlgorithm = "KeyWrapAlgorithm";
        public const string Lifetime = "Lifetime";
        public const string OnBehalfOf = "OnBehalfOf";
        public const string Participant = "Participant";
        public const string Participants = "Participants";
        public const string Primary = "Primary";
        public const string ProofEncryption = "ProofEncryption";
        public const string Reason = "Reason";
        public const string Renewing = "Renewing";
        public const string RenewTarget = "RenewTarget";
        public const string RequestedAttachedReference = "RequestedAttachedReference";
        public const string RequestedProofToken = "RequestedProofToken";
        public const string RequestedSecurityToken = "RequestedSecurityToken";
        public const string RequestedUnattachedReference = "RequestedUnattachedReference";
        public const string RequestSecurityToken = "RequestSecurityToken";
        public const string RequestSecurityTokenResponse = "RequestSecurityTokenResponse";
        public const string RequestSecurityTokenResponseCollection = "RequestSecurityTokenResponseCollection";
        public const string RequestType = "RequestType";
        public const string SecondaryParameters = "SecondaryParameters";
        public const string SignatureAlgorithm = "SignatureAlgorithm";
        public const string SignChallenge = "SignChallenge";
        public const string SignWith = "SignWith";
        public const string Status = "Status";
        public const string TokenType = "TokenType";
        public const string UseKey = "UseKey";
        public const string ValidateTarget = "ValidateTarget";
        public const string Value = "Value";
    }
}
