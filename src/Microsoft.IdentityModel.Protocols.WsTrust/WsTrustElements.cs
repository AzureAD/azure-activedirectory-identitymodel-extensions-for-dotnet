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

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Provides string values for WsTrust elements.
    /// <para>Attribute values for WsTrust Feb2005, 1.3 and 1.4 are the same.</para>
    /// </summary>
    public static class WsTrustElements
    {
        /// <summary>
        /// Gets the 'ActAs' element value.
        /// </summary>
        public const string ActAs = "ActAs";

        /// <summary>
        /// Gets the 'AllowPostdating' element value.
        /// </summary>
        public const string AllowPostdating = "AllowPostdating";

        /// <summary>
        /// Gets the 'AuthenticationType' element value.
        /// </summary>
        public const string AuthenticationType = "AuthenticationType";

        /// <summary>
        /// Gets the 'BinaryExchange' element value.
        /// </summary>
        public const string BinaryExchange = "BinaryExchange";

        /// <summary>
        /// Gets the 'BinarySecret' element value.
        /// </summary>
        public const string BinarySecret = "BinarySecret";

        /// <summary>
        /// Gets the 'CancelTarget' element value.
        /// </summary>
        public const string CancelTarget = "CancelTarget";

        /// <summary>
        /// Gets the 'Claims' element value.
        /// </summary>
        public const string Claims = "Claims";

        /// <summary>
        /// Gets the 'Challenge' element value.
        /// </summary>
        public const string Challenge = "Challenge";

        /// <summary>
        /// Gets the 'Created' element value.
        /// </summary>
        public const string Created = "Created";

        /// <summary>
        /// Gets the 'CanonicalizationAlgorithm' element value.
        /// </summary>
        public const string CanonicalizationAlgorithm = "CanonicalizationAlgorithm";

        /// <summary>
        /// Gets the 'ComputedKey' element value.
        /// </summary>
        public const string ComputedKey = "ComputedKey";

        /// <summary>
        /// Gets the 'ComputedKeyAlgorithm' element value.
        /// </summary>
        public const string ComputedKeyAlgorithm = "ComputedKeyAlgorithm";

        /// <summary>
        /// Gets the 'Context' element value.
        /// </summary>
        public const string Context = "Context";

        /// <summary>
        /// Gets the 'Code' element value.
        /// </summary>
        public const string Code = "Code";

        /// <summary>
        /// Gets the 'Delegatable' element value.
        /// </summary>
        public const string Delegatable = "Delegatable";

        /// <summary>
        /// Gets the 'DelegateTo' element value.
        /// </summary>
        public const string DelegateTo = "DelegateTo";

        /// <summary>
        /// Gets the 'EncryptionAlgorithm' element value.
        /// </summary>
        public const string EncryptionAlgorithm = "EncryptionAlgorithm";

        /// <summary>
        /// Gets the 'EncryptWith' element value.
        /// </summary>
        public const string EncryptWith = "EncryptWith";

        /// <summary>
        /// Gets the 'Entropy' element value.
        /// </summary>
        public const string Entropy = "Entropy";

        /// <summary>
        /// Gets the 'Expires' element value.
        /// </summary>
        public const string Expires = "Expires";

        /// <summary>
        /// Gets the 'Forwardable' element value.
        /// </summary>
        public const string Forwardable = "Forwardable";

        /// <summary>
        /// Gets the 'IssuedTokens' element value.
        /// </summary>
        public const string IssuedTokens = "IssuedTokens";

        /// <summary>
        /// Gets the 'Issuer' element value.
        /// </summary>
        public const string Issuer = "Issuer";

        /// <summary>
        /// Gets the 'KeySize' element value.
        /// </summary>
        public const string KeySize = "KeySize";

        /// <summary>
        /// Gets the 'KeyType' element value.
        /// </summary>
        public const string KeyType = "KeyType";

        /// <summary>
        /// Gets the 'KeyWrapAlgorithm' element value.
        /// </summary>
        public const string KeyWrapAlgorithm = "KeyWrapAlgorithm";

        /// <summary>
        /// Gets the 'Lifetime' element value.
        /// </summary>
        public const string Lifetime = "Lifetime";

        /// <summary>
        /// Gets the 'OnBehalfOf' element value.
        /// </summary>
        public const string OnBehalfOf = "OnBehalfOf";

        /// <summary>
        /// Gets the 'Participant' element value.
        /// </summary>
        public const string Participant = "Participant";

        /// <summary>
        /// Gets the 'Participants' element value.
        /// </summary>
        public const string Participants = "Participants";

        /// <summary>
        /// Gets the 'Primary' element value.
        /// </summary>
        public const string Primary = "Primary";

        /// <summary>
        /// Gets the 'ProofEncryption' element value.
        /// </summary>
        public const string ProofEncryption = "ProofEncryption";

        /// <summary>
        /// Gets the 'Reason' element value.
        /// </summary>
        public const string Reason = "Reason";

        /// <summary>
        /// Gets the 'Renewing' element value.
        /// </summary>
        public const string Renewing = "Renewing";

        /// <summary>
        /// Gets the 'RenewTarget' element value.
        /// </summary>
        public const string RenewTarget = "RenewTarget";

        /// <summary>
        /// Gets the 'RequestedAttachedReference' element value.
        /// </summary>
        public const string RequestedAttachedReference = "RequestedAttachedReference";

        /// <summary>
        /// Gets the 'ActAs' element value.
        /// </summary>
        public const string RequestedProofToken = "RequestedProofToken";

        /// <summary>
        /// Gets the 'RequestedProofToken' element value.
        /// </summary>
        public const string RequestedSecurityToken = "RequestedSecurityToken";

        /// <summary>
        /// Gets the 'RequestedUnattachedReference' element value.
        /// </summary>
        public const string RequestedUnattachedReference = "RequestedUnattachedReference";

        /// <summary>
        /// Gets the 'RequestSecurityToken' element value.
        /// </summary>
        public const string RequestSecurityToken = "RequestSecurityToken";

        /// <summary>
        /// Gets the 'RequestSecurityTokenResponse' element value.
        /// </summary>
        public const string RequestSecurityTokenResponse = "RequestSecurityTokenResponse";

        /// <summary>
        /// Gets the 'RequestSecurityTokenResponseCollection' element value.
        /// </summary>
        public const string RequestSecurityTokenResponseCollection = "RequestSecurityTokenResponseCollection";

        /// <summary>
        /// Gets the 'RequestType' element value.
        /// </summary>
        public const string RequestType = "RequestType";

        /// <summary>
        /// Gets the 'SecondaryParameters' element value.
        /// </summary>
        public const string SecondaryParameters = "SecondaryParameters";

        /// <summary>
        /// Gets the 'SignatureAlgorithm' element value.
        /// </summary>
        public const string SignatureAlgorithm = "SignatureAlgorithm";

        /// <summary>
        /// Gets the 'SignChallenge' element value.
        /// </summary>
        public const string SignChallenge = "SignChallenge";

        /// <summary>
        /// Gets the 'SignWith' element value.
        /// </summary>
        public const string SignWith = "SignWith";

        /// <summary>
        /// Gets the 'Status' element value.
        /// </summary>
        public const string Status = "Status";

        /// <summary>
        /// Gets the 'TokenType' element value.
        /// </summary>
        public const string TokenType = "TokenType";

        /// <summary>
        /// Gets the 'UseKey' element value.
        /// </summary>
        public const string UseKey = "UseKey";

        /// <summary>
        /// Gets the 'ValidateTarget' element value.
        /// </summary>
        public const string ValidateTarget = "ValidateTarget";

        /// <summary>
        /// Gets the 'Value' element value.
        /// </summary>
        public const string Value = "Value";
    }
}
