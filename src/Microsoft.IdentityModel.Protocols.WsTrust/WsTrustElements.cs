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
    /// Constants for WSTrust element names.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public static class WsTrustElements
    {
        /// <summary>
        /// Gets the value for "ActAs"
        /// </summary>
        public const string ActAs = "ActAs";

        /// <summary>
        /// Gets the value for "AllowPostdating"
        /// </summary>
        public const string AllowPostdating = "AllowPostdating";

        /// <summary>
        /// Gets the value for "AuthenticationType"
        /// </summary>
        public const string AuthenticationType = "AuthenticationType";

        /// <summary>
        /// Gets the value for "BinaryExchange"
        /// </summary>
        public const string BinaryExchange = "BinaryExchange";

        /// <summary>
        /// Gets the value for "BinarySecret"
        /// </summary>
        public const string BinarySecret = "BinarySecret";

        /// <summary>
        /// Gets the value for "CancelTarget"
        /// </summary>
        public const string CancelTarget = "CancelTarget";

        /// <summary>
        /// Gets the value for "Claims"
        /// </summary>
        public const string Claims = "Claims";

        /// <summary>
        /// Gets the value for "Challenge"
        /// </summary>
        public const string Challenge = "Challenge";

        /// <summary>
        /// Gets the value for "Created"
        /// </summary>
        public const string Created = "Created";

        /// <summary>
        /// Gets the value for "CanonicalizationAlgorithm"
        /// </summary>
        public const string CanonicalizationAlgorithm = "CanonicalizationAlgorithm";

        /// <summary>
        /// Gets the value for "ComputedKey"
        /// </summary>
        public const string ComputedKey = "ComputedKey";

        /// <summary>
        /// Gets the value for "ComputedKeyAlgorithm"
        /// </summary>
        public const string ComputedKeyAlgorithm = "ComputedKeyAlgorithm";

        /// <summary>
        /// Gets the value for "Context"
        /// </summary>
        public const string Context = "Context";

        /// <summary>
        /// Gets the value for "Code"
        /// </summary>
        public const string Code = "Code";

        /// <summary>
        /// Gets the value for "Delegatable"
        /// </summary>
        public const string Delegatable = "Delegatable";

        /// <summary>
        /// Gets the value for "DelegateTo"
        /// </summary>
        public const string DelegateTo = "DelegateTo";

        /// <summary>
        /// Gets the value for "EncryptionAlgorithm"
        /// </summary>
        public const string EncryptionAlgorithm = "EncryptionAlgorithm";

        /// <summary>
        /// Gets the value for "EncryptWith"
        /// </summary>
        public const string EncryptWith = "EncryptWith";

        /// <summary>
        /// Gets the value for "Entropy"
        /// </summary>
        public const string Entropy = "Entropy";

        /// <summary>
        /// Gets the value for "Expires"
        /// </summary>
        public const string Expires = "Expires";

        /// <summary>
        /// Gets the value for "Forwardable"
        /// </summary>
        public const string Forwardable = "Forwardable";

        /// <summary>
        /// Gets the value for "IssuedTokens"
        /// </summary>
        public const string IssuedTokens = "IssuedTokens";

        /// <summary>
        /// Gets the value for "Issuer"
        /// </summary>
        public const string Issuer = "Issuer";

        /// <summary>
        /// Gets the value for "KeySize"
        /// </summary>
        public const string KeySize = "KeySize";

        /// <summary>
        /// Gets the value for "KeyType"
        /// </summary>
        public const string KeyType = "KeyType";

        /// <summary>
        /// Gets the value for "KeyWrapAlgorithm"
        /// </summary>
        public const string KeyWrapAlgorithm = "KeyWrapAlgorithm";

        /// <summary>
        /// Gets the value for "Lifetime"
        /// </summary>
        public const string Lifetime = "Lifetime";

        /// <summary>
        /// Gets the value for "OnBehalfOf"
        /// </summary>
        public const string OnBehalfOf = "OnBehalfOf";

        /// <summary>
        /// Gets the value for "Participant"
        /// </summary>
        public const string Participant = "Participant";

        /// <summary>
        /// Gets the value for "Participants"
        /// </summary>
        public const string Participants = "Participants";

        /// <summary>
        /// Gets the value for "Primary"
        /// </summary>
        public const string Primary = "Primary";

        /// <summary>
        /// Gets the value for "ProofEncryption"
        /// </summary>
        public const string ProofEncryption = "ProofEncryption";

        /// <summary>
        /// Gets the value for "Reason"
        /// </summary>
        public const string Reason = "Reason";

        /// <summary>
        /// Gets the value for "Renewing"
        /// </summary>
        public const string Renewing = "Renewing";

        /// <summary>
        /// Gets the value for "RenewTarget"
        /// </summary>
        public const string RenewTarget = "RenewTarget";

        /// <summary>
        /// Gets the value for "RequestedAttachedReference"
        /// </summary>
        public const string RequestedAttachedReference = "RequestedAttachedReference";

        /// <summary>
        /// Gets the value for "RequestedProofToken"
        /// </summary>
        public const string RequestedProofToken = "RequestedProofToken";

        /// <summary>
        /// Gets the value for "RequestedSecurityToken"
        /// </summary>
        public const string RequestedSecurityToken = "RequestedSecurityToken";

        /// <summary>
        /// Gets the value for "RequestedUnattachedReference"
        /// </summary>
        public const string RequestedUnattachedReference = "RequestedUnattachedReference";

        /// <summary>
        /// Gets the value for "RequestSecurityToken"
        /// </summary>
        public const string RequestSecurityToken = "RequestSecurityToken";

        /// <summary>
        /// Gets the value for "RequestSecurityTokenResponse"
        /// </summary>
        public const string RequestSecurityTokenResponse = "RequestSecurityTokenResponse";

        /// <summary>
        /// Gets the value for "RequestSecurityTokenResponseCollection"
        /// </summary>
        public const string RequestSecurityTokenResponseCollection = "RequestSecurityTokenResponseCollection";

        /// <summary>
        /// Gets the value for "RequestType"
        /// </summary>
        public const string RequestType = "RequestType";

        /// <summary>
        /// Gets the value for "SecondaryParameters"
        /// </summary>
        public const string SecondaryParameters = "SecondaryParameters";

        /// <summary>
        /// Gets the value for "SignatureAlgorithm"
        /// </summary>
        public const string SignatureAlgorithm = "SignatureAlgorithm";

        /// <summary>
        /// Gets the value for "SignChallenge"
        /// </summary>
        public const string SignChallenge = "SignChallenge";

        /// <summary>
        /// Gets the value for "SignWith"
        /// </summary>
        public const string SignWith = "SignWith";

        /// <summary>
        /// Gets the value for "Status"
        /// </summary>
        public const string Status = "Status";

        /// <summary>
        /// Gets the value for "TokenType"
        /// </summary>
        public const string TokenType = "TokenType";

        /// <summary>
        /// Gets the value for "UseKey"
        /// </summary>
        public const string UseKey = "UseKey";

        /// <summary>
        /// Gets the value for "ValidateTarget"
        /// </summary>
        public const string ValidateTarget = "ValidateTarget";

        /// <summary>
        /// Gets the value for "Value"
        /// </summary>
        public const string Value = "Value";
    }
}
