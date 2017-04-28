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

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// Log messages and codes
    /// </summary>
    internal static class LogMessages
    {
#pragma warning disable 1591

        // SecurityTokenHandler messages
        internal const string IDX10400 = "IDX10400: The '{0}', can only process SecurityTokens of type: '{1}'. The SecurityToken received is of type: '{2}'.";
        internal const string IDX10721 = "IDX10721: Creating SamlSecurityToken: Issuer: '{0}', Audience: '{1}'";

        // SamlSerializer reading
        internal const string IDX11100 = "IDX11100: Saml Only one element of type '{0}' is supported.";
        internal const string IDX11101 = "IDX11101: Saml Unexpected element found '{0}' while reading.";
        internal const string IDX11102 = "IDX11102: Saml An AuthorizationDecisionStatement must have at least one Action.";
        internal const string IDX11103 = "IDX11103: Saml Evidence must have at least one assertion.";
        internal const string IDX11104 = "IDX11104: Saml Name cannot be null or empty.";
        internal const string IDX11105 = "IDX11105: Saml SubjectConformation Name cannot be null or empty.";
        internal const string IDX11106 = "IDX11106: Saml No SubjectConfirmation clauses were specified.";
        internal const string IDX11107 = "IDX11107: Saml A Subject requires a NameIdentifier or ConfirmationMethod";
        internal const string IDX11108 = "IDX11108: Saml AuthorityBinding.AuthorityKind is not well formed. Is should be of the form str:str, it is '{0}'";
        internal const string IDX11109 = "IDX11109: SamlAssertion.Issuer cannont be null or empty when creating claims.";
        internal const string IDX11110 = "IDX11110: The SamlSecurityToken must have a value for its Assertion property.";

#pragma warning restore 1591
    }
}
