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
        // general
        internal const string IDX10000 = "IDX10000: The parameter '{0}' cannot be a 'null' or an empty object.";

        // properties, configuration 
        internal const string IDX10101 = "IDX10101: MaximumTokenSizeInBytes must be greater than zero. value: '{0}'";
        internal const string IDX10104 = "IDX10104: TokenLifetimeInMinutes must be greater than zero. value: '{0}'";

        // token validation
        internal const string IDX10209 = "IDX10209: token has length: '{0}' which is larger than the MaximumTokenSizeInBytes: '{1}'.";
        internal const string IDX10213 = "IDX10213: SecurityTokens must be signed. SecurityToken: '{0}'.";
        internal const string IDX10221 = "IDX10221: Unable to create claims from securityToken, 'issuer' is null or empty.";
        internal const string IDX10230 = "IDX10230: Lifetime validation failed. Delegate returned false, securitytoken: '{0}'.";
        internal const string IDX10231 = "IDX10231: Audience validation failed. Delegate returned false, securitytoken: '{0}'.";

        // SecurityTokenHandler messages
        internal const string IDX10400 = "IDX10400: The '{0}', can only process SecurityTokens of type: '{1}'. The SecurityToken received is of type: '{2}'.";

        internal const string IDX10721 = "IDX10721: Creating SamlSecurityToken: Issuer: '{0}', Audience: '{1}'";

        // NotSupported Exceptions
        internal const string IDX11002 = "IDX11002: This method is not supported to read a 'saml2token' use the method: ReadToken(XmlReader reader, TokenValidationParameters validationParameters).";
        internal const string IDX11003 = "IDX11003: This method is not supported to read a 'samltoken' use the method: ReadToken(XmlReader reader, TokenValidationParameters validationParameters).";
        internal const string IDX11006 = "IDX11006: This method is not supported to read a 'saml2token' use the method: ReadToken(string securityToken, TokenValidationParameters validationParameters).";
        internal const string IDX11007 = "IDX11007: This method is not supported to read a 'samltoken' use the method: ReadToken(string securityToken, TokenValidationParameters validationParameters).";

#pragma warning restore 1591
    }
}
