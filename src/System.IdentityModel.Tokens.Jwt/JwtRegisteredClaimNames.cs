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

namespace System.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// List of registered claims from different sources
    /// http://tools.ietf.org/html/rfc7519#section-4
    /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    /// </summary>
    public struct JwtRegisteredClaimNames
    {
        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Actort = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Actort;

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Acr = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Acr;

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Amr = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Amr;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Aud = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Aud;

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string AuthTime = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.AuthTime;

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Azp = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Azp;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Birthdate = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Birthdate;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string CHash = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.CHash;

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        /// </summary>
        public const string AtHash = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.AtHash;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Email = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Email;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Exp = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Exp;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Gender = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Gender;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string FamilyName = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.FamilyName;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string GivenName = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.GivenName;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Iat = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Iat;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Iss = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Iss;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Jti = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string NameId = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.NameId;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Nonce = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Nonce;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Nbf = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Nbf;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Prn = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Prn;

        /// <summary>
        /// http://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
        /// </summary>
        public const string Sid = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sid;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Sub = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Typ = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Typ;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string UniqueName = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.UniqueName;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Website = Microsoft.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Website;
    }
}
