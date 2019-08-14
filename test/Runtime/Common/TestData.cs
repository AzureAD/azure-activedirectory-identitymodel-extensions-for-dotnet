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

using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace RuntimeCommon
{
    public static class TestData
    {
        public static string Audience { get => "http://Audience"; }

        public static string AuthenticationType { get => "LocalUser"; }

        public static IDictionary<string, object> ClaimsDictionary
        {
            get => new Dictionary<string, object>
            {
                { ClaimTypes.Country, "USA" },
                { ClaimTypes.NameIdentifier, "Bob" },
                { ClaimTypes.Email, "Bob@contoso.com" },
                { ClaimTypes.GivenName, "Bob" },
                { ClaimTypes.HomePhone, "555.1212" },
                { ClaimTypes.Role, "Developer" },
                { ClaimTypes.StreetAddress, "123AnyWhereStreet/r/nSomeTown/r/nUSA" },
                { ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien" }
            };
        }

        public static List<Claim> Claims
        {
            get => new List<Claim>
            {
                new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.NameIdentifier, "Bob", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.Email, "Bob@contoso.com", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.Role, "Developer", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.StreetAddress, "123AnyWhereStreet/r/nSomeTown/r/nUSA", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien", ClaimValueTypes.String, Issuer, OriginalIssuer),
            };
        }

        public static string Issuer { get => "http://issuer.com"; }

        public static string OriginalIssuer { get => "http://originalIssuer.com"; }

        public static SecurityTokenDescriptor RsaSecurityTokenDescriptor => new SecurityTokenDescriptor
        {
            Audience = Audience,
            Claims = ClaimsDictionary,
            Issuer = Issuer,
            Subject = Subject,
            SigningCredentials = RsaSigningCredentials_2048
        };

        public static SigningCredentials RsaSigningCredentials_2048  => new SigningCredentials(TestKeyMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256);

        public static TokenValidationParameters RsaTokenValidationParameters_2048_Public => new TokenValidationParameters
        {
            IssuerSigningKey = TestKeyMaterial.RsaSecurityKey_2048_Public,
            ValidAudience = Audience,
            ValidIssuer = Issuer
        };

        public static ClaimsIdentity Subject { get => new ClaimsIdentity(Claims, AuthenticationType); }
    }
}
