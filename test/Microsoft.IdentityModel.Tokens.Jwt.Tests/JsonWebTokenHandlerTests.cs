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

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tests;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Jwt.Tests
{
    public class JsonWebTokenHandlerTests
    {
        [Fact]
        public void CreateJWSAsync()
        {
            var tokenHandler = new JsonWebTokenHandler();
            var signingCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials;

            var payload = new JObject()
            {
                { JwtRegisteredClaimNames.Email, "Bob@contoso.com"},
                { JwtRegisteredClaimNames.GivenName, "Bob"},
                { JwtRegisteredClaimNames.Iss, "http://Default.Issuer.com" },
                { JwtRegisteredClaimNames.Aud, "http://Default.Audience.com" },
                { JwtRegisteredClaimNames.Nbf, "2017-03-18T18:33:37.080Z" },
                { JwtRegisteredClaimNames.Exp, "2021-03-17T18:33:37.080Z" }
            };

            var accessToken = tokenHandler.CreateToken(payload, signingCredentials);
        }

        [Fact]
        public void ValidateJWSAsync()
        {
            IdentityModelEventSource.ShowPII = true;
            var tokenHandler = new JsonWebTokenHandler();
            var accessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgiLCJ0eXAiOiJKV1QifQ.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwibmJmIjoiMjAxNy0wMy0xOFQxODozMzozNy4wODBaIiwiZXhwIjoiMjAyMS0wMy0xN1QxODozMzozNy4wODBaIn0.JeUhB3r_BBiImzySSQ5qBO0HqE6-mkW5vQDr6Yocfu7pLluAxS854PXMXuIOlbiV9TCQAUDw8UjaxryaCEFRDqfAxl_nfMXn4K7iRc691ft9TL1qw9y40cjc16McBHc-lpu1F0lnXYNW9vGdxkQHpSQLDsVxAzyKXNypLYyNPwlZJp_G1Gx7fuVxOQOyMgZ-wcTx1c-mQmozLVQJ6r8-XC4LLVVotwjTQqZzVRhyPoMFHP_6auPA77P0JaiFnl3KMsASDmE3EMF5iOLBWzR0XqHLB9HNqdp0cVQQroSxvU7YJoE9jVFX6KfHusg5blsudlR0v4vv-1rhL9uFqRDNfw";
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = "http://Default.Audience.com",
                ValidIssuer = "http://Default.Issuer.com",
                IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
            };
            var tokenValidationResult = tokenHandler.ValidateToken(accessToken, tokenValidationParameters);
            var jsonWebToken = tokenValidationResult.SecurityToken as JsonWebToken;
            var email = jsonWebToken.Payload.Value<string>(JwtRegisteredClaimNames.Email);

            if (!email.Equals("Bob@contoso.com"))
                throw new SecurityTokenException("Token does not contain the correct value for the 'email' claim.");
        }
    }
}
