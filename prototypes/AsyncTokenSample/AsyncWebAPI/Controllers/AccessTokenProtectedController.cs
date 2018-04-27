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

using AsyncCommon;
using Microsoft.IdentityModel.S2S.Tokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Jwt;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace AsyncWebsite.Controllers
{
    public class AccessTokenProtectedController : ApiController
    {
        private JsonWebTokenHandler _jsonWebTokenHandler = new JsonWebTokenHandler();

        [HttpGet]
        public async Task<IEnumerable<string>> ProtectedApi()
        {
            var authorizationHeader = HttpContext.Current.Request.Headers.Get(AuthenticationConstants.AuthorizationHeader);
            string token = null;
            try
            {
                if (authorizationHeader.StartsWith(AuthenticationConstants.BearerWithSpace, StringComparison.OrdinalIgnoreCase))
                    token = authorizationHeader.Substring(AuthenticationConstants.BearerWithSpace.Length).Trim();
                else
                    throw new InvalidOperationException();
            }
            catch (Exception ex)
            {
                return new string[]
                {
                    "Site: AsyncWebsite",
                    $"This exception was thrown during validation: '{ex}'"
                };
            }

            return await ValidateTokenAsync(token);
        }

        /// <summary>
        /// Asynchronously validates the JWS recieved from the AsyncWebsite.
        /// </summary>
        async Task<IEnumerable<string>> ValidateTokenAsync(string payloadToken)
        {
            try
            {
                var tokenValidationParameters = new TokenValidationParameters()
                {
                    ValidAudience = "http://Default.Audience.com",
                    ValidIssuer = "http://Default.Issuer.com",
                    IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                    CryptoProviderFactory = new CryptoProviderFactory()
                    {
                        CustomCryptoProvider = new AsyncCryptoProvider(KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key, KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Algorithm, false)
                    }
                };
                var tokenValidationResult = await _jsonWebTokenHandler.ValidateJWSAsync(payloadToken, tokenValidationParameters).ConfigureAwait(false);
                var jsonWebToken = tokenValidationResult.SecurityToken as JsonWebToken;
                var email = jsonWebToken.Payload.Value<string>(JwtRegisteredClaimNames.Email);

                if (!email.Equals("Bob@contoso.com"))
                    throw new SecurityTokenException("Token does not contain the correct value for the 'email' claim.");

                return new string[] { "Token was validated." };
            }
            catch (Exception ex)
            {
                return new string[]
                {
                    $"Site: 'AsyncWebsite threw: '{ex}'"
                };
            }
        }
    }
}
