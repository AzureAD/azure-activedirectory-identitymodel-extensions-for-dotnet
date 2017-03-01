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

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Threading;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class End2EndTests
    {
        [Fact]
        public void OpenIdConnect()
        {
            SigningCredentials rsaSigningCredentials =
                new SigningCredentials(
                    KeyingMaterial.RsaSecurityKey_2048,
                    SecurityAlgorithms.RsaSha256Signature
                    );

            //"<RSAKeyValue><Modulus>rCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
            OpenIdConnectConfiguration configuration = OpenIdConnectConfigurationRetriever.GetAsync(OpenIdConfigData.OpenIdConnectMetadataFileEnd2End, new FileDocumentRetriever(), CancellationToken.None).Result;
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken = 
                tokenHandler.CreateJwtSecurityToken(
                    configuration.Issuer,
                    IdentityUtilities.DefaultAudience,
                    ClaimSets.DefaultClaimsIdentity,
                    DateTime.UtcNow,
                    DateTime.UtcNow + TimeSpan.FromHours(1),
                    DateTime.UtcNow + TimeSpan.FromHours(1),
                    rsaSigningCredentials);

            tokenHandler.WriteToken(jwtToken);

            TokenValidationParameters validationParameters =
                new TokenValidationParameters
                {
                    IssuerSigningKeys = configuration.SigningKeys,
                    ValidAudience = IdentityUtilities.DefaultAudience,
                    ValidIssuer = configuration.Issuer,
                };

            SecurityToken securityToken = null;
            tokenHandler.ValidateToken(jwtToken.RawData, validationParameters, out securityToken);
        }
    }
}
