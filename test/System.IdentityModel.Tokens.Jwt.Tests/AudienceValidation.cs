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
using System.IdentityModel.Tokens.Tests;
using System.Security.Claims;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    public class AudienceValidationTests
    {
        [Fact(DisplayName = "AudienceValidation: Variations")]
        public void Variations()
        {
            List<string> errors = new List<string>();

            RunAudienceVariation(ClaimSets.MultipleAudiences(), IdentityUtilities.DefaultAudiences, errors);

            List<string> audiences = new List<string>();
            audiences.Add(IdentityUtilities.DefaultAudience);
            RunAudienceVariation(ClaimSets.SingleAudience(), audiences, errors);

            TestUtilities.AssertFailIfErrors("AudienceValidation: ", errors);
        }

        private void RunAudienceVariation(IEnumerable<Claim> claims, IList<string> expectedAudiences, IList<string> errors)
        {
            var validationParameters =
                new TokenValidationParameters
                {
                    RequireExpirationTime = false,
                    RequireSignedTokens = false,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                };

            var payload = new JwtPayload(claims: claims);
            var jwtToken = new JwtSecurityToken(new JwtHeader(), payload);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(jwtToken);

            SecurityToken validatedJwt = null;
            var claimsPrincipal = handler.ValidateToken(jwt, validationParameters, out validatedJwt);
            var audiences = (validatedJwt as JwtSecurityToken).Audiences;
            var jwtAudiences = jwtToken.Audiences;

            if (!IdentityComparer.AreEqual<IEnumerable<string>>(audiences, jwtAudiences))
            {
                errors.Add("!IdentityComparer.AreEqual<IEnumerable<string>>(audiences, jwtAudiences)");
            }

            if (!IdentityComparer.AreEqual<IEnumerable<string>>(audiences, expectedAudiences))
            {
                errors.Add("!IdentityComparer.AreEqual<IEnumerable<string>>(audiences, expectedAudiences)");
            }

            ClaimsIdentity identity = claimsPrincipal.Identity as ClaimsIdentity;
            IEnumerable<Claim> audienceClaims = identity.FindAll("aud");

            if (audienceClaims == null)
            {
                errors.Add(@"identity.FindAll(""aud"") == null");
            }
            else
            {
                List<string> auds = new List<string>();
                foreach(var claim in audienceClaims)
                {
                    auds.Add(claim.Value);
                }

                if (!IdentityComparer.AreEqual<IEnumerable<string>>(auds, audiences))
                {
                    errors.Add("!IdentityComparer.AreEqual<IEnumerable<string>>(auds, audiences)");
                }
            }
        }
    }
}
