//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Xunit;

namespace System.IdentityModel.Test
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