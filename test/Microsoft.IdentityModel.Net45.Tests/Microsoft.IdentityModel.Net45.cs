// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

/// <summary>
/// This set of tests if for ensuring the net45 targets are not broken.
/// </summary>
namespace Microsoft.IdentityModel.Net45.Tests
{
    [TestClass]
    public class Net45Tests
    {
        [TestMethod]
        public void TestJwtTokenCreationAndValidation()
        {
            IdentityModelEventSource.ShowPII = true;
            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();
            var jwt = handler.CreateEncodedJwt(Default.AsymmetricSignSecurityTokenDescriptor(null));
            var jwtToken = new JwtSecurityToken(jwt) { SigningKey = Default.AsymmetricSigningKey };
            SecurityToken token = null;
            handler.ValidateToken(jwt, Default.AsymmetricSignTokenValidationParameters, out token);
            var context = new CompareContext
            {
                PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
                {
                    { typeof(JwtHeader), new List<string> { "Item" } },
                    { typeof(JwtPayload), new List<string> { "Item" } }
                }
            };

            if (!IdentityComparer.AreJwtSecurityTokensEqual(jwtToken, token as JwtSecurityToken, context))
                TestUtilities.AssertFailIfErrors("TestJwtTokenCreationAndValidation", context.Diffs);
        }
    }
}
