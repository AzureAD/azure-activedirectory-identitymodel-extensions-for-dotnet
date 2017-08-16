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
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens.Saml;
using Xunit;

namespace Microsoft.IdentityModel.Tests
{
    // Checks to make sure that Claims, ClaimsIdentities, and ClaimsPrincipals with different properties are found 
    // to be unequal by the IdentityComparer.AreEqual() method.
    public class IdentityComparerTests
    {       
        [Fact]
        public void CompareClaimsTest()
        {
            // Base claim that all tests will compare against.
            var originalClaim = new Claim(ClaimTypes.Country, Default.Country, ClaimValueTypes.String, Default.Issuer, Default.OriginalIssuer);

            var claimsToCompare = new List<Claim>()
            {    
                // Claim with different value for 'type'
                new Claim(Guid.NewGuid().ToString(), Default.Country, ClaimValueTypes.String, Default.Issuer, Default.OriginalIssuer),
                // Claim with different value for 'value'
                new Claim(ClaimTypes.Country, Guid.NewGuid().ToString(), ClaimValueTypes.String, Default.Issuer, Default.OriginalIssuer),
                // Claim with different value for 'valueType'
                new Claim(ClaimTypes.Country, Default.Country, Guid.NewGuid().ToString(), Default.Issuer, Default.OriginalIssuer),
                // Claim with different value for 'issuer'
                new Claim(ClaimTypes.Country, Default.Country, ClaimValueTypes.String, Guid.NewGuid().ToString(), Default.OriginalIssuer),
                // Claim with different value for 'originalIssuer'
                new Claim(ClaimTypes.Country, Default.Country, ClaimValueTypes.String, Default.Issuer, Guid.NewGuid().ToString()),
            };

            var context = new CompareContext();
            foreach (var otherClaim in claimsToCompare)
            {
                IdentityComparer.AreEqual(originalClaim, otherClaim, context);
            }

            // Lists all the properties which should have been marked as different in the compareContext.
            var propertiesToTest = new string[] { "Type", "Value", "ValueType", "Issuer", "OriginalIssuer"};

            // Create a separate context to keep track of any properties which were not marked as different (even though they should have been).
            var failureContext = new CompareContext();
            foreach (var property in propertiesToTest)
            {
                if(!context.Diffs.Contains(property + ":"))
                {
                    failureContext.Diffs.Add("IdentityComparer should have found a difference in propertyInfo.Name: " + property);
                }
            }

            TestUtilities.AssertFailIfErrors(failureContext);
        }

        [Fact]
        public void CompareClaimsWithPropertiesTest()
        {
            // Base claim that all tests will compare against.
            var originalClaim = new Claim(ClaimTypes.Country, Default.Country, ClaimValueTypes.String, Default.Issuer, Default.OriginalIssuer);
            originalClaim.Properties[ClaimProperties.SamlNameIdentifierFormat] = Default.NameIdentifierFormat;
            originalClaim.Properties[ClaimProperties.SamlNameIdentifierNameQualifier] = Default.NameQualifier;

            // Claim with the same property names but different values for them
            var claim1 = new Claim(ClaimTypes.Country, Default.Country, ClaimValueTypes.String, Default.Issuer, Default.OriginalIssuer);
            claim1.Properties[ClaimProperties.SamlNameIdentifierFormat] = Guid.NewGuid().ToString();
            claim1.Properties[ClaimProperties.SamlNameIdentifierNameQualifier] = Guid.NewGuid().ToString();

            // Claim with one property that's the same but another that's different.
            var claim2 = new Claim(ClaimTypes.Country, Default.Country, ClaimValueTypes.String, Default.Issuer, Default.OriginalIssuer);
            claim2.Properties[ClaimProperties.SamlNameIdentifierFormat] = Default.NameIdentifierFormat;
            claim2.Properties[ClaimProperties.SamlNameIdentifierNameQualifier] = Guid.NewGuid().ToString();

            // Claim with the same number of properties as the original (but different names and values).
            var claim3 = new Claim(ClaimTypes.Country, Default.Country, ClaimValueTypes.String, Default.Issuer, Default.OriginalIssuer);
            claim3.Properties[Guid.NewGuid().ToString()] = Guid.NewGuid().ToString();
            claim3.Properties[Guid.NewGuid().ToString()] = Guid.NewGuid().ToString();

            // Claim with only one property (that's shared with the original).
            var claim4 = new Claim(ClaimTypes.Country, Default.Country, ClaimValueTypes.String, Default.Issuer, Default.OriginalIssuer);
            claim4.Properties[ClaimProperties.SamlNameIdentifierFormat] = Default.NameIdentifierFormat;

            // Claim with no properties.
            var claim5 = new Claim(ClaimTypes.Country, Default.Country, ClaimValueTypes.String, Default.Issuer, Default.OriginalIssuer);

            var claimsToCompare = new List<Claim>()
            {    
                claim1, claim2, claim3, claim4, claim5,
            };

            var context = new CompareContext();
            foreach (var otherClaim in claimsToCompare)
            {
                IdentityComparer.AreEqual(originalClaim, otherClaim, context);
            }

            // Make sure that the properties don't match for all 5 of the claims in the list above.
            Assert.True(context.Diffs.Count(s => s == "Properties:") == 5);
        }
    }
}
