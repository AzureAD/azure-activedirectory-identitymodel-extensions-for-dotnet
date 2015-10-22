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
using Xunit;

namespace System.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class ValidatorsTests
    {
        [Fact(DisplayName = "ValidatorsTests: AudienceValidator")]
        public void Audience()
        {
            List<string> audiences = new List<string> { "", IdentityUtilities.DefaultAudience };
            List<string> invalidAudiences = new List<string> { "", IdentityUtilities.NotDefaultAudience };

            RunAudienceTest(audiences: null, securityToken: null, validationParameters: null, ee: ExpectedException.ArgumentNullException());
            RunAudienceTest(audiences: null, securityToken: null, validationParameters: new TokenValidationParameters { ValidateAudience = false }, ee: ExpectedException.NoExceptionExpected);
            RunAudienceTest(audiences: null, securityToken: null, validationParameters: new TokenValidationParameters(), ee: ExpectedException.SecurityTokenInvalidAudienceException(substringExpected: "IDX10214:"));
            RunAudienceTest(audiences: audiences, securityToken: null, validationParameters: new TokenValidationParameters(), ee: ExpectedException.SecurityTokenInvalidAudienceException(substringExpected: "IDX10208:"));
            RunAudienceTest(audiences: audiences, securityToken: null, validationParameters: new TokenValidationParameters { ValidAudience = IdentityUtilities.NotDefaultAudience}, ee: ExpectedException.SecurityTokenInvalidAudienceException(substringExpected: "IDX10214:"));
            RunAudienceTest(audiences: audiences, securityToken: null, validationParameters: new TokenValidationParameters { ValidAudiences = invalidAudiences }, ee: ExpectedException.SecurityTokenInvalidAudienceException(substringExpected: "IDX10214:"));
            RunAudienceTest(audiences: audiences, securityToken: null, validationParameters: new TokenValidationParameters { ValidAudience = IdentityUtilities.DefaultAudience }, ee: ExpectedException.NoExceptionExpected);
            RunAudienceTest(audiences: audiences, securityToken: null, validationParameters: new TokenValidationParameters { ValidAudiences = audiences }, ee: ExpectedException.NoExceptionExpected);
        }

        private void RunAudienceTest(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters, ExpectedException ee)
        {
            try
            {
                Validators.ValidateAudience(audiences, securityToken, validationParameters);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        [Fact(DisplayName = "ValidatorsTests: IssuerValidator")]
        public void Issuer()
        {
            List<string> issuers = new List<string> { "", IdentityUtilities.DefaultIssuer };
            List<string> invalidIssuers = new List<string> { "", IdentityUtilities.NotDefaultIssuer };

            RunIssuerTest(issuer: null, securityToken: null, validationParameters: null, ee: ExpectedException.ArgumentNullException());
            RunIssuerTest(issuer: null, securityToken: null, validationParameters: new TokenValidationParameters { ValidateIssuer = false }, ee: ExpectedException.NoExceptionExpected);
            RunIssuerTest(issuer: null, securityToken: null, validationParameters: new TokenValidationParameters(), ee: ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10211:"));
            RunIssuerTest(issuer: IdentityUtilities.DefaultIssuer, securityToken: null, validationParameters: new TokenValidationParameters(), ee: ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10204:"));
            RunIssuerTest(issuer: IdentityUtilities.DefaultIssuer, securityToken: null, validationParameters: new TokenValidationParameters { ValidIssuer = IdentityUtilities.NotDefaultIssuer }, ee: ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205:"));
            RunIssuerTest(issuer: IdentityUtilities.DefaultIssuer, securityToken: null, validationParameters: new TokenValidationParameters { ValidIssuers = invalidIssuers }, ee: ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205:"));
            RunIssuerTest(issuer: IdentityUtilities.DefaultIssuer, securityToken: null, validationParameters: new TokenValidationParameters { ValidIssuer = IdentityUtilities.DefaultIssuer }, ee: ExpectedException.NoExceptionExpected);
            RunIssuerTest(issuer: IdentityUtilities.DefaultIssuer, securityToken: null, validationParameters: new TokenValidationParameters { ValidIssuers = issuers }, ee: ExpectedException.NoExceptionExpected);
        }

        private void RunIssuerTest(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters, ExpectedException ee)
        {
            try
            {
                Validators.ValidateIssuer(issuer, securityToken, validationParameters);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        [Fact(DisplayName = "ValidatorsTests: LifetimeValidator")]
        public void Lifetime()
        {
            RunLifetimeTest(expires: null, notBefore: null, securityToken: null, validationParameters: null, ee: ExpectedException.ArgumentNullException());
            RunLifetimeTest(expires: null, notBefore: null, securityToken: null, validationParameters: new TokenValidationParameters { ValidateLifetime = false }, ee: ExpectedException.NoExceptionExpected);
            RunLifetimeTest(expires: null, notBefore: null, securityToken: null, validationParameters: new TokenValidationParameters { }, ee: ExpectedException.SecurityTokenNoExpirationException(substringExpected: "IDX10225:"));
            RunLifetimeTest(expires: DateTime.UtcNow, notBefore: DateTime.UtcNow + TimeSpan.FromHours(1), securityToken: null, validationParameters: new TokenValidationParameters { }, ee: ExpectedException.SecurityTokenInvalidLifetimeException(substringExpected: "IDX10224:"));
            RunLifetimeTest(expires: DateTime.UtcNow + TimeSpan.FromHours(2), notBefore: DateTime.UtcNow + TimeSpan.FromHours(1), securityToken: null, validationParameters: new TokenValidationParameters { }, ee: ExpectedException.SecurityTokenNotYetValidException(substringExpected: "IDX10222:"));
            RunLifetimeTest(expires: DateTime.UtcNow - TimeSpan.FromHours(1), notBefore: DateTime.UtcNow - TimeSpan.FromHours(2), securityToken: null, validationParameters: new TokenValidationParameters { }, ee: ExpectedException.SecurityTokenExpiredException(substringExpected: "IDX10223:"));
            RunLifetimeTest(expires: DateTime.UtcNow, notBefore: DateTime.UtcNow - TimeSpan.FromHours(2), securityToken: null, validationParameters: new TokenValidationParameters { }, ee: ExpectedException.NoExceptionExpected);
        }

        private void RunLifetimeTest(DateTime? expires, DateTime? notBefore, SecurityToken securityToken, TokenValidationParameters validationParameters, ExpectedException ee)
        {
            try
            {
                Validators.ValidateLifetime(notBefore: notBefore, expires: expires, securityToken: securityToken, validationParameters: validationParameters);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        [Fact(DisplayName = "ValidatorsTests: SecurityKeyValidator")]
        public void SecurityKey()
        {
        }
    }
}
