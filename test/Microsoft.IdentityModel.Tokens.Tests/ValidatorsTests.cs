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
using System.IdentityModel.Tokens.Jwt;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class ValidatorsTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("AudienceDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Audience(List<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters, ExpectedException ee)
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

        public static TheoryData<List<string>, SecurityToken, TokenValidationParameters, ExpectedException> AudienceDataSet
        {
            get
            {
                List<string> audiences = new List<string> { "", IdentityUtilities.DefaultAudience };
                List<string> invalidAudiences = new List<string> { "", IdentityUtilities.NotDefaultAudience };
                Dictionary<string, object> properties = new Dictionary<string, object> { { "InvalidAudience", TestUtilities.SerializeAsSingleCommaDelimitedString(audiences) } };

                var dataset = new TheoryData<List<string>, SecurityToken, TokenValidationParameters, ExpectedException>();

                dataset.Add(null, null, null, ExpectedException.ArgumentNullException());
                dataset.Add(null, null, new TokenValidationParameters { ValidateAudience = false }, ExpectedException.NoExceptionExpected);
                dataset.Add(null, null, new TokenValidationParameters(), ExpectedException.SecurityTokenInvalidAudienceException("IDX10207:"));
                dataset.Add(audiences, null, new TokenValidationParameters(), ExpectedException.SecurityTokenInvalidAudienceException("IDX10208:", propertiesExpected: properties));
                dataset.Add(audiences, null, new TokenValidationParameters { ValidAudience = IdentityUtilities.NotDefaultAudience }, ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:", propertiesExpected: properties));
                dataset.Add(audiences, null, new TokenValidationParameters { ValidAudiences = invalidAudiences }, ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:", propertiesExpected: properties));
                dataset.Add(audiences, null, new TokenValidationParameters { ValidAudience = IdentityUtilities.DefaultAudience }, ExpectedException.NoExceptionExpected);
                dataset.Add(audiences, null, new TokenValidationParameters { ValidAudiences = audiences }, ExpectedException.NoExceptionExpected);

                return dataset;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("IssuerDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Issuer(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters, ExpectedException ee)
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

        public static TheoryData<string, SecurityToken, TokenValidationParameters, ExpectedException> IssuerDataSet
        {
            get
            {
                List<string> issuers = new List<string> { "", IdentityUtilities.DefaultIssuer };
                List<string> invalidIssuers = new List<string> { "", IdentityUtilities.NotDefaultIssuer };
                Dictionary<string, object> properties = new Dictionary<string, object> { { "InvalidIssuer", IdentityUtilities.DefaultIssuer } };

                var dataset = new TheoryData<string, SecurityToken, TokenValidationParameters, ExpectedException>();

                dataset.Add(null, null, null, ExpectedException.ArgumentNullException());
                dataset.Add(null, null, new TokenValidationParameters { ValidateIssuer = false }, ExpectedException.NoExceptionExpected);
                dataset.Add(null, null, new TokenValidationParameters(), ExpectedException.SecurityTokenInvalidIssuerException("IDX10211:", propertiesExpected: new Dictionary<string, object> { { "InvalidIssuer", null } }));
                dataset.Add(IdentityUtilities.DefaultIssuer, null, new TokenValidationParameters(), ExpectedException.SecurityTokenInvalidIssuerException("IDX10204:", propertiesExpected: properties));
                dataset.Add(IdentityUtilities.DefaultIssuer, null, new TokenValidationParameters { ValidIssuer = IdentityUtilities.NotDefaultIssuer }, ExpectedException.SecurityTokenInvalidIssuerException("IDX10205:", propertiesExpected: properties));
                dataset.Add(IdentityUtilities.DefaultIssuer, null, new TokenValidationParameters { ValidIssuers = invalidIssuers }, ExpectedException.SecurityTokenInvalidIssuerException("IDX10205:", propertiesExpected: properties));
                dataset.Add(IdentityUtilities.DefaultIssuer, null, new TokenValidationParameters { ValidIssuer = IdentityUtilities.DefaultIssuer }, ExpectedException.NoExceptionExpected);
                dataset.Add(IdentityUtilities.DefaultIssuer, null, new TokenValidationParameters { ValidIssuers = issuers }, ExpectedException.NoExceptionExpected);

                return dataset;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("LifeTimeDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Lifetime(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters, ExpectedException ee)
        {
            try
            {
                Validators.ValidateLifetime(notBefore, expires, securityToken, validationParameters);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<DateTime?, DateTime?, SecurityToken, TokenValidationParameters, ExpectedException> LifeTimeDataSet
        {
            get
            {
                List<string> issuers = new List<string> { "", IdentityUtilities.DefaultIssuer };
                List<string> invalidIssuers = new List<string> { "", IdentityUtilities.NotDefaultIssuer };
                DateTime? notBefore;
                DateTime? expires;

                //                           notbefore  expires    
                var dataset = new TheoryData<DateTime?, DateTime?, SecurityToken, TokenValidationParameters, ExpectedException>();

                dataset.Add(null, null, null, null, ExpectedException.ArgumentNullException());
                dataset.Add(null, null, null, new TokenValidationParameters { ValidateLifetime = false }, ExpectedException.NoExceptionExpected);
                dataset.Add(null, null, null, new TokenValidationParameters(), ExpectedException.SecurityTokenNoExpirationException("IDX10225:"));

                notBefore = EpochTime.DateTime(EpochTime.GetIntDate((DateTime.UtcNow + TimeSpan.FromHours(1)).ToUniversalTime()));
                expires = EpochTime.DateTime(EpochTime.GetIntDate(DateTime.UtcNow.ToUniversalTime()));
                dataset.Add(notBefore, expires, null, new TokenValidationParameters(), ExpectedException.SecurityTokenInvalidLifetimeException("IDX10224:", propertiesExpected: new Dictionary<string, object> { { "NotBefore", notBefore }, { "Expires", expires } }));

                notBefore = EpochTime.DateTime(EpochTime.GetIntDate((DateTime.UtcNow + TimeSpan.FromHours(1)).ToUniversalTime()));
                expires = EpochTime.DateTime(EpochTime.GetIntDate((DateTime.UtcNow + TimeSpan.FromHours(2)).ToUniversalTime()));
                dataset.Add(notBefore, expires, null, new TokenValidationParameters(), ExpectedException.SecurityTokenNotYetValidException("IDX10222:", propertiesExpected: new Dictionary<string, object> { { "NotBefore", notBefore } }));

                dataset.Add(DateTime.UtcNow - TimeSpan.FromHours(2), DateTime.UtcNow - TimeSpan.FromHours(1), null, new TokenValidationParameters(), ExpectedException.SecurityTokenExpiredException("IDX10223:"));
                dataset.Add(DateTime.UtcNow - TimeSpan.FromHours(2), DateTime.UtcNow + TimeSpan.FromHours(1), null, new TokenValidationParameters(), ExpectedException.NoExceptionExpected);

                // clock skew, positive then negative
                dataset.Add(DateTime.UtcNow + TimeSpan.FromMinutes(2), DateTime.UtcNow + TimeSpan.FromHours(1), null, new TokenValidationParameters{ ClockSkew = TimeSpan.FromMinutes(5) }, ExpectedException.NoExceptionExpected);
                dataset.Add(DateTime.UtcNow - TimeSpan.FromMinutes(2), DateTime.UtcNow - TimeSpan.FromMinutes(1), null, new TokenValidationParameters{ ClockSkew = TimeSpan.FromMinutes(5) }, ExpectedException.NoExceptionExpected);

                notBefore = EpochTime.DateTime(EpochTime.GetIntDate((DateTime.UtcNow + TimeSpan.FromMinutes(6)).ToUniversalTime()));
                expires = EpochTime.DateTime(EpochTime.GetIntDate((DateTime.UtcNow + TimeSpan.FromHours(1)).ToUniversalTime()));
                dataset.Add(notBefore, expires, null, new TokenValidationParameters{ ClockSkew = TimeSpan.FromMinutes(5) }, ExpectedException.SecurityTokenNotYetValidException("IDX10222:", propertiesExpected: new Dictionary<string, object> { { "NotBefore", notBefore } }));

                dataset.Add(DateTime.UtcNow - TimeSpan.FromHours(2), DateTime.UtcNow - TimeSpan.FromMinutes(6), null, new TokenValidationParameters{ ClockSkew = TimeSpan.FromMinutes(5) }, ExpectedException.SecurityTokenExpiredException("IDX10223:"));

                return dataset;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SecurityKeyDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters, ExpectedException ee)
        {
            try
            {
                Validators.ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<SecurityKey, SecurityToken, TokenValidationParameters, ExpectedException> SecurityKeyDataSet
        {
            get
            {
                var dataset = new TheoryData<SecurityKey, SecurityToken, TokenValidationParameters, ExpectedException>();

                dataset.Add(null, new JwtSecurityToken(), new TokenValidationParameters { ValidateIssuerSigningKey = true }, ExpectedException.ArgumentNullException());
                dataset.Add(KeyingMaterial.SymmetricSecurityKey2_256, null, new TokenValidationParameters { ValidateIssuerSigningKey = true }, ExpectedException.ArgumentNullException());
                dataset.Add(KeyingMaterial.SymmetricSecurityKey2_256, new JwtSecurityToken(), null, ExpectedException.ArgumentNullException());
                dataset.Add(KeyingMaterial.SymmetricSecurityKey2_256, new JwtSecurityToken(), new TokenValidationParameters { ValidateIssuerSigningKey = true }, ExpectedException.NoExceptionExpected);
                dataset.Add(null, new JwtSecurityToken(), new TokenValidationParameters { ValidateIssuerSigningKey = false }, ExpectedException.NoExceptionExpected);
                dataset.Add(KeyingMaterial.SymmetricSecurityKey2_256, null, new TokenValidationParameters { ValidateIssuerSigningKey = false }, ExpectedException.NoExceptionExpected);

                return dataset;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("TokenReplayDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void TokenReplay(string securityToken, DateTime? expirationTime, TokenValidationParameters validationParameters, ExpectedException ee)
        {
            try
            {
                Validators.ValidateTokenReplay(securityToken, expirationTime, validationParameters);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, DateTime?, TokenValidationParameters, ExpectedException> TokenReplayDataSet
        {
            get
            {
                var dataset = new TheoryData<string, DateTime?, TokenValidationParameters, ExpectedException>();

                dataset.Add(null, null, new TokenValidationParameters(), ExpectedException.ArgumentNullException());
                dataset.Add(string.Empty, null, new TokenValidationParameters(), ExpectedException.ArgumentNullException());
                dataset.Add("token", DateTime.UtcNow + TimeSpan.FromDays(1), null, ExpectedException.ArgumentNullException());
                dataset.Add("token", null, new TokenValidationParameters { TokenReplayCache = new TokenReplayCache { AddRetVal = true, FindRetVal = true } }, ExpectedException.SecurityTokenNoExpirationException());
                dataset.Add("token", DateTime.UtcNow + TimeSpan.FromDays(1), new TokenValidationParameters { TokenReplayCache = new TokenReplayCache { AddRetVal = true, FindRetVal = true } }, ExpectedException.SecurityTokenReplayDetected("IDX10228:"));
                dataset.Add("token", DateTime.UtcNow + TimeSpan.FromDays(1), new TokenValidationParameters { TokenReplayCache = new TokenReplayCache { AddRetVal = false, FindRetVal = false } }, ExpectedException.SecurityTokenReplayAddFailed("IDX10229:"));
                dataset.Add("token", DateTime.UtcNow + TimeSpan.FromDays(1), new TokenValidationParameters { TokenReplayCache = new TokenReplayCache { AddRetVal = true, FindRetVal = false } }, ExpectedException.NoExceptionExpected);

                return dataset;
            }
        }

        class TokenReplayCache : ITokenReplayCache
        {
            public bool AddRetVal { get; set; }

            public bool FindRetVal { get; set; }

            public bool TryAdd(string securityToken, DateTime expiresOn)
            {
                return AddRetVal;
            }

            public bool TryFind(string securityToken)
            {
                return FindRetVal;
            }
        }
    }
}
