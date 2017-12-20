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
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.IdentityModel.Protocols.Extensions.OldVersion;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Xunit;

using LifeTime4x = System.IdentityModel.Protocols.WSTrust.Lifetime;
using SamlAccessDecision4x = System.IdentityModel.Tokens.SamlAccessDecision;
using SamlAction4x = System.IdentityModel.Tokens.SamlAction;
using SamlAdvice4x = System.IdentityModel.Tokens.SamlAdvice;
using SamlAssertion4x = System.IdentityModel.Tokens.SamlAssertion;
using SamlAttribute4x = System.IdentityModel.Tokens.SamlAttribute;
using SamlAttributeStatement4x = System.IdentityModel.Tokens.SamlAttributeStatement;
using SamlAudienceRestrictionCondition4x = System.IdentityModel.Tokens.SamlAudienceRestrictionCondition;
using SamlAuthenticationStatement4x = System.IdentityModel.Tokens.SamlAuthenticationStatement;
using SamlAuthorityBinding4x = System.IdentityModel.Tokens.SamlAuthorityBinding;
using SamlAuthorizationDecisionClaimResource4x = System.IdentityModel.Tokens.SamlAuthorizationDecisionClaimResource;
using SamlAuthorizationDecisionStatement4x = System.IdentityModel.Tokens.SamlAuthorizationDecisionStatement;
using SamlCondition4x = System.IdentityModel.Tokens.SamlCondition;
using SamlConditions4x = System.IdentityModel.Tokens.SamlConditions;
using SamlDoNotCacheCondition4x = System.IdentityModel.Tokens.SamlDoNotCacheCondition;
using SamlEvidence4x = System.IdentityModel.Tokens.SamlEvidence;
using SamlSecurityToken4x = System.IdentityModel.Tokens.SamlSecurityToken;
using SamlSecurityTokenHandler4x = System.IdentityModel.Tokens.SamlSecurityTokenHandler;
using SamlStatement4x = System.IdentityModel.Tokens.SamlStatement;
using SamlSubject4x = System.IdentityModel.Tokens.SamlSubject;
using SecurityToken4x = System.IdentityModel.Tokens.SecurityToken;
using SecurityTokenDescriptor4x = System.IdentityModel.Tokens.SecurityTokenDescriptor;
using SigningCredentials4x = System.IdentityModel.Tokens.SigningCredentials;
using TokenValidationParameters4x = System.IdentityModel.Tokens.TokenValidationParameters;
using X509SigningCredentials4x = System.IdentityModel.Tokens.X509SigningCredentials;
using X509SecurityKey4x = System.IdentityModel.Tokens.X509SecurityKey;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.CrossVersionTokenValidation.Tests
{
    public class SamlCrossVersionTokenValidationTests
    {
        [Theory, MemberData(nameof(CreateTokenCrossVerstionTheoryData))]
        public void CreateTokenCrossVerstionTest(TokenCrossTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateTokenCrossVerstionTest", theoryData);
            var token4x = CrossVersionTokenValidationTestsData.GetSamlSecurityToken4x(theoryData.TokenDescriptor4x);
            var samlHandler5x = new Microsoft.IdentityModel.Tokens.Saml.SamlSecurityTokenHandler();
            var token5x = samlHandler5x.CreateToken(theoryData.TokenDescriptor5x);

            AreSamlTokensEqual(token4x, token5x, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<TokenCrossTheoryData> CreateTokenCrossVerstionTheoryData
        {
            get
            {
                var defaultClaimsIdentity = new ClaimsIdentity(Default.SamlClaims);
                var notBefore = DateTime.UtcNow;
                var expires = notBefore + TimeSpan.FromDays(1);
                return new TheoryData<TokenCrossTheoryData>
                {
                    new TokenCrossTheoryData
                    {
                        TokenDescriptor4x = new SecurityTokenDescriptor4x
                        {
                            AppliesToAddress = Default.Audience,
                            Lifetime = new LifeTime4x(notBefore, expires),
                            SigningCredentials = new SigningCredentials4x(new X509SecurityKey4x(KeyingMaterial.CertSelfSigned2048_SHA256), SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest),
                            Subject = defaultClaimsIdentity,
                            TokenIssuerName = Default.Issuer,
                        },
                        TokenDescriptor5x = new SecurityTokenDescriptor
                        {
                            Audience = Default.Audience,
                            NotBefore = notBefore,
                            Expires = expires,
                            Issuer = Default.Issuer,
                            SigningCredentials = new SigningCredentials(KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256, SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256),
                            Subject = defaultClaimsIdentity
                        }
                    },
                    new TokenCrossTheoryData
                    {
                        TokenDescriptor4x = new SecurityTokenDescriptor4x
                        {
                            AppliesToAddress = Default.Audience,
                            Lifetime = new LifeTime4x(notBefore, expires),
                            Subject = AuthenticationClaimsIdentity,
                            TokenIssuerName = Default.Issuer,
                        },
                        TokenDescriptor5x = new SecurityTokenDescriptor
                        {
                            Audience = Default.Audience,
                            NotBefore = notBefore,
                            Expires = expires,
                            Issuer = Default.Issuer,
                            Subject = AuthenticationClaimsIdentity
                        }
                    }
                };
            }
        }

        [Theory, MemberData(nameof(CreateClaimsPrincipalCrossVersionTestTheoryData))]
        public void CreateClaimsPrincipalCrossVersionTest(ClaimsPrincipalTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateClaimsPrincipalCrossVersionTest", theoryData);
            var tvp5x = new TokenValidationParameters();

            PropertyInfo[] propertyInfos = typeof(SharedTokenValidationParameters).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
            foreach (PropertyInfo propertyInfo in propertyInfos)
            {
                if (propertyInfo.GetMethod != null)
                {
                    object val = propertyInfo.GetValue(theoryData.TokenValidationParameters, null);
                    PropertyInfo tvp5xPropertyInfo = typeof(TokenValidationParameters).GetProperty(propertyInfo.Name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
                    tvp5xPropertyInfo.SetValue(tvp5x, val);
                }
            }

            if (theoryData.X509Certificate != null)
                tvp5x.IssuerSigningKey = new X509SecurityKey(theoryData.X509Certificate);

            var claimsPrincipal4x = CrossVersionTokenValidationTestsData.GetSamlClaimsPrincipal4x(theoryData.Token, theoryData.TokenValidationParameters, theoryData.X509Certificate, out SecurityToken4x validateToken4x);
            var claimsPrincipal5x = new Microsoft.IdentityModel.Tokens.Saml.SamlSecurityTokenHandler().ValidateToken(theoryData.Token, tvp5x, out SecurityToken validateToken5x);

            IdentityComparer.AreClaimsPrincipalsEqual(claimsPrincipal4x, claimsPrincipal5x, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ClaimsPrincipalTheoryData> CreateClaimsPrincipalCrossVersionTestTheoryData
        {
            get
            {
                var defaultClaimsIdentity = new ClaimsIdentity(Default.SamlClaims);
                var notBefore = DateTime.UtcNow;
                var expires = notBefore + TimeSpan.FromDays(1);
                var tokenDescriptor4x = new SecurityTokenDescriptor4x
                {
                    AppliesToAddress = Default.Audience,
                    Lifetime = new LifeTime4x(notBefore, expires),
                    SigningCredentials = new X509SigningCredentials4x(KeyingMaterial.DefaultCert_2048, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest),
                    Subject = defaultClaimsIdentity,
                    TokenIssuerName = Default.Issuer,
                };

                var token4x_AttributeStatement = CrossVersionTokenValidationTestsData.GetSamlSecurityToken4x(tokenDescriptor4x);

                tokenDescriptor4x.Subject = AuthenticationClaimsIdentity;
                tokenDescriptor4x.AuthenticationInfo = new AuthenticationInformation
                {
                    Address = Default.IPAddress,
                    DnsName = Default.DNSAddress
                };

                var token4x_AuthenticationStatement = CrossVersionTokenValidationTestsData.GetSamlSecurityToken4x(tokenDescriptor4x);

                tokenDescriptor4x.Subject = AuthorizationDecisionClaimsIdentity;
                var authorizationDecisionStatements = new SamlAuthorizationDecisionStatement4x(new SamlSubject4x(Default.NameIdentifierFormat, Default.NameQualifier, Default.Subject), Default.SamlResource, SamlAccessDecision4x.Permit, new List<SamlAction4x> { new SamlAction4x("Action") });
                var samlAssertion_AuthorizationDecision = new SamlAssertion4x(Default.SamlAssertionID, Default.Issuer, DateTime.Parse(Default.IssueInstant), (token4x_AttributeStatement as SamlSecurityToken4x).Assertion.Conditions, null, new List<SamlStatement4x> { authorizationDecisionStatements });
                var token4x_AuthorizationDecisionStatement = new SamlSecurityToken4x(samlAssertion_AuthorizationDecision);

                return new TheoryData<ClaimsPrincipalTheoryData>
                {
                    new ClaimsPrincipalTheoryData
                    {
                        TestId = "AttributeStatement",
                        Token = CrossVersionTokenValidationTestsData.GetSamlToken(token4x_AttributeStatement),
                        TokenValidationParameters = new SharedTokenValidationParameters
                        {
                            NameClaimType = ClaimsIdentity.DefaultNameClaimType,
                            RoleClaimType = ClaimsIdentity.DefaultRoleClaimType,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        X509Certificate = KeyingMaterial.DefaultCert_2048
                    },
                    new ClaimsPrincipalTheoryData
                    {
                        TestId = "AuthenticationStatement",
                        Token = CrossVersionTokenValidationTestsData.GetSamlToken(token4x_AuthenticationStatement),
                        TokenValidationParameters = new SharedTokenValidationParameters
                        {
                            NameClaimType = ClaimsIdentity.DefaultNameClaimType,
                            RoleClaimType = ClaimsIdentity.DefaultRoleClaimType,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        X509Certificate = KeyingMaterial.DefaultCert_2048
                    },
                    new ClaimsPrincipalTheoryData
                    {
                        TestId = "AuthorizationDecisionStatement",
                        Token = CrossVersionTokenValidationTestsData.GetSamlToken(token4x_AuthorizationDecisionStatement),
                        TokenValidationParameters = new SharedTokenValidationParameters
                        {
                            NameClaimType = ClaimsIdentity.DefaultNameClaimType,
                            RoleClaimType = ClaimsIdentity.DefaultRoleClaimType,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        X509Certificate = KeyingMaterial.DefaultCert_2048
                    }
                };
            }
        }

        private static ClaimsIdentity AuthenticationClaimsIdentity
        {
            get
            {
                var authorizationClaims = new List<Claim>
                {
                    Default.SamlClaims.Find(x => x.Type == ClaimTypes.NameIdentifier),
                    new Claim(ClaimTypes.AuthenticationMethod, Default.AuthenticationMethod, ClaimValueTypes.String, Default.Issuer),
                    new Claim(ClaimTypes.AuthenticationInstant, Default.AuthenticationInstant, ClaimValueTypes.DateTime, Default.Issuer)
                };

                return new ClaimsIdentity(authorizationClaims);
            }
        }

        private static ClaimsIdentity AuthorizationDecisionClaimsIdentity
        {
            get
            {
                var authorizationDecisionClaims = new List<Claim>
                {
                    Default.SamlClaims.Find(x => x.Type == ClaimTypes.NameIdentifier)
                };

                return new ClaimsIdentity(authorizationDecisionClaims);
            }
        }

        private static bool AreSamlTokensEqual(SecurityToken4x token4x, SecurityToken token5x, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(token4x, token5x, localContext))
                return context.Merge(localContext);

            if (!(token4x is SamlSecurityToken4x samlToken4x))
                return false;

            if (!(token5x is SamlSecurityToken samlToken5x))
                return false;

            if (!DateTime.Equals(samlToken4x.ValidFrom, samlToken5x.ValidFrom))
                localContext.Diffs.Add(Environment.NewLine + $"token1.ValidFrom != token2.ValidFrom: {samlToken4x.ValidFrom}, {samlToken5x.ValidFrom}");

            if (!DateTime.Equals(samlToken4x.ValidTo, samlToken5x.ValidTo))
                localContext.Diffs.Add(Environment.NewLine + $"token1.ValidTo != token2.ValidTo: {samlToken4x.ValidTo}  {samlToken5x.ValidTo}");

            AreSamlAssertionsEqual(samlToken4x.Assertion, samlToken5x.Assertion, localContext);
            return context.Merge(localContext);
        }

        private static bool AreSamlAssertionsEqual(SamlAssertion4x assertion4x, SamlAssertion assertion5x, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(assertion4x, assertion5x, localContext))
                return context.Merge(localContext);

            // Note: We ignore compare assertion.IssueInstant, because in SamlSecurityTokenHandler.CreateToken level, this value always has been set as Utc.Now.

            if (String.CompareOrdinal(assertion4x.Issuer, assertion5x.Issuer) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"assertion1.Issuer != assertion2.Issuer: {assertion4x.Issuer}, {assertion5x.Issuer}");

            if (assertion4x.MajorVersion != int.Parse(assertion5x.MajorVersion))
                localContext.Diffs.Add(Environment.NewLine + $"assertion1.MajorVersion != assertion2.MajorVersion: {assertion4x.MajorVersion}, {assertion5x.MajorVersion}");

            if (assertion4x.MinorVersion != int.Parse(assertion5x.MinorVersion))
                localContext.Diffs.Add(Environment.NewLine + $"assertion1.MinorVersion != assertion2.MinorVersion: {assertion4x.MinorVersion}, {assertion5x.MinorVersion}");

            // Compare advice
            AreSamlAdvicesEqual(assertion4x.Advice, assertion5x.Advice, localContext);

            //Compare Conditions
            AreSamlConditionsEnumsEqual(assertion4x.Conditions, assertion5x.Conditions, localContext);

            // Compare Statements
            AreSamlObjectEnumsEqual(assertion4x.Statements, assertion5x.Statements, localContext);

            return context.Merge(localContext);
        }

        private static bool AreSamlAdvicesEqual(SamlAdvice4x advice4x, SamlAdvice advice5x, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(advice4x, advice5x, localContext))
                return context.Merge(localContext);

            if (advice4x.AssertionIdReferences.Count != advice5x.AssertionIdReferences.Count)
                localContext.Diffs.Add(Environment.NewLine + $"advice1.AssertionIdReferences.Count != advice2.AssertionIdReferences.Count: {advice4x.AssertionIdReferences.Count}, {advice5x.AssertionIdReferences.Count}");

            var diff = advice4x.AssertionIdReferences.Where(x => !advice5x.AssertionIdReferences.Contains(x));
            if (diff.Count() != 0)
            {
                foreach (var id in diff)
                {
                    localContext.Diffs.Add(Environment.NewLine + $"advice2 doesn't have {id} which in advice1.");
                }
            }

            diff = advice5x.AssertionIdReferences.Where(x => !advice4x.AssertionIdReferences.Contains(x));
            if (diff.Count() != 0)
            {
                foreach (var id in diff)
                {
                    localContext.Diffs.Add(Environment.NewLine + $"advice1 doesn't have {id} which in advice2.");
                }
            }

            if (advice4x.Assertions.Count != advice5x.Assertions.Count)
                localContext.Diffs.Add(Environment.NewLine + $"advice1.Assertions.Count: {advice4x.Assertions.Count} != advice2.Assertions.Count: {advice5x.Assertions.Count}");

            AreSamlObjectEnumsEqual(advice4x.Assertions, advice5x.Assertions, localContext);
            return context.Merge(localContext);
        }

        private static bool AreSamlConditionsEqual(SamlCondition4x condition4x, SamlCondition condition5x, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(condition4x, condition5x, localContext))
                return context.Merge(localContext);

            var type4x = condition4x.GetType();
            var type5x = condition5x.GetType();
            if (type4x == typeof(SamlAudienceRestrictionCondition4x) ^ type5x == typeof(SamlAudienceRestrictionCondition))
                localContext.Diffs.Add(Environment.NewLine + $"System.IdentityModel.Tokens.SamlCondition.GetType() != Microsoft.IdentityModel.Tokens.Saml.SamlCondition.GetType(): {condition4x.GetType()}, {condition5x.GetType()}");
            else if (type4x == typeof(SamlDoNotCacheCondition4x) ^ type5x == typeof(SamlDoNotCacheCondition))
                localContext.Diffs.Add(Environment.NewLine + $"System.IdentityModel.Tokens.SamlCondition.GetType() != Microsoft.IdentityModel.Tokens.Saml.SamlCondition.GetType(): {condition4x.GetType()}, {condition5x.GetType()}");
            else
            {
                if (condition4x is SamlAudienceRestrictionCondition4x audienceCondition1)
                {
                    // Compare SamlAudienceRestrictionCondition
                    var audienceCondition2 = condition5x as SamlAudienceRestrictionCondition;
                    if (audienceCondition1.Audiences.Count != audienceCondition2.Audiences.Count)
                        localContext.Diffs.Add(Environment.NewLine + $"System.IdentityModel.Tokens.SamlAudienceRestrictionCondition.Audiences.Count != Microsoft.IdentityModel.Tokens.Saml.SamlAudienceRestrictionCondition.Audiences.Count: {audienceCondition1.Audiences.Count}, {audienceCondition2.Audiences.Count}");

                    var diff = audienceCondition1.Audiences.Where(x => !audienceCondition2.Audiences.Contains(x));
                    if (diff.Count() != 0)
                    {
                        foreach (var item in diff)
                            localContext.Diffs.Add(Environment.NewLine + $"condition2 doesn't have audience: {item} which in condition1");
                    }

                    diff = audienceCondition2.Audiences.Where(x => !audienceCondition1.Audiences.Contains(x));
                    if (diff.Count() != 0)
                    {
                        foreach (var item in diff)
                            localContext.Diffs.Add(Environment.NewLine + $"condition1 doesn't have audience: {item} which in condition2");
                    }
                }
            }

            return context.Merge(localContext);
        }

        private static bool AreSamlConditionsEnumsEqual(SamlConditions4x conditions4x, SamlConditions conditions5x, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(conditions4x, conditions5x, localContext))
                return context.Merge(localContext);

            if (conditions4x.Conditions.Count != conditions5x.Conditions.Count)
                context.Diffs.Add(Environment.NewLine + $"conditions1.Conditions.Count != conditions2.Conditions.Count: {conditions4x.Conditions.Count}, {conditions5x.Conditions.Count}");

            int numMatched = 0;
            int numToMatch = conditions4x.Conditions.Count;
            var notMatched = new List<SamlCondition4x>();
            foreach (var condition in conditions4x.Conditions)
            {
                var perClaimContext = new CompareContext(localContext);
                bool matched = false;
                for (int i = 0; i < conditions5x.Conditions.Count; i++)
                {
                    var type4x = condition.GetType();
                    var type5x = conditions5x.Conditions.ElementAt(i).GetType();

                    if (type4x == typeof(SamlAudienceRestrictionCondition4x) ^ type5x == typeof(SamlAudienceRestrictionCondition))
                        continue;

                    if (type4x == typeof(SamlDoNotCacheCondition4x) ^ type5x == typeof(Microsoft.IdentityModel.Tokens.Saml.SamlDoNotCacheCondition))
                        continue;

                    if (AreSamlConditionsEqual(condition, conditions5x.Conditions.ElementAt(i), perClaimContext))
                    {
                        numMatched++;
                        matched = true;
                        conditions5x.Conditions.Remove(conditions5x.Conditions.ElementAt(i));
                        break;
                    }
                }

                if (!matched)
                {
                    notMatched.Add(condition);
                }
            }

            if (numMatched != numToMatch)
            {
                localContext.Diffs.Add(Environment.NewLine + "numMatched != numToMatch: " + numMatched + ", " + numToMatch);
                localContext.Diffs.Add(Environment.NewLine + "conditions1 NOT Matched:" + Environment.NewLine);
                foreach (var condition in notMatched)
                {
                    var type = condition.GetType();
                    if (condition is SamlAudienceRestrictionCondition4x audienceCondition)
                    {
                        localContext.Diffs.Add($"condition type: {condition.GetType()}");
                        foreach (var audience in audienceCondition.Audiences)
                            localContext.Diffs.Add($"condition value: {audienceCondition.Audiences}");
                    }
                    else if (condition is SamlDoNotCacheCondition4x doNotCacheCondition)
                        localContext.Diffs.Add($"condition type: {condition.GetType()}");
                }

                localContext.Diffs.Add(Environment.NewLine + "conditions2 NOT Matched:" + Environment.NewLine);
                foreach (var condition in conditions5x.Conditions)
                {
                    var type = condition.GetType();
                    if (condition is SamlAudienceRestrictionCondition audienceCondition)
                    {
                        localContext.Diffs.Add($"condition type: {condition.GetType()}");
                        foreach (var audience in audienceCondition.Audiences)
                            localContext.Diffs.Add($"condition value: {audienceCondition.Audiences}");
                    }
                    else if (condition is SamlDoNotCacheCondition doNotCacheCondition)
                        localContext.Diffs.Add($"condition type: {condition.GetType()}");
                }

                localContext.Diffs.Add(Environment.NewLine);
            }

            return context.Merge(localContext);
        }

        private static bool AreSamlStatementsEqual(SamlStatement4x statement4x, SamlStatement statement5x, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(statement4x, statement5x, localContext))
                return context.Merge(localContext);

            var type4x = statement4x.GetType();
            var type5x = statement5x.GetType();
            if (type4x == typeof(SamlAuthenticationStatement4x) ^ type5x == typeof(SamlAuthenticationStatement))
                localContext.Diffs.Add(Environment.NewLine + $"System.IdentityModel.Tokens.SamlStatement.GetType() != Microsoft.IdentityModel.Tokens.Saml.SamlStatement.GetType(): {statement4x.GetType()}, {statement5x.GetType()}");
            else if (type4x == typeof(SamlAttributeStatement4x) ^ type5x == typeof(SamlAttributeStatement))
                localContext.Diffs.Add(Environment.NewLine + $"System.IdentityModel.Tokens.SamlStatement.GetType() != Microsoft.IdentityModel.Tokens.Saml.SamlStatement.GetType(): {statement4x.GetType()}, {statement5x.GetType()}");
            else if (type4x == typeof(SamlAuthorizationDecisionClaimResource4x) ^ type5x == typeof(SamlAuthorizationDecisionStatement))
                localContext.Diffs.Add(Environment.NewLine + $"System.IdentityModel.Tokens.SamlStatement.GetType() != Microsoft.IdentityModel.Tokens.Saml.SamlStatement.GetType(): {statement4x.GetType()}, {statement5x.GetType()}");
            else
            {
                if (statement4x is SamlAuthenticationStatement4x authStatement4x)
                {
                    var authStatement2 = statement5x as SamlAuthenticationStatement;
                    if (!DateTime.Equals(authStatement4x.AuthenticationInstant, authStatement2.AuthenticationInstant))
                        localContext.Diffs.Add(Environment.NewLine + $"authStatement1.AuthenticationInstant != authStatement2.AuthenticationInstant: {authStatement4x.AuthenticationInstant}, {authStatement2.AuthenticationInstant}");

                    if (String.CompareOrdinal(authStatement4x.AuthenticationMethod, authStatement2.AuthenticationMethod) != 0)
                        localContext.Diffs.Add(Environment.NewLine + $"authStatement1.AuthenticationMethod != authStatement2.AuthenticationMethod: {authStatement4x.AuthenticationMethod}, {authStatement2.AuthenticationMethod}");

                    if (String.CompareOrdinal(authStatement4x.DnsAddress, authStatement2.DnsAddress) != 0)
                        localContext.Diffs.Add(Environment.NewLine + $"authStatement1.DnsAddress != authStatement2.DnsAddress: {authStatement4x.DnsAddress}, {authStatement2.DnsAddress}");

                    if (String.CompareOrdinal(authStatement4x.IPAddress, authStatement2.IPAddress) != 0)
                        localContext.Diffs.Add(Environment.NewLine + $"authStatement1.IPAddress != authStatement2.IPAddress: {authStatement4x.IPAddress}, {authStatement2.IPAddress}");

                    AreSamlSubjectsEqual(authStatement4x.SamlSubject, authStatement2.Subject, localContext);
                    AreSamlObjectEnumsEqual(authStatement4x.AuthorityBindings, authStatement2.AuthorityBindings, localContext);
                }
                else if (statement4x is SamlAttributeStatement4x attributeStatement4x)
                {
                    var attributeStatement2 = statement5x as SamlAttributeStatement;
                    AreSamlSubjectsEqual(attributeStatement4x.SamlSubject, attributeStatement2.Subject, localContext);
                    AreSamlObjectEnumsEqual(attributeStatement4x.Attributes, attributeStatement2.Attributes, localContext);
                }
                else if (statement4x is SamlAuthorizationDecisionStatement4x decisionStatement4x)
                {
                    var decisionStatement2 = statement5x as SamlAuthorizationDecisionStatement;
                    AreSamlSubjectsEqual(decisionStatement4x.SamlSubject, decisionStatement2.Subject, localContext);
                    AreSamlObjectEnumsEqual(decisionStatement4x.SamlActions, decisionStatement2.Actions, localContext);

                    if (String.CompareOrdinal(decisionStatement4x.AccessDecision.ToString(), decisionStatement2.Decision) != 0)
                        localContext.Diffs.Add(Environment.NewLine + $"decisionStatement1.AccessDecision != decisionStatement2.Decision: {decisionStatement4x.AccessDecision}, {decisionStatement2.Decision}");

                    AreSamlEvidencesEqual(decisionStatement4x.Evidence, decisionStatement2.Evidence, localContext);

                    if (String.CompareOrdinal(decisionStatement4x.Resource, decisionStatement2.Resource) != 0)
                        localContext.Diffs.Add(Environment.NewLine + $"decisionStatement1.Resource != decisionStatement2.Resource: {decisionStatement4x.Resource}, {decisionStatement2.Resource}");
                }
            }

            return context.Merge(localContext);
        }

        private static bool AreSamlObjectEnumsEqual<T1, T2>(ICollection<T1> objs1, ICollection<T2> objs2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(objs1, objs2, localContext))
                return context.Merge(localContext);

            if (objs1.Count() != objs2.Count())
                localContext.Diffs.Add(Environment.NewLine + $"obj1.Count != obj2.Count: {objs1.Count()}, {objs2.Count()}");

            List<T1> toMatch = new List<T1>(objs1);
            List<T2> expectedValues = new List<T2>(objs2);

            int numMatched = 0;
            int numToMatch = toMatch.Count();
            var notMatched = new List<T1>();
            foreach (var obj in toMatch)
            {
                var perClaimContext = new CompareContext(localContext);
                bool matched = false;
                for (int i = 0; i < expectedValues.Count(); i++)
                {
                    var type4x = obj.GetType();
                    var type5x = expectedValues.ElementAt(i).GetType();

                    if (obj is SamlStatement4x)
                    {
                        if (type4x == typeof(SamlAttributeStatement4x) ^ type5x == typeof(SamlAttributeStatement))
                            continue;

                        if (type4x == typeof(SamlAuthenticationStatement4x) ^ type5x == typeof(SamlAuthenticationStatement))
                            continue;

                        if (type4x == typeof(SamlAuthorizationDecisionStatement4x) ^ type5x == typeof(SamlAuthorizationDecisionStatement))
                            continue;

                        if (AreSamlStatementsEqual(obj as SamlStatement4x, expectedValues.ElementAt(i) as SamlStatement, perClaimContext))
                        {
                            numMatched++;
                            matched = true;
                            expectedValues.Remove(expectedValues.ElementAt(i));
                            break;
                        }
                    }
                    else if (obj is SamlAttribute4x)
                    {
                        if (AreSamlAttributesEqual(obj as SamlAttribute4x, expectedValues.ElementAt(i) as SamlAttribute, perClaimContext))
                        {
                            numMatched++;
                            matched = true;
                            expectedValues.Remove(expectedValues.ElementAt(i));
                            break;
                        }
                    }
                    else if (obj is SamlAction4x)
                    {
                        if (AreSamlActionsEqual(obj as SamlAction4x, expectedValues.ElementAt(i) as SamlAction, perClaimContext))
                        {
                            numMatched++;
                            matched = true;
                            expectedValues.Remove(expectedValues.ElementAt(i));
                            break;
                        }
                    }
                    else if (obj is SamlAuthorityBinding4x)
                    {
                        if (AreSamlAuthorityBindingsEqual(obj as SamlAuthorityBinding4x, expectedValues.ElementAt(i) as SamlAuthorityBinding, perClaimContext))
                        {
                            numMatched++;
                            matched = true;
                            expectedValues.Remove(expectedValues.ElementAt(i));
                            break;
                        }
                    }
                    else if (obj is SamlAssertion4x)
                    {
                        if (AreSamlAssertionsEqual(obj as SamlAssertion4x, expectedValues.ElementAt(i) as SamlAssertion, perClaimContext))
                        {
                            numMatched++;
                            matched = true;
                            expectedValues.Remove(expectedValues.ElementAt(i));
                            break;
                        }
                    }
                }

                if (!matched)
                {
                    notMatched.Add(obj);
                }
            }

            if (numMatched != numToMatch)
            {
                localContext.Diffs.Add(Environment.NewLine + "numMatched != numToMatch: " + numMatched + ", " + numToMatch);
                localContext.Diffs.Add(Environment.NewLine + $"objs1 NOT Matched: Type {toMatch.GetType()}:****************");
                foreach (var obj in notMatched)
                {
                    Type type = obj.GetType();
                    localContext.Diffs.Add(Environment.NewLine + $"Object Type: {type}");
                    PropertyInfo[] propertyInfos = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
                    foreach (PropertyInfo propertyInfo in propertyInfos)
                    {
                        if (propertyInfo.GetMethod != null)
                        {
                            object val = propertyInfo.GetValue(obj, null);
                            if (val != null)
                                localContext.Diffs.Add(Environment.NewLine + $"{propertyInfo.Name}: {val}");
                        }
                    }
                }

                localContext.Diffs.Add(Environment.NewLine + $"objs2 NOT Matched: Type {expectedValues.GetType()}:****************");
                foreach (var obj in expectedValues)
                {
                    Type type = obj.GetType();
                    localContext.Diffs.Add(Environment.NewLine + $"Object Type: {type}");
                    PropertyInfo[] propertyInfos = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
                    foreach (PropertyInfo propertyInfo in propertyInfos)
                    {
                        if (propertyInfo.GetMethod != null)
                        {
                            object val = propertyInfo.GetValue(obj, null);
                            if (val != null)
                                localContext.Diffs.Add(Environment.NewLine + $"{propertyInfo.Name}: {val}");
                        }
                    }
                }
            }

            return context.Merge(localContext);
        }

        private static bool AreSamlAuthorityBindingsEqual(SamlAuthorityBinding4x binding4x, SamlAuthorityBinding binding5x, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(binding4x, binding5x, localContext))
                return context.Merge(localContext);

            if (String.Compare(binding4x.Binding, binding5x.Binding) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"bindings1.Binding != bindings2.Binding: {binding4x.Binding}, {binding5x.Binding}");

            if (String.Compare(binding4x.Location, binding5x.Location) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"bindings1.Location != bindings2.Location: {binding4x.Location}, {binding5x.Location}");

            AreNameQualifiersEqual(binding4x.AuthorityKind, binding5x.AuthorityKind, localContext);
            return context.Merge(localContext);
        }

        private static bool AreNameQualifiersEqual(XmlQualifiedName name4x, XmlQualifiedName name5x, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(name4x, name5x, localContext))
                return context.Merge(localContext);

            if (String.CompareOrdinal(name4x.Name, name5x.Name) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"name1.Name != name2.Name: {name4x.Name}, {name5x.Name}");

            if (String.CompareOrdinal(name4x.Namespace, name5x.Namespace) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"name1.Namespace != name2.Namespace: {name4x.Namespace}, {name5x.Namespace}");

            return context.Merge(localContext);
        }

        private static bool AreSamlSubjectsEqual(SamlSubject4x subject4x, SamlSubject subject5x, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(subject4x, subject5x, localContext))
                return context.Merge(localContext);

            if (String.CompareOrdinal(subject4x.SubjectConfirmationData, subject5x.ConfirmationData) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"subject1.SubjectConfirmationData != subject2.ConfirmationData: {subject4x.SubjectConfirmationData}, {subject5x.ConfirmationData}");

            if (String.CompareOrdinal(subject4x.NameQualifier, subject5x.NameQualifier) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"subject1.NameQualifier != subject2.NameQualifier: {subject4x.NameQualifier}, {subject5x.NameQualifier}");

            if (String.CompareOrdinal(subject4x.NameFormat, subject5x.NameFormat) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"subject1.NameFormat != subject2.NameFormat: {subject4x.NameFormat}, {subject5x.NameFormat}");

            if (String.CompareOrdinal(subject4x.Name, subject5x.Name) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"subject1.Name != subject2.Name: {subject4x.Name}, {subject5x.Name}");

            var diff = subject4x.ConfirmationMethods.Where(x => !subject5x.ConfirmationMethods.Contains(x));
            if (diff.Count() > 0)
            {
                localContext.Diffs.Add(Environment.NewLine + $"subject2.ConfirmationMethods doesn't have methods:");
                foreach (var item in diff)
                    localContext.Diffs.Add(Environment.NewLine + item);
            }

            diff = subject5x.ConfirmationMethods.Where(x => !subject4x.ConfirmationMethods.Contains(x));
            if (diff.Count() > 0)
            {
                localContext.Diffs.Add(Environment.NewLine + $"subject1.ConfirmationMethods doesn't have methods:");
                foreach (var item in diff)
                    localContext.Diffs.Add(Environment.NewLine + item);
            }

            return context.Merge(localContext);
        }

        private static bool AreSamlAttributesEqual(SamlAttribute4x attribute4x, SamlAttribute attribute5x, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(attribute4x, attribute5x, localContext))
                return context.Merge(localContext);

            if (String.CompareOrdinal(attribute4x.Name, attribute5x.Name) != 0)
                localContext.Diffs.Add($"attribute1.Name != attribute2.Name: {attribute4x.Name}, {attribute5x.Name}");

            if (String.CompareOrdinal(attribute4x.Namespace, attribute5x.Namespace) != 0)
                localContext.Diffs.Add($"attribute1.Namespace != attribute2.Namespace: {attribute4x.Namespace}, {attribute5x.Namespace}");

            if (String.CompareOrdinal(attribute4x.OriginalIssuer, attribute5x.OriginalIssuer) != 0)
                localContext.Diffs.Add($"attribute1.OriginalIssuer != attribute2.OriginalIssuer: {attribute4x.OriginalIssuer}, {attribute5x.OriginalIssuer}");

            if (String.CompareOrdinal(attribute4x.AttributeValueXsiType, attribute5x.AttributeValueXsiType) != 0)
                localContext.Diffs.Add($"attribute1.AttributeValueXsiType != attribute2.AttributeValueXsiType: {attribute4x.AttributeValueXsiType}, {attribute5x.AttributeValueXsiType}");

            if (attribute4x.AttributeValues.Count != attribute5x.Values.Count)
                localContext.Diffs.Add(Environment.NewLine + $"attribute1.AttributeValues.Count != attribute2.Values.Count: {attribute4x.AttributeValues.Count}, {attribute5x.Values.Count}");

            var diff = attribute4x.AttributeValues.Where(x => !attribute5x.Values.Contains(x));
            if (diff.Count() != 0)
                foreach (var item in diff)
                    localContext.Diffs.Add($"attribute2 doesn't have AttributeValue {item} which in attribute1");

            diff = attribute5x.Values.Where(x => !attribute4x.AttributeValues.Contains(x));
            if (diff.Count() != 0)
                foreach (var item in diff)
                    localContext.Diffs.Add($"attribute1 doesn't have AttributeValue {item} which in attribute2");

            return context.Merge(localContext);
        }

        private static bool AreSamlActionsEqual(SamlAction4x action4x, SamlAction action5x, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(action4x, action5x, localContext))
                return context.Merge(localContext);

            if (String.CompareOrdinal(action4x.Action, action5x.Value) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"action1.Action != action.Value: {action4x.Action}, {action5x.Value}");

            if (String.CompareOrdinal(action4x.Namespace, action5x.Namespace.ToString()) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"action1.Namespace != action2.Namespace: {action4x.Namespace}, {action5x.Namespace}");

            return context.Merge(localContext);
        }

        private static bool AreSamlEvidencesEqual(SamlEvidence4x evidence4x, SamlEvidence evidence5x, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(evidence4x, evidence5x, localContext))
                return context.Merge(localContext);

            if (evidence4x.AssertionIdReferences.Count != evidence5x.AssertionIDReferences.Count)
                localContext.Diffs.Add(Environment.NewLine + $"evidence1.AssertionIdReferences.Count != evidence2.AssertionIDReferences.Count: {evidence4x.AssertionIdReferences.Count}, {evidence5x.AssertionIDReferences.Count}");

            var diff = evidence4x.AssertionIdReferences.Where(x => !evidence5x.AssertionIDReferences.Contains(x));
            if (diff.Count() != 0)
            {
                foreach (var id in diff)
                {
                    localContext.Diffs.Add(Environment.NewLine + $"evidence2 doesn't have {id} which in advice1.");
                }
            }

            diff = evidence5x.AssertionIDReferences.Where(x => !evidence4x.AssertionIdReferences.Contains(x));
            if (diff.Count() != 0)
            {
                foreach (var id in diff)
                {
                    localContext.Diffs.Add(Environment.NewLine + $"evidence1 doesn't have {id} which in advice2.");
                }
            }

            if (evidence4x.Assertions.Count != evidence5x.Assertions.Count)
                localContext.Diffs.Add(Environment.NewLine + $"evidence1.Assertions.Count != evidence2.Assertions.Count: {evidence4x.Assertions.Count}, {evidence5x.Assertions.Count}");

            AreSamlObjectEnumsEqual(evidence4x.Assertions, evidence5x.Assertions, localContext);
            return context.Merge(localContext);
        }

        private static bool ContinueCheckingEquality<T1, T2>(T1 obj1, T2 obj2, CompareContext context)
        {
            if (obj1 == null && obj2 == null)
                return false;

            if (obj1 == null)
            {
                context.Diffs.Add(Environment.NewLine + $"{typeof(T1)} is null");
                return false;
            }

            if (obj2 == null)
            {
                context.Diffs.Add(Environment.NewLine + $"{typeof(T2)} is null");
                return false;
            }

            return true;
        }
    }

    public class TokenCrossTheoryData : TheoryDataBase
    {
        public SecurityTokenDescriptor4x TokenDescriptor4x { get; set; }

        public SecurityTokenDescriptor TokenDescriptor5x { get; set; }

        public TokenValidationParameters4x ValidationParameters4x { get; set; }

        public TokenValidationParameters ValidationParameters5x { get; set; }
    }

    public class ClaimsPrincipalTheoryData : TheoryDataBase
    {
        public string Token { get; set; }

        public SharedTokenValidationParameters TokenValidationParameters { get; set; }

        public X509Certificate2 X509Certificate { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
