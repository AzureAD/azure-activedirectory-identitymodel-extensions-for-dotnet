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
using Xunit;
using Microsoft.IdentityModel.Protocols.Extensions.OldVersion;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tests;

namespace Microsoft.IdentityModel.CrossVersionTokenValidation.Tests
{
    public class SamlCrossVersionTokenValidationTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("CreateTokenCrossVerstionTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void CreateTokenCrossVerstionTest(TokenCrossTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.CreateTokenCrossVerstionTest", theoryData);
            var context = new CompareContext($"{this}.CreateTokenCrossVerstionTest, {theoryData.TestId}");

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
                        TokenDescriptor4x = new System.IdentityModel.Tokens.SecurityTokenDescriptor
                        {
                            AppliesToAddress = Default.Audience,
                            Lifetime = new System.IdentityModel.Protocols.WSTrust.Lifetime(notBefore, expires),
                            Subject = defaultClaimsIdentity,
                            TokenIssuerName = Default.Issuer,
                        },
                        TokenDescriptor5x = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
                        {
                            Audience = Default.Audience,
                            NotBefore = notBefore,
                            Expires = expires,
                            Issuer = Default.Issuer,
                            Subject = defaultClaimsIdentity
                        }
                    },
                    new TokenCrossTheoryData
                    {
                        TokenDescriptor4x = new System.IdentityModel.Tokens.SecurityTokenDescriptor
                        {
                            AppliesToAddress = Default.Audience,
                            Lifetime = new System.IdentityModel.Protocols.WSTrust.Lifetime(notBefore, expires),
                            Subject = AuthenticationClaimsIdentity,
                            TokenIssuerName = Default.Issuer,
                        },
                        TokenDescriptor5x = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("CreateClaimsPrincipalCrossVersionTestTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void CreateClaimsPrincipalCrossVersionTest(ClaimsPrincipalTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.CreateClaimsPrincipalCrossVersionTest", theoryData);
            var context = new CompareContext($"{this}.CreateClaimsPrincipalCrossVersionTest, {theoryData.TestId}");

            var tvp5x = new Microsoft.IdentityModel.Tokens.TokenValidationParameters();

            PropertyInfo[] propertyInfos = typeof(SharedTokenValidationParameters).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
            foreach (PropertyInfo propertyInfo in propertyInfos)
            {
                if (propertyInfo.GetMethod != null)
                {
                    object val = propertyInfo.GetValue(theoryData.TokenValidationParameters, null);
                    PropertyInfo tvp5xPropertyInfo = typeof(Microsoft.IdentityModel.Tokens.TokenValidationParameters).GetProperty(propertyInfo.Name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
                    tvp5xPropertyInfo.SetValue(tvp5x, val);
                }
            }

            if (theoryData.X509Certificate != null)
                tvp5x.IssuerSigningKey = new Microsoft.IdentityModel.Tokens.X509SecurityKey(theoryData.X509Certificate);

            var claimsPrincipal4x = CrossVersionTokenValidationTestsData.GetSamlClaimsPrincipal4x(theoryData.Token, theoryData.TokenValidationParameters, theoryData.X509Certificate, out System.IdentityModel.Tokens.SecurityToken validateToken4x);
            var claimsPrincipal5x = new Microsoft.IdentityModel.Tokens.Saml.SamlSecurityTokenHandler().ValidateToken(theoryData.Token, tvp5x, out Microsoft.IdentityModel.Tokens.SecurityToken validateToken5x);

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
                var tokenDescriptor4x = new System.IdentityModel.Tokens.SecurityTokenDescriptor
                {
                    AppliesToAddress = Default.Audience,
                    Lifetime = new System.IdentityModel.Protocols.WSTrust.Lifetime(notBefore, expires),
                    SigningCredentials = new System.IdentityModel.Tokens.X509SigningCredentials(KeyingMaterial.DefaultCert_2048, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest),
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
                var authorizationDecisionStatements = new System.IdentityModel.Tokens.SamlAuthorizationDecisionStatement(new System.IdentityModel.Tokens.SamlSubject(Default.NameIdentifierFormat, Default.NameQualifier, Default.Subject), Default.SamlResource, System.IdentityModel.Tokens.SamlAccessDecision.Permit, new List<System.IdentityModel.Tokens.SamlAction> { new System.IdentityModel.Tokens.SamlAction("Action") });
                var samlAssertion_AuthorizationDecision = new System.IdentityModel.Tokens.SamlAssertion(Default.SamlAssertionID, Default.Issuer, DateTime.Parse(Default.IssueInstant), (token4x_AttributeStatement as System.IdentityModel.Tokens.SamlSecurityToken).Assertion.Conditions, null, new List<System.IdentityModel.Tokens.SamlStatement> { authorizationDecisionStatements });
                var token4x_AuthorizationDecisionStatement = new System.IdentityModel.Tokens.SamlSecurityToken(samlAssertion_AuthorizationDecision);

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

        private static bool AreSamlTokensEqual(System.IdentityModel.Tokens.SecurityToken token1, Microsoft.IdentityModel.Tokens.SecurityToken token2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(token1, token2, localContext))
                return context.Merge(localContext);

            if (!(token1 is System.IdentityModel.Tokens.SamlSecurityToken samlToken1))
                return false;

            if (!(token2 is Microsoft.IdentityModel.Tokens.Saml.SamlSecurityToken samlToken2))
                return false;

            if (!DateTime.Equals(samlToken1.ValidFrom, samlToken2.ValidFrom))
                localContext.Diffs.Add(Environment.NewLine + $"token1.ValidFrom != token2.ValidFrom: {samlToken1.ValidFrom}, {samlToken2.ValidFrom}");

            if (!DateTime.Equals(samlToken1.ValidTo, samlToken2.ValidTo))
                localContext.Diffs.Add(Environment.NewLine + $"token1.ValidTo != token2.ValidTo: {samlToken1.ValidTo}  {samlToken2.ValidTo}");

            AreSamlAssertionsEqual(samlToken1.Assertion, samlToken2.Assertion, localContext);
            return context.Merge(localContext);
        }

        private static bool AreSamlAssertionsEqual(System.IdentityModel.Tokens.SamlAssertion assertion1, SamlAssertion assertion2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(assertion1, assertion2, localContext))
                return context.Merge(localContext);

            // Note: We ignore compare assertion.IssueInstant, because in SamlSecurityTokenHandler.CreateToken level, this value always has been set as Utc.Now.

            if (String.CompareOrdinal(assertion1.Issuer, assertion2.Issuer) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"assertion1.Issuer != assertion2.Issuer: {assertion1.Issuer}, {assertion2.Issuer}");

            if (assertion1.MajorVersion != int.Parse(assertion2.MajorVersion))
                localContext.Diffs.Add(Environment.NewLine + $"assertion1.MajorVersion != assertion2.MajorVersion: {assertion1.MajorVersion}, {assertion2.MajorVersion}");

            if (assertion1.MinorVersion != int.Parse(assertion2.MinorVersion))
                localContext.Diffs.Add(Environment.NewLine + $"assertion1.MinorVersion != assertion2.MinorVersion: {assertion1.MinorVersion}, {assertion2.MinorVersion}");

            // Compare advice
            AreSamlAdvicesEqual(assertion1.Advice, assertion2.Advice, localContext);

            //Compare Conditions
            AreSamlConditionsEnumsEqual(assertion1.Conditions, assertion2.Conditions, localContext);

            // Compare Statements
            AreSamlObjectEnumsEqual(assertion1.Statements, assertion2.Statements, localContext);

            return context.Merge(localContext);
        }

        private static bool AreSamlAdvicesEqual(System.IdentityModel.Tokens.SamlAdvice advice1, Microsoft.IdentityModel.Tokens.Saml.SamlAdvice advice2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(advice1, advice2, localContext))
                return context.Merge(localContext);

            if (advice1.AssertionIdReferences.Count != advice2.AssertionIdReferences.Count)
                localContext.Diffs.Add(Environment.NewLine + $"advice1.AssertionIdReferences.Count != advice2.AssertionIdReferences.Count: {advice1.AssertionIdReferences.Count}, {advice2.AssertionIdReferences.Count}");

            var diff = advice1.AssertionIdReferences.Where(x => !advice2.AssertionIdReferences.Contains(x));
            if (diff.Count() != 0)
            {
                foreach (var id in diff)
                {
                    localContext.Diffs.Add(Environment.NewLine + $"advice2 doesn't have {id} which in advice1.");
                }
            }

            diff = advice2.AssertionIdReferences.Where(x => !advice1.AssertionIdReferences.Contains(x));
            if (diff.Count() != 0)
            {
                foreach (var id in diff)
                {
                    localContext.Diffs.Add(Environment.NewLine + $"advice1 doesn't have {id} which in advice2.");
                }
            }

            if (advice1.Assertions.Count != advice2.Assertions.Count)
                localContext.Diffs.Add(Environment.NewLine + $"advice1.Assertions.Count: {advice1.Assertions.Count} != advice2.Assertions.Count: {advice2.Assertions.Count}");

            AreSamlObjectEnumsEqual(advice1.Assertions, advice2.Assertions, localContext);
            return context.Merge(localContext);
        }

        private static bool AreSamlConditionsEqual(System.IdentityModel.Tokens.SamlCondition condition1, SamlCondition condition2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(condition1, condition2, localContext))
                return context.Merge(localContext);

            var type1 = condition1.GetType();
            var type2 = condition2.GetType();
            if (type1 == typeof(System.IdentityModel.Tokens.SamlAudienceRestrictionCondition) ^ type2 == typeof(Microsoft.IdentityModel.Tokens.Saml.SamlAudienceRestrictionCondition))
                localContext.Diffs.Add(Environment.NewLine + $"System.IdentityModel.Tokens.SamlCondition.GetType() != Microsoft.IdentityModel.Tokens.Saml.SamlCondition.GetType(): {condition1.GetType()}, {condition2.GetType()}");
            else if (type1 == typeof(System.IdentityModel.Tokens.SamlDoNotCacheCondition) ^ type2 == typeof(Microsoft.IdentityModel.Tokens.Saml.SamlDoNotCacheCondition))
                localContext.Diffs.Add(Environment.NewLine + $"System.IdentityModel.Tokens.SamlCondition.GetType() != Microsoft.IdentityModel.Tokens.Saml.SamlCondition.GetType(): {condition1.GetType()}, {condition2.GetType()}");
            else
            {
                if (condition1 is System.IdentityModel.Tokens.SamlAudienceRestrictionCondition audienceCondition1)
                {
                    // Compare SamlAudienceRestrictionCondition
                    var audienceCondition2 = condition2 as Microsoft.IdentityModel.Tokens.Saml.SamlAudienceRestrictionCondition;
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

        private static bool AreSamlConditionsEnumsEqual(System.IdentityModel.Tokens.SamlConditions conditions1, SamlConditions conditions2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(conditions1, conditions2, localContext))
                return context.Merge(localContext);

            if (conditions1.Conditions.Count != conditions2.Conditions.Count)
                context.Diffs.Add(Environment.NewLine + $"conditions1.Conditions.Count != conditions2.Conditions.Count: {conditions1.Conditions.Count}, {conditions2.Conditions.Count}");

            int numMatched = 0;
            int numToMatch = conditions1.Conditions.Count;
            var notMatched = new List<System.IdentityModel.Tokens.SamlCondition>();
            foreach (var condition in conditions1.Conditions)
            {
                var perClaimContext = new CompareContext(localContext);
                bool matched = false;
                for (int i = 0; i < conditions2.Conditions.Count; i++)
                {
                    var type1 = condition.GetType();
                    var type2 = conditions2.Conditions.ElementAt(i).GetType();

                    if (type1 == typeof(System.IdentityModel.Tokens.SamlAudienceRestrictionCondition) ^ type2 == typeof(Microsoft.IdentityModel.Tokens.Saml.SamlAudienceRestrictionCondition))
                        continue;

                    if (type1 == typeof(System.IdentityModel.Tokens.SamlDoNotCacheCondition) ^ type2 == typeof(Microsoft.IdentityModel.Tokens.Saml.SamlDoNotCacheCondition))
                        continue;

                    if (AreSamlConditionsEqual(condition, conditions2.Conditions.ElementAt(i), perClaimContext))
                    {
                        numMatched++;
                        matched = true;
                        conditions2.Conditions.Remove(conditions2.Conditions.ElementAt(i));
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
                    if (condition is System.IdentityModel.Tokens.SamlAudienceRestrictionCondition audienceCondition)
                    {
                        localContext.Diffs.Add($"condition type: {condition.GetType()}");
                        foreach (var audience in audienceCondition.Audiences)
                            localContext.Diffs.Add($"condition value: {audienceCondition.Audiences}");
                    }
                    else if (condition is System.IdentityModel.Tokens.SamlDoNotCacheCondition doNotCacheCondition)
                        localContext.Diffs.Add($"condition type: {condition.GetType()}");
                }

                localContext.Diffs.Add(Environment.NewLine + "conditions2 NOT Matched:" + Environment.NewLine);
                foreach (var condition in conditions2.Conditions)
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

        private static bool AreSamlStatementsEqual(System.IdentityModel.Tokens.SamlStatement statement1, SamlStatement statement2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(statement1, statement2, localContext))
                return context.Merge(localContext);

            var type1 = statement1.GetType();
            var type2 = statement2.GetType();
            if (type1 == typeof(System.IdentityModel.Tokens.SamlAuthenticationStatement) ^ type2 == typeof(SamlAuthenticationStatement))
                localContext.Diffs.Add(Environment.NewLine + $"System.IdentityModel.Tokens.SamlStatement.GetType() != Microsoft.IdentityModel.Tokens.Saml.SamlStatement.GetType(): {statement1.GetType()}, {statement2.GetType()}");
            else if (type1 == typeof(System.IdentityModel.Tokens.SamlAttributeStatement) ^ type2 == typeof(SamlAttributeStatement))
                localContext.Diffs.Add(Environment.NewLine + $"System.IdentityModel.Tokens.SamlStatement.GetType() != Microsoft.IdentityModel.Tokens.Saml.SamlStatement.GetType(): {statement1.GetType()}, {statement2.GetType()}");
            else if (type1 == typeof(System.IdentityModel.Tokens.SamlAuthorizationDecisionClaimResource) ^ type2 == typeof(SamlAuthorizationDecisionStatement))
                localContext.Diffs.Add(Environment.NewLine + $"System.IdentityModel.Tokens.SamlStatement.GetType() != Microsoft.IdentityModel.Tokens.Saml.SamlStatement.GetType(): {statement1.GetType()}, {statement2.GetType()}");
            else
            {
                if (statement1 is System.IdentityModel.Tokens.SamlAuthenticationStatement authStatement1)
                {
                    var authStatement2 = statement2 as SamlAuthenticationStatement;
                    if (!DateTime.Equals(authStatement1.AuthenticationInstant, authStatement2.AuthenticationInstant))
                        localContext.Diffs.Add(Environment.NewLine + $"authStatement1.AuthenticationInstant != authStatement2.AuthenticationInstant: {authStatement1.AuthenticationInstant}, {authStatement2.AuthenticationInstant}");

                    if (String.CompareOrdinal(authStatement1.AuthenticationMethod, authStatement2.AuthenticationMethod) != 0)
                        localContext.Diffs.Add(Environment.NewLine + $"authStatement1.AuthenticationMethod != authStatement2.AuthenticationMethod: {authStatement1.AuthenticationMethod}, {authStatement2.AuthenticationMethod}");

                    if (String.CompareOrdinal(authStatement1.DnsAddress, authStatement2.DnsAddress) != 0)
                        localContext.Diffs.Add(Environment.NewLine + $"authStatement1.DnsAddress != authStatement2.DnsAddress: {authStatement1.DnsAddress}, {authStatement2.DnsAddress}");

                    if (String.CompareOrdinal(authStatement1.IPAddress, authStatement2.IPAddress) != 0)
                        localContext.Diffs.Add(Environment.NewLine + $"authStatement1.IPAddress != authStatement2.IPAddress: {authStatement1.IPAddress}, {authStatement2.IPAddress}");

                    AreSamlSubjectsEqual(authStatement1.SamlSubject, authStatement2.Subject, localContext);
                    AreSamlObjectEnumsEqual(authStatement1.AuthorityBindings, authStatement2.AuthorityBindings, localContext);
                }
                else if (statement1 is System.IdentityModel.Tokens.SamlAttributeStatement attributeStatement1)
                {
                    var attributeStatement2 = statement2 as SamlAttributeStatement;
                    AreSamlSubjectsEqual(attributeStatement1.SamlSubject, attributeStatement2.Subject, localContext);
                    AreSamlObjectEnumsEqual(attributeStatement1.Attributes, attributeStatement2.Attributes, localContext);
                }
                else if (statement1 is System.IdentityModel.Tokens.SamlAuthorizationDecisionStatement decisionStatement1)
                {
                    var decisionStatement2 = statement2 as SamlAuthorizationDecisionStatement;
                    AreSamlSubjectsEqual(decisionStatement1.SamlSubject, decisionStatement2.Subject, localContext);
                    AreSamlObjectEnumsEqual(decisionStatement1.SamlActions, decisionStatement2.Actions, localContext);

                    if (String.CompareOrdinal(decisionStatement1.AccessDecision.ToString(), decisionStatement2.Decision) != 0)
                        localContext.Diffs.Add(Environment.NewLine + $"decisionStatement1.AccessDecision != decisionStatement2.Decision: {decisionStatement1.AccessDecision}, {decisionStatement2.Decision}");

                    AreSamlEvidencesEqual(decisionStatement1.Evidence, decisionStatement2.Evidence, localContext);

                    if (String.CompareOrdinal(decisionStatement1.Resource, decisionStatement2.Resource) != 0)
                        localContext.Diffs.Add(Environment.NewLine + $"decisionStatement1.Resource != decisionStatement2.Resource: {decisionStatement1.Resource}, {decisionStatement2.Resource}");
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
                    var t1 = obj.GetType();
                    var t2 = expectedValues.ElementAt(i).GetType();

                    if (obj is System.IdentityModel.Tokens.SamlStatement)
                    {
                        if (t1 == typeof(System.IdentityModel.Tokens.SamlAttributeStatement) ^ t2 == typeof(Microsoft.IdentityModel.Tokens.Saml.SamlAttributeStatement))
                            continue;

                        if (t1 == typeof(System.IdentityModel.Tokens.SamlAuthenticationStatement) ^ t2 == typeof(Microsoft.IdentityModel.Tokens.Saml.SamlAuthenticationStatement))
                            continue;

                        if (t1 == typeof(System.IdentityModel.Tokens.SamlAuthorizationDecisionStatement) ^ t2 == typeof(Microsoft.IdentityModel.Tokens.Saml.SamlAuthorizationDecisionStatement))
                            continue;

                        if (AreSamlStatementsEqual(obj as System.IdentityModel.Tokens.SamlStatement, expectedValues.ElementAt(i) as SamlStatement, perClaimContext))
                        {
                            numMatched++;
                            matched = true;
                            expectedValues.Remove(expectedValues.ElementAt(i));
                            break;
                        }
                    }
                    else if (obj is System.IdentityModel.Tokens.SamlAttribute)
                    {
                        if (AreSamlAttributesEqual(obj as System.IdentityModel.Tokens.SamlAttribute, expectedValues.ElementAt(i) as SamlAttribute, perClaimContext))
                        {
                            numMatched++;
                            matched = true;
                            expectedValues.Remove(expectedValues.ElementAt(i));
                            break;
                        }
                    }
                    else if (obj is System.IdentityModel.Tokens.SamlAction)
                    {
                        if (AreSamlActionsEqual(obj as System.IdentityModel.Tokens.SamlAction, expectedValues.ElementAt(i) as SamlAction, perClaimContext))
                        {
                            numMatched++;
                            matched = true;
                            expectedValues.Remove(expectedValues.ElementAt(i));
                            break;
                        }
                    }
                    else if (obj is System.IdentityModel.Tokens.SamlAuthorityBinding)
                    {
                        if (AreSamlAuthorityBindingsEqual(obj as System.IdentityModel.Tokens.SamlAuthorityBinding, expectedValues.ElementAt(i) as SamlAuthorityBinding, perClaimContext))
                        {
                            numMatched++;
                            matched = true;
                            expectedValues.Remove(expectedValues.ElementAt(i));
                            break;
                        }
                    }
                    else if (obj is System.IdentityModel.Tokens.SamlAssertion)
                    {
                        if (AreSamlAssertionsEqual(obj as System.IdentityModel.Tokens.SamlAssertion, expectedValues.ElementAt(i) as SamlAssertion, perClaimContext))
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

        private static bool AreSamlAuthorityBindingsEqual(System.IdentityModel.Tokens.SamlAuthorityBinding bindings1, SamlAuthorityBinding bindings2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(bindings1, bindings2, localContext))
                return context.Merge(localContext);

            if (String.Compare(bindings1.Binding, bindings2.Binding) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"bindings1.Binding != bindings2.Binding: {bindings1.Binding}, {bindings2.Binding}");

            if (String.Compare(bindings1.Location, bindings2.Location) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"bindings1.Location != bindings2.Location: {bindings1.Location}, {bindings2.Location}");

            AreNameQualifiersEqual(bindings1.AuthorityKind, bindings2.AuthorityKind, localContext);
            return context.Merge(localContext);
        }

        private static bool AreNameQualifiersEqual(XmlQualifiedName name1, XmlQualifiedName name2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(name1, name2, localContext))
                return context.Merge(localContext);

            if (String.CompareOrdinal(name1.Name, name2.Name) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"name1.Name != name2.Name: {name1.Name}, {name2.Name}");

            if (String.CompareOrdinal(name1.Namespace, name2.Namespace) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"name1.Namespace != name2.Namespace: {name1.Namespace}, {name2.Namespace}");

            return context.Merge(localContext);
        }

        private static bool AreSamlSubjectsEqual(System.IdentityModel.Tokens.SamlSubject subject1, SamlSubject subject2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(subject1, subject2, localContext))
                return context.Merge(localContext);

            if (String.CompareOrdinal(subject1.SubjectConfirmationData, subject2.ConfirmationData) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"subject1.SubjectConfirmationData != subject2.ConfirmationData: {subject1.SubjectConfirmationData}, {subject2.ConfirmationData}");

            if (String.CompareOrdinal(subject1.NameQualifier, subject2.NameQualifier) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"subject1.NameQualifier != subject2.NameQualifier: {subject1.NameQualifier}, {subject2.NameQualifier}");

            if (String.CompareOrdinal(subject1.NameFormat, subject2.NameFormat) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"subject1.NameFormat != subject2.NameFormat: {subject1.NameFormat}, {subject2.NameFormat}");

            if (String.CompareOrdinal(subject1.Name, subject2.Name) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"subject1.Name != subject2.Name: {subject1.Name}, {subject2.Name}");

            var diff = subject1.ConfirmationMethods.Where(x => !subject2.ConfirmationMethods.Contains(x));
            if (diff.Count() > 0)
            {
                localContext.Diffs.Add(Environment.NewLine + $"subject2.ConfirmationMethods doesn't have methods:");
                foreach (var item in diff)
                    localContext.Diffs.Add(Environment.NewLine + item);
            }

            diff = subject2.ConfirmationMethods.Where(x => !subject1.ConfirmationMethods.Contains(x));
            if (diff.Count() > 0)
            {
                localContext.Diffs.Add(Environment.NewLine + $"subject1.ConfirmationMethods doesn't have methods:");
                foreach (var item in diff)
                    localContext.Diffs.Add(Environment.NewLine + item);
            }

            return context.Merge(localContext);
        }

        private static bool AreSamlAttributesEqual(System.IdentityModel.Tokens.SamlAttribute attribute1, SamlAttribute attribute2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(attribute1, attribute2, localContext))
                return context.Merge(localContext);

            if (String.CompareOrdinal(attribute1.Name, attribute2.Name) != 0)
                localContext.Diffs.Add($"attribute1.Name != attribute2.Name: {attribute1.Name}, {attribute2.Name}");

            if (String.CompareOrdinal(attribute1.Namespace, attribute2.Namespace) != 0)
                localContext.Diffs.Add($"attribute1.Namespace != attribute2.Namespace: {attribute1.Namespace}, {attribute2.Namespace}");

            if (String.CompareOrdinal(attribute1.OriginalIssuer, attribute2.OriginalIssuer) != 0)
                localContext.Diffs.Add($"attribute1.OriginalIssuer != attribute2.OriginalIssuer: {attribute1.OriginalIssuer}, {attribute2.OriginalIssuer}");

            if (String.CompareOrdinal(attribute1.AttributeValueXsiType, attribute2.AttributeValueXsiType) != 0)
                localContext.Diffs.Add($"attribute1.AttributeValueXsiType != attribute2.AttributeValueXsiType: {attribute1.AttributeValueXsiType}, {attribute2.AttributeValueXsiType}");

            if (attribute1.AttributeValues.Count != attribute2.Values.Count)
                localContext.Diffs.Add(Environment.NewLine + $"attribute1.AttributeValues.Count != attribute2.Values.Count: {attribute1.AttributeValues.Count}, {attribute2.Values.Count}");

            var diff = attribute1.AttributeValues.Where(x => !attribute2.Values.Contains(x));
            if (diff.Count() != 0)
                foreach (var item in diff)
                    localContext.Diffs.Add($"attribute2 doesn't have AttributeValue {item} which in attribute1");

            diff = attribute2.Values.Where(x => !attribute1.AttributeValues.Contains(x));
            if (diff.Count() != 0)
                foreach (var item in diff)
                    localContext.Diffs.Add($"attribute1 doesn't have AttributeValue {item} which in attribute2");

            return context.Merge(localContext);
        }

        private static bool AreSamlActionsEqual(System.IdentityModel.Tokens.SamlAction action1, SamlAction action2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(action1, action2, localContext))
                return context.Merge(localContext);

            if (String.CompareOrdinal(action1.Action, action2.Value) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"action1.Action != action.Value: {action1.Action}, {action2.Value}");

            if (String.CompareOrdinal(action1.Namespace, action2.Namespace.ToString()) != 0)
                localContext.Diffs.Add(Environment.NewLine + $"action1.Namespace != action2.Namespace: {action1.Namespace}, {action2.Namespace}");

            return context.Merge(localContext);
        }

        private static bool AreSamlEvidencesEqual(System.IdentityModel.Tokens.SamlEvidence evidence1, SamlEvidence evidence2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(evidence1, evidence2, localContext))
                return context.Merge(localContext);

            if (evidence1.AssertionIdReferences.Count != evidence2.AssertionIDReferences.Count)
                localContext.Diffs.Add(Environment.NewLine + $"evidence1.AssertionIdReferences.Count != evidence2.AssertionIDReferences.Count: {evidence1.AssertionIdReferences.Count}, {evidence2.AssertionIDReferences.Count}");

            var diff = evidence1.AssertionIdReferences.Where(x => !evidence2.AssertionIDReferences.Contains(x));
            if (diff.Count() != 0)
            {
                foreach (var id in diff)
                {
                    localContext.Diffs.Add(Environment.NewLine + $"evidence2 doesn't have {id} which in advice1.");
                }
            }

            diff = evidence2.AssertionIDReferences.Where(x => !evidence1.AssertionIdReferences.Contains(x));
            if (diff.Count() != 0)
            {
                foreach (var id in diff)
                {
                    localContext.Diffs.Add(Environment.NewLine + $"evidence1 doesn't have {id} which in advice2.");
                }
            }

            if (evidence1.Assertions.Count != evidence2.Assertions.Count)
                localContext.Diffs.Add(Environment.NewLine + $"evidence1.Assertions.Count != evidence2.Assertions.Count: {evidence1.Assertions.Count}, {evidence2.Assertions.Count}");

            AreSamlObjectEnumsEqual(evidence1.Assertions, evidence2.Assertions, localContext);
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
        public System.IdentityModel.Tokens.SecurityTokenDescriptor TokenDescriptor4x { get; set; }
        public Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor TokenDescriptor5x { get; set; }
    }

    public class ClaimsPrincipalTheoryData : TheoryDataBase
    {
        public string Token { get; set; }
        public SharedTokenValidationParameters TokenValidationParameters { get; set; }
        public X509Certificate2 X509Certificate { get; set; }
    }
}