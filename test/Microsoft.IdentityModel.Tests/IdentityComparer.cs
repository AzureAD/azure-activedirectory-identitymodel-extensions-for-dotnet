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
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tests
{
    public class CompareContext
    {       
        List<string> _diffs = new List<string>();

        public static CompareContext Default = new CompareContext();

        public CompareContext()
        {
        }

        public CompareContext(string title)
        {
            Title = title;
        }

        public CompareContext(CompareContext other)
        {
            if (other == null)
                return;

            ExpectRawData = other.ExpectRawData;
            IgnoreClaimsIdentityType = other.IgnoreClaimsIdentityType;
            IgnoreClaimsPrincipalType = other.IgnoreClaimsPrincipalType;
            IgnoreClaimType = other.IgnoreClaimType;
            IgnoreProperties = other.IgnoreProperties;
            IgnoreSubject = other.IgnoreSubject;
            IgnoreTokenStreamReader = other.IgnoreTokenStreamReader;
            IgnoreType = other.IgnoreType;
            StringComparison = other.StringComparison;
        }

        public List<string> Diffs { get { return _diffs; } }

        public bool ExpectRawData { get; set; }

        /// <summary>
        /// Adds diffs and returns if any diffs were added.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>true if any diffs were added.</returns>
        public bool Merge(CompareContext context)
        {
            return Merge(null, context);
        }

        public bool Merge(string title, CompareContext context)
        {
            if (context == null)
                return false;

            if (context.Diffs.Count > 0)
            {
                _diffs.Add(title ?? string.Empty);
                _diffs.AddRange(context.Diffs);
            }

            return (context.Diffs.Count == 0);
        }

        public bool IgnoreClaimsIdentityType { get; set; }

        public bool IgnoreClaimsPrincipalType { get; set; }

        public bool IgnoreClaimType { get; set; }

        public bool IgnoreProperties { get; set; }

        public bool IgnoreSubject { get; set; } = true;

        public bool IgnoreTokenStreamReader { get; set; } = true;

        public bool IgnoreType { get; set; }

        public StringComparison StringComparison { get; set; } = System.StringComparison.Ordinal;

        public string Title { get; set; }
    }

    public class IdentityComparer
    {
        public static bool AreEnumsEqual<T>(IEnumerable<T> t1, IEnumerable<T> t2, CompareContext context, Func<T, T, CompareContext, bool> areEqual)
        {
            if (t1 == null && t2 == null)
                return true;

            if (t1 == null)
            {
                context.Diffs.Add($"t1 == null, t2 != null, (type: {t2.GetType()}, value: {t2.ToString()}).");
                return false;
            }

            if (t2 == null)
            {
                context.Diffs.Add($"t1 != null, t2 == null, (type: {t1.GetType()}), value: {t1.ToString()}).");
                return false;
            }

            if (ReferenceEquals(t1, t2))
                return true;

            List<T> toMatch = new List<T>(t1);
            List<T> expectedValues = new List<T>(t2);
            if (toMatch.Count != expectedValues.Count)
            {
                context.Diffs.Add("toMatch.Count != expectedToMatch.Count: " + toMatch.Count + ", " + expectedValues.Count + ", typeof: " + t1.GetType().ToString());
                return false;
            }

            int numMatched = 0;
            int numToMatch = toMatch.Count;
            CompareContext localContext = new CompareContext(context);
            List<KeyValuePair<T,T>> matchedTs = new List<KeyValuePair<T,T>>();
            
            // helps debugging to see what didn't match
            List<T> notMatched = new List<T>();
            foreach (var t in t1)
            {
                CompareContext perItemContext = new CompareContext(localContext);
                bool matched = false;
                for (int i = 0; i < expectedValues.Count; i++)
                {
                    if (areEqual(t, expectedValues[i], perItemContext))
                    {
                        numMatched++;
                        matchedTs.Add(new KeyValuePair<T, T>(expectedValues[i], t));
                        matched = true;
                        expectedValues.RemoveAt(i);
                        break;
                    }
                }

                if (!matched)
                {
                    notMatched.Add(t);
                    localContext.Diffs.AddRange(perItemContext.Diffs);
                }
            }

            if (numMatched != numToMatch)
            {
                localContext.Diffs.Add("numMatched != numToMatch: " + numMatched + ", " + numToMatch);
                if (notMatched.Count > 0)
                {
                    localContext.Diffs.Add(Environment.NewLine + "items in first enumeration NOT Matched");
                    foreach (var item in notMatched)
                    {
                        if (item != null)
                            localContext.Diffs.Add(item.ToString());
                        else
                            localContext.Diffs.Add("item is null");
                    }
                }

                if (expectedValues.Count > 0)
                {
                    localContext.Diffs.Add(Environment.NewLine + "expectedValues NOT Matched");
                    foreach (var item in expectedValues)
                    {
                        if (item != null)
                            localContext.Diffs.Add(item.ToString());
                        else
                            localContext.Diffs.Add("item is null");
                    }
                }

                if (matchedTs.Count > 0)
                {
                    localContext.Diffs.Add(Environment.NewLine + "items that were Matched");
                    foreach (var item in matchedTs)
                    {
                        localContext.Diffs.Add(item.Key.ToString());
                    }
                }
            }

            return context.Merge(localContext);
        }

        public static bool AreClaimsEnumsEqual(IEnumerable<Claim> t1, IEnumerable<Claim> t2, CompareContext context)
        {
            if (t1 == null && t2 == null)
                return true;

            if (t1 == null)
            {
                context.Diffs.Add($"t1 == null, t2 != null, (type: {t2.GetType()}, value: {t2.ToString()}).");
                return false;
            }

            if (t2 == null)
            {
                context.Diffs.Add($"t1 != null, t2 == null, (type: {t1.GetType()}), value: {t1.ToString()}).");
                return false;
            }

            if (ReferenceEquals(t1, t2))
                return true;

            var claims1 = new List<Claim>(t1);
            var claims2 = new List<Claim>(t2);
            if (claims1.Count != claims2.Count)
            {
                context.Diffs.Add($"claims1.Count != claims2.Count: {claims1.Count}, {claims2.Count}");
                context.Diffs.Add("claims1:");
                foreach (var claim in claims1)
                    context.Diffs.Add(claim.Type + ": " + claim.Value + ": " + claim.ValueType + ": " + claim.Issuer + ": " + claim.OriginalIssuer);

                context.Diffs.Add("claims2:");
                foreach (var claim in claims2)
                    context.Diffs.Add(claim.Type + ": " + claim.Value + ": " + claim.ValueType + ": " + claim.Issuer + ": " + claim.OriginalIssuer);

//                return false;
            }

            int numMatched = 0;
            int numToMatch = claims1.Count;
            var localContext = new CompareContext(context);
            var matchedClaims = new List<Claim>();
            var notMatched = new List<Claim>();
            foreach (var t in t1)
            {
                var perClaimContext = new CompareContext(localContext);
                bool matched = false;
                for (int i = 0; i < claims2.Count; i++)
                {
                    if (AreClaimsEqual(t, claims2[i], perClaimContext))
                    {
                        numMatched++;
                        matchedClaims.Add(t);
                        matched = true;
                        claims2.RemoveAt(i);
                        break;
                    }
                }

                if (!matched)
                {
                    notMatched.Add(t);
                    //localContext.Diffs.AddRange(perClaimContext.Diffs);
                }
            }

            if (numMatched != numToMatch)
            {
                localContext.Diffs.Add(Environment.NewLine + "numMatched != numToMatch: " + numMatched + ", " + numToMatch);
                localContext.Diffs.Add(Environment.NewLine + "Claims1 NOT Matched:" + Environment.NewLine);
                foreach (var claim in notMatched)
                    localContext.Diffs.Add(claim.Type + ": " + claim.Value + ": " + claim.ValueType + ": " + claim.Issuer + ": " + claim.OriginalIssuer);

                localContext.Diffs.Add(Environment.NewLine + "Claims2 NOT Matched:" + Environment.NewLine);
                foreach (var claim in claims2)
                    localContext.Diffs.Add(claim.Type + ": " + claim.Value + ": " + claim.ValueType + ": " + claim.Issuer + ": " + claim.OriginalIssuer);

                localContext.Diffs.Add(Environment.NewLine + "Claims Matched:" + Environment.NewLine);
                foreach (var claim in matchedClaims)
                    localContext.Diffs.Add(claim.Type + ": " + claim.Value + ": " + claim.ValueType + ": " + claim.Issuer + ": " + claim.OriginalIssuer);

                localContext.Diffs.Add(Environment.NewLine);
            }

            return context.Merge(localContext);
        }

        public static bool AreClaimsIdentitiesEnumsEqual(IEnumerable<ClaimsIdentity> t1, IEnumerable<ClaimsIdentity> t2, CompareContext context)
        {
            if (t1 == null && t2 == null)
                return true;

            if (t1 == null)
            {
                context.Diffs.Add("t1 == null, t2 != null");
                return false;
            }

            if (t2 == null)
            {
                context.Diffs.Add("t1 != null, t2 == null");
                return false;
            }

            if (ReferenceEquals(t1, t2))
                return true;

            var claimsIdentity1 = new List<ClaimsIdentity>(t1);
            var claimsIdentity2 = new List<ClaimsIdentity>(t2);
            if (claimsIdentity1.Count != claimsIdentity2.Count)
            {
                context.Diffs.Add($"claimsIdentity1.Count != claimsIdentity2.Count: {claimsIdentity1.Count}, {claimsIdentity2.Count}");
                context.Diffs.Add("claimsIdentity1:");
                foreach (var identity in claimsIdentity1)
                    context.Diffs.Add(identity.Name + ": " + identity.Label + ": " + identity.IsAuthenticated + ": " + identity.AuthenticationType + ": " + identity.RoleClaimType + ": " + identity.NameClaimType);

                context.Diffs.Add("claimsIdentity2:");
                foreach (var identity in claimsIdentity2)
                    context.Diffs.Add(identity.Name + ": " + identity.Label + ": " + identity.IsAuthenticated + ": " + identity.AuthenticationType + ": " + identity.RoleClaimType + ": " + identity.NameClaimType);
            }

            int numMatched = 0;
            int numToMatch = claimsIdentity1.Count;
            var localContext = new CompareContext(context);
            var matchedClaimsIdentities = new List<ClaimsIdentity>();
            var notMatched = new List<ClaimsIdentity>();
            foreach (var t in t1)
            {
                var perClaimContext = new CompareContext(localContext);
                bool matched = false;
                for (int i = 0; i < claimsIdentity2.Count; i++)
                {
                    if (AreClaimsIdentitiesEqual(t, claimsIdentity2[i], perClaimContext))
                    {
                        numMatched++;
                        matchedClaimsIdentities.Add(t);
                        matched = true;
                        claimsIdentity2.RemoveAt(i);
                        break;
                    }
                }

                if (!matched)
                {
                    notMatched.Add(t);
                }
            }

            if (numMatched != numToMatch)
            {
                localContext.Diffs.Add(Environment.NewLine + "numMatched != numToMatch: " + numMatched + ", " + numToMatch);
                localContext.Diffs.Add(Environment.NewLine + "claimsIdentity1 NOT Matched:" + Environment.NewLine);
                foreach (var identity in notMatched)
                    localContext.Diffs.Add(identity.Name + ": " + identity.Label + ": " + identity.IsAuthenticated + ": " + identity.AuthenticationType + ": " + identity.RoleClaimType + ": " + identity.NameClaimType);

                localContext.Diffs.Add(Environment.NewLine + "claimsIdentity2 NOT Matched:" + Environment.NewLine);
                foreach (var identity in claimsIdentity2)
                    localContext.Diffs.Add(identity.Name + ": " + identity.Label + ": " + identity.IsAuthenticated + ": " + identity.AuthenticationType + ": " + identity.RoleClaimType + ": " + identity.NameClaimType);

                localContext.Diffs.Add(Environment.NewLine + "claimsIdentity Matched:" + Environment.NewLine);
                foreach (var identity in matchedClaimsIdentities)
                    localContext.Diffs.Add(identity.Name + ": " + identity.Label + ": " + identity.IsAuthenticated + ": " + identity.AuthenticationType + ": " + identity.RoleClaimType + ": " + identity.NameClaimType);

                localContext.Diffs.Add(Environment.NewLine);
            }

            return context.Merge(localContext);
        }

        public static bool AreEqual(object t1, object t2)
        {
            return AreEqual(t1, t2, CompareContext.Default);
        }

        public static bool AreEqual(object t1, object t2, CompareContext context)
        {
            if (t1 == null && t2 == null)
                return true;

            if (t1 == null)
            {
                context.Diffs.Add($"t1 == null, t2 != null, (type: {t2.GetType()}, value: {t2.ToString()}).");
                return false;
            }

            if (t2 == null)
            {
                context.Diffs.Add($"t1 != null, t2 == null, (type: {t1.GetType()}), value: {t1.ToString()}).");
                return false;
            }

            if (ReferenceEquals(t1, t2))
                return true;

            if (t1 is TokenValidationParameters)
                return AreTokenValidationParametersEqual(t1 as TokenValidationParameters, t2 as TokenValidationParameters, context);
            else if (t1 is Claim)
                return AreClaimsEqual(t1 as Claim, t2 as Claim, context);
            else if (t1 is ClaimsIdentity)
                return AreClaimsIdentitiesEqual(t1 as ClaimsIdentity, t2 as ClaimsIdentity, context);
            else if (t1 is ClaimsPrincipal)
                return AreClaimsPrincipalsEqual(t1 as ClaimsPrincipal, t2 as ClaimsPrincipal, context);
            else if (t1 is IDictionary<string, string>)
                return AreDictionariesEqual(t1 as Dictionary<string, string>, t2 as Dictionary<string, string>, context);
            else if (t1 is JsonWebKey)
                return AreJsonWebKeysEqual(t1 as JsonWebKey, t2 as JsonWebKey, context);
            else if (t1 is JsonWebKeySet)
                return AreJsonWebKeySetsEqual(t1 as JsonWebKeySet, t2 as JsonWebKeySet, context);
            else if (t1 is JwtHeader)
                return AreJwtHeadersEqual(t1 as JwtHeader, t2 as JwtHeader, context);
            else if (t1 is JwtPayload)
                return AreJwtPayloadsEqual(t1 as JwtPayload, t2 as JwtPayload, context);
            else if (t1 is JwtSecurityToken)
                return AreJwtSecurityTokensEqual(t1 as JwtSecurityToken, t2 as JwtSecurityToken, context);
            else if (t1 is IEnumerable<Claim>)
                return AreClaimsEnumsEqual(t1 as IEnumerable<Claim>, t2 as IEnumerable<Claim>, context);
            else if (t1 is IEnumerable<ClaimsIdentity>)
                return AreClaimsIdentitiesEnumsEqual(t1 as IEnumerable<ClaimsIdentity>, t2 as IEnumerable<ClaimsIdentity>, context);
            else if (t1 is IEnumerable<SecurityKey>)
                return AreEnumsEqual<SecurityKey>(t1 as IEnumerable<SecurityKey>, t2 as IEnumerable<SecurityKey>, context, AreSecurityKeysEqual);
            else if (t1 is IEnumerable<string>)
                return AreEnumsEqual<string>(t1 as IEnumerable<string>, t2 as IEnumerable<string>, context, AreStringsEqual);
            else if (t1 is string)
                return AreStringsEqual(t1 as string, t2 as string, context);
            else if (t1 is Dictionary<string, object>)
                return AreDictionariesEqual(t1 as Dictionary<string, object>, t2 as Dictionary<string, object>, context);
            else if (t1 is Dictionary<string, object>.ValueCollection)
                return AreValueCollectionsEqual(t1 as Dictionary<string, object>.ValueCollection, t2 as Dictionary<string, object>.ValueCollection, context);
            else if (t1 is Newtonsoft.Json.Linq.JArray)
                return AreJArraysEqual(t1 as Newtonsoft.Json.Linq.JArray, t2 as Newtonsoft.Json.Linq.JArray, context);
            else if (t1 is IEnumerable<object>)
                return AreEnumsEqual<object>(t1 as IEnumerable<object>, t2 as IEnumerable<object>, context, AreObjectsEqual);
            else if (t1 is AudienceValidator)
                return AreAudienceValidatorsEqual(t1 as AudienceValidator, t1 as AudienceValidator, context);
            else if (t1 is LifetimeValidator)
                return AreLifetimeValidatorsEqual(t1 as LifetimeValidator, t1 as LifetimeValidator, context);
            else if (t1 is IssuerSigningKeyResolver)
                return AreIssuerSigningKeyResolversEqual(t1 as IssuerSigningKeyResolver, t1 as IssuerSigningKeyResolver, context);
            else if (t1 is IssuerSigningKeyValidator)
                return AreIssuerSigningKeyValidatorsEqual(t1 as IssuerSigningKeyValidator, t1 as IssuerSigningKeyValidator, context);
            else if (t1 is IssuerValidator)
                return AreIssuerValidatorsEqual(t1 as IssuerValidator, t1 as IssuerValidator, context);
            else if (t1 is KeyInfo)
                return AreKeyInfosEqual(t1 as KeyInfo, t2 as KeyInfo, context);
            else if (t1 is OpenIdConnectConfiguration)
                return AreOpenIdConnectConfigurationsEqual(t1 as OpenIdConnectConfiguration, t2 as OpenIdConnectConfiguration, context);
            else if (t1 is OpenIdConnectMessage)
                return AreOpenIdConnectMessagesEqual(t1 as OpenIdConnectMessage, t2 as OpenIdConnectMessage, context);
            else if (t1 is Reference)
                return AreReferencesEqual(t1 as Reference, t2 as Reference, context);
            else if (t1 is Signature)
                return AreSignaturesEqual(t1 as Signature, t2 as Signature, context);
            else if (t1 is SignedInfo)
                return AreSignedInfosEqual(t1 as SignedInfo, t2 as SignedInfo, context);
            else if (t1 is SignatureValidator)
                return AreSignatureValidatorsEqual(t1 as SignatureValidator, t2 as SignatureValidator, context);
            else if (t1 is WsFederationConfiguration)
                return AreWsFederationConfigurationsEqual(t1 as WsFederationConfiguration, t2 as WsFederationConfiguration, context);
            else if (t1 is WsFederationMessage)
                return AreWsFederationMessagesEqual(t1 as WsFederationMessage, t2 as WsFederationMessage, context);
            else if (t1 is SamlAction)
                return AreSamlActionsEqual(t1 as SamlAction, t2 as SamlAction, context);
            else if (t1 is SamlAssertion)
                return AreSamlAssertionsEqual(t1 as SamlAssertion, t2 as SamlAssertion, context);
            else if (t1 is SamlAdvice)
                return AreSamlAdvicesEqual(t1 as SamlAdvice, t2 as SamlAdvice, context);
            else if (t1 is SamlAttribute)
                return AreSamlAttributesEqual(t1 as SamlAttribute, t2 as SamlAttribute, context);
            else if (t1 is SamlAttributeStatement)
                return AreSamlAttributeStatementsEqual(t1 as SamlAttributeStatement, t2 as SamlAttributeStatement, context);
            else if (t1 is SamlAudienceRestrictionCondition)
                return AreSamlAudienceRestrictionConditionsEqual(t1 as SamlAudienceRestrictionCondition, t2 as SamlAudienceRestrictionCondition, context);
            else if (t1 is SamlAuthenticationStatement)
                return AreSamlAuthenticationStatementsEqual(t1 as SamlAuthenticationStatement, t2 as SamlAuthenticationStatement, context);
            else if (t1 is SamlAuthorizationDecisionStatement)
                return AreSamlAuthorizationDecisionStatementsEqual(t1 as SamlAuthorizationDecisionStatement, t2 as SamlAuthorizationDecisionStatement, context);
            else if (t1 is SamlConditions)
                return AreSamlConditionsEqual(t1 as SamlConditions, t2 as SamlConditions, context);
            else if (t1 is SamlEvidence)
                return AreSamlEvidencesEqual(t1 as SamlEvidence, t2 as SamlEvidence, context);
            else if (t1 is SamlStatement)
                return AreSamlStatementsEqual(t1 as SamlStatement, t2 as SamlStatement, context);
            else if (t1 is SamlSubject)
                return AreSamlSubjectsEqual(t1 as SamlSubject, t2 as SamlSubject, context);
            else if (t1 is Transform)
                return AreTransformsEqual(t1 as Transform, t2 as Transform, context);
            else
            {
                var localContext = new CompareContext(context);
                ContinueCheckingEquality(t1, t2, localContext);
                return context.Merge(localContext);
            }
        }

        public static bool AreSamlActionsEqual(SamlAction action1, SamlAction action2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(action1, action2, context))
                CompareAllPublicProperties(action1, action2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreSamlAssertionsEqual(SamlAssertion assertion1, SamlAssertion assertion2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(assertion1, assertion2, context))
                CompareAllPublicProperties(assertion1, assertion2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreSamlAdvicesEqual(SamlAdvice advice1, SamlAdvice advice2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(advice1, advice2, context))
                CompareAllPublicProperties(advice1, advice2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreSamlAttributesEqual(SamlAttribute attribute1, SamlAttribute attribute2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(attribute1, attribute2, context))
                CompareAllPublicProperties(attribute1, attribute2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreSamlAttributeStatementsEqual(SamlAttributeStatement statement1, SamlAttributeStatement statement2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(statement1, statement2, context))
                CompareAllPublicProperties(statement1, statement2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreSamlAudienceRestrictionConditionsEqual(SamlAudienceRestrictionCondition condition1, SamlAudienceRestrictionCondition condition2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(condition1, condition2, context))
                CompareAllPublicProperties(condition1, condition2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreSamlAuthenticationStatementsEqual(SamlAuthenticationStatement statement1, SamlAuthenticationStatement statement2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(statement1, statement2, context))
                CompareAllPublicProperties(statement1, statement2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreSamlAuthorizationDecisionStatementsEqual(SamlAuthorizationDecisionStatement statement1, SamlAuthorizationDecisionStatement statement2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(statement1, statement2, context))
                CompareAllPublicProperties(statement1, statement2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreSamlConditionsEqual(SamlConditions conditions1, SamlConditions conditions2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(conditions1, conditions2, context))
                CompareAllPublicProperties(conditions1, conditions2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreSamlEvidencesEqual(SamlEvidence evidence1, SamlEvidence evidence2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(evidence1, evidence2, context))
                CompareAllPublicProperties(evidence1, evidence2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreSamlStatementsEqual(SamlStatement statement1, SamlStatement statement2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(statement1, statement2, context))
                CompareAllPublicProperties(statement1, statement2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreSamlSubjectsEqual(SamlSubject subject1, SamlSubject subject2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(subject1, subject2, context))
                CompareAllPublicProperties(subject1, subject2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreJArraysEqual(Newtonsoft.Json.Linq.JArray a1, Newtonsoft.Json.Linq.JArray a2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(a1, a2, localContext))
                return context.Merge(localContext);

            if (a1.Count != a2.Count)
                localContext.Diffs.Add($"a1.Count != a2.Count. '{a1.Count}' : '{a2.Count}'");

            return context.Merge(localContext);
        }

        private static bool AreObjectsEqual(object obj1, object obj2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(obj1, obj2, localContext))
                return context.Merge(localContext);

            AreEqual(obj1, obj2, localContext);

            return context.Merge(localContext);
        }

        private static bool AreValueCollectionsEqual(Dictionary<string, object>.ValueCollection vc1, Dictionary<string, object>.ValueCollection vc2, CompareContext context)
        {
            return true;
        }

        public static bool AreBytesEqual(byte[] bytes1, byte[] bytes2)
        {
            if (bytes1 == null && bytes2 == null)
            {
                return true;
            }

            if (bytes1 == null || bytes2 == null)
            {
                return false;
            }

            if (bytes1.Length != bytes2.Length)
            {
                return false;
            }

            for (int i = 0; i < bytes1.Length; i++)
            {
                if (bytes1[i] != bytes2[i])
                {
                    return false;
                }
            }

            return true;
        }

        public static bool AreClaimsEqual(Claim claim1, Claim claim2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(claim1, claim2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(claim1, claim2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreClaimsIdentitiesEqual(ClaimsIdentity identity1, ClaimsIdentity identity2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(identity1, identity2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(identity1, identity2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreClaimsPrincipalsEqual(ClaimsPrincipal principal1, ClaimsPrincipal principal2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(principal1, principal2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(principal1, principal2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreDictionariesEqual(IDictionary<string, object> dictionary1, IDictionary<string, object> dictionary2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(dictionary1, dictionary2, localContext))
                return context.Merge(localContext);

            if (dictionary1.Count != dictionary2.Count)
                localContext.Diffs.Add($"(dictionary1.Count != dictionary2.Count: {dictionary1.Count}, {dictionary2.Count})");

            int numMatched = 0;
            foreach (string key in dictionary1.Keys)
            {
                if (dictionary2.ContainsKey(key))
                {
                    if (dictionary1[key].GetType() != dictionary2[key].GetType())
                    {
                        localContext.Diffs.Add($"dictionary1[{key}].GetType() != dictionary2[{key}].GetType(). '{dictionary1[key].GetType()}' : '{dictionary2[key].GetType()}'");
                        continue;
                    }

                    // for now just typing strings, should expand types.
                    var obj1 = dictionary1[key];
                    var obj2 = dictionary2[key];
                    if (obj1 is int || obj1 is long || obj1 is DateTime || obj1 is bool || obj1 is double || obj1 is System.TimeSpan)
                    {
                        if (!obj1.Equals(obj2))
                            localContext.Diffs.Add(BuildStringDiff(key + ": ", obj1, obj2));
                    }
                    else
                    {
                        if (AreEqual(obj1, obj2, context))
                            numMatched++;
                    }
                }
                else
                {
                    localContext.Diffs.Add("dictionary1[key] ! found in dictionary2. key: " + key);
                }
            }

            return context.Merge(localContext);
        }

        public static bool AreDictionariesEqual(IDictionary<string, string> dictionary1, IDictionary<string, string> dictionary2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(dictionary1, dictionary2, localContext))
                return context.Merge(localContext);

            if (dictionary1.Count != dictionary2.Count)
                localContext.Diffs.Add($"(dictionary1.Count != dictionary2.Count: {dictionary1.Count}, {dictionary2.Count})");

            int numMatched = 0;
            foreach (string key in dictionary1.Keys)
            {
                if (dictionary2.ContainsKey(key))
                {
                    if (!dictionary1[key].Equals(dictionary2[key]))
                    {
                        localContext.Diffs.Add($"dictionary1[key] != dictionary2[key], key: '{key}' value1, value2: '{dictionary1[key]}' + '{dictionary2[key]}'");
                    }
                    else
                    {
                        numMatched++;
                    }
                }
                else
                {
                    localContext.Diffs.Add("dictionary1[key] ! found in dictionary2. key: " + key);
                }
            }

            context.Diffs.AddRange(localContext.Diffs);
            return localContext.Diffs.Count == 0;
        }

        public static bool AreJsonWebKeysEqual(JsonWebKey jsonWebkey1, JsonWebKey jsonWebkey2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(jsonWebkey1, jsonWebkey2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(jsonWebkey1, jsonWebkey2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreJsonWebKeySetsEqual(JsonWebKeySet jsonWebKeySet1, JsonWebKeySet jsonWebKeySet2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(jsonWebKeySet1, jsonWebKeySet2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(jsonWebKeySet1, jsonWebKeySet2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreJwtHeadersEqual(JwtHeader header1, JwtHeader header2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(header1, header2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(header1, header2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreJwtPayloadsEqual(JwtPayload payload1, JwtPayload payload2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(payload1, payload2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(payload1, payload2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreJwtSecurityTokensEqual(JwtSecurityToken jwt1, JwtSecurityToken jwt2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(jwt1, jwt2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(jwt1, jwt2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreOpenIdConnectConfigurationsEqual(OpenIdConnectConfiguration configuration1, OpenIdConnectConfiguration configuration2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(configuration1, configuration2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(configuration1, configuration2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreOpenIdConnectMessagesEqual(OpenIdConnectMessage message1, OpenIdConnectMessage message2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(message1, message1, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(message1, message1, localContext);
            return context.Merge(localContext);
        }

        public static bool AreSecurityKeysEqual(SecurityKey securityKey1, SecurityKey securityKey2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(securityKey1, securityKey2, localContext))
                return context.Merge(localContext);

            // X509SecurityKey doesn't have to use reflection to get cert.
            X509SecurityKey x509Key1 = securityKey1 as X509SecurityKey;
            X509SecurityKey x509Key2 = securityKey2 as X509SecurityKey;
            if (x509Key1 != null && x509Key2 != null)
                CompareAllPublicProperties(x509Key1, x509Key2, localContext);

            SymmetricSecurityKey symKey1 = securityKey1 as SymmetricSecurityKey;
            SymmetricSecurityKey symKey2 = securityKey2 as SymmetricSecurityKey;
            if (symKey1 != null && symKey2 != null)
                CompareAllPublicProperties(symKey1, symKey2, localContext);

            RsaSecurityKey rsaKey1 = securityKey1 as RsaSecurityKey;
            RsaSecurityKey rsaKey2 = securityKey2 as RsaSecurityKey;
            if (rsaKey1 != null && rsaKey2 != null)
            {
                CompareAllPublicProperties(rsaKey1, rsaKey2, localContext);
                AreRsaParametersEqual(rsaKey1.Parameters, rsaKey2.Parameters, localContext);
            }

            return context.Merge(localContext);
        }

        private static bool AreReferencesEqual(Reference reference1, Reference reference2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(reference1, reference2, localContext))
                CompareAllPublicProperties(reference1, reference2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreRsaParametersEqual(RSAParameters rsaParameters1, RSAParameters rsaParameters2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(rsaParameters1, rsaParameters2, localContext))
                return context.Merge(localContext);

            if (!AreBytesEqual(rsaParameters1.D, rsaParameters2.D))
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.D, rsaParameters2.D)");

            if (!AreBytesEqual(rsaParameters1.DP, rsaParameters2.DP))
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.DP, rsaParameters2.DP)");

            if (!AreBytesEqual(rsaParameters1.DQ, rsaParameters2.DQ))
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.DQ, rsaParameters2.DQ)");

            if (!AreBytesEqual(rsaParameters1.Exponent, rsaParameters2.Exponent))
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.Exponent, rsaParameters2.Exponent)");

            if (!AreBytesEqual(rsaParameters1.InverseQ, rsaParameters2.InverseQ))
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.InverseQ, rsaParameters2.InverseQ)");

            if (!AreBytesEqual(rsaParameters1.Modulus, rsaParameters2.Modulus))
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.Modulus, rsaParameters2.Modulus)");

            if (!AreBytesEqual(rsaParameters1.P, rsaParameters2.P))
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.P, rsaParameters2.P)");

            if (!AreBytesEqual(rsaParameters1.Q, rsaParameters2.Q))
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.Q, rsaParameters2.Q)");

            return context.Merge(localContext);
        }

        public static bool AreSecurityTokensEqual(SecurityToken token1, SecurityToken token2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(token1, token2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(token1, token2, localContext);
            return context.Merge(localContext);
        }

        private static bool AreSigningCredentialsEqual(SigningCredentials signingCredentials1, SigningCredentials signingCredentials2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(signingCredentials1, signingCredentials2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(signingCredentials1, signingCredentials2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreStringsEqual(string str1, string str2)
        {
            if (string.IsNullOrEmpty(str1) && string.IsNullOrEmpty(str2))
                return true;

            if (ReferenceEquals(str1, str2))
                return true;

            if (str1 == null || str2 == null)
                return false;

            return string.Equals(str1, str2, StringComparison.Ordinal);
        }

        public static bool AreStringsEqual(string str1, string str2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(str1, str2, localContext))
                return context.Merge(localContext);

            if (string.IsNullOrEmpty(str1) && string.IsNullOrEmpty(str2))
                return true;

            if (ReferenceEquals(str1, str2))
                return true;

            if (str1 == null || str2 == null)
                localContext.Diffs.Add("(str1 == null || str2 == null)");

            if (!string.Equals(str1, str2, context.StringComparison))
                localContext.Diffs.Add($"'{str1}' != '{str2}' --- StringComparison: '{context.StringComparison}'");

            return context.Merge(localContext);
        }

        public static bool AreTokenValidationParametersEqual(TokenValidationParameters validationParameters1, TokenValidationParameters validationParameters2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(validationParameters1, validationParameters2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(validationParameters1, validationParameters2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreTransformsEqual(Transform transform1, Transform transform2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(transform1, transform2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(transform1, transform2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreAudienceValidatorsEqual(AudienceValidator validator1, AudienceValidator validator2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            ContinueCheckingEquality(validator1, validator2, context);
            return context.Merge(localContext);
        }

        public static bool AreKeyInfosEqual(KeyInfo keyInfo1, KeyInfo keyInfo2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(keyInfo1, keyInfo2, context))
                CompareAllPublicProperties(keyInfo1, keyInfo2, localContext);

            return context.Merge(localContext);
        }

        private static bool AreLifetimeValidatorsEqual(LifetimeValidator validator1, LifetimeValidator validator2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            ContinueCheckingEquality(validator1, validator2, context);
            return context.Merge(localContext);
        }

        private static bool AreIssuerSigningKeyResolversEqual(IssuerSigningKeyResolver keyResolver1, IssuerSigningKeyResolver keyResolver2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            ContinueCheckingEquality(keyResolver1, keyResolver2, context);
            return context.Merge(localContext);
        }

        private static bool AreIssuerSigningKeyValidatorsEqual(IssuerSigningKeyValidator validator1, IssuerSigningKeyValidator validator2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            ContinueCheckingEquality(validator1, validator2, context);
            return context.Merge(localContext);
        }

        private static bool AreIssuerValidatorsEqual(IssuerValidator validator1, IssuerValidator validator2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            ContinueCheckingEquality(validator1, validator2, context);
            return context.Merge(localContext);
        }

        public static bool AreSignaturesEqual(Signature signature1, Signature signature2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(signature1, signature2, localContext))
                CompareAllPublicProperties(signature1, signature2, localContext);

            return context.Merge(localContext);
        }

        private static bool AreSignatureValidatorsEqual(SignatureValidator validator1, SignatureValidator validator2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            ContinueCheckingEquality(validator1, validator2, context);
            return context.Merge(localContext);
        }

        public static bool AreSignedInfosEqual(SignedInfo signedInfo1, SignedInfo signedInfo2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(signedInfo1, signedInfo2, localContext))
                CompareAllPublicProperties(signedInfo1, signedInfo2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreWsFederationConfigurationsEqual(WsFederationConfiguration configuration1, WsFederationConfiguration configuration2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(configuration1, configuration2, localContext))
                CompareAllPublicProperties(configuration1, configuration2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreWsFederationMessagesEqual(WsFederationMessage message1, WsFederationMessage message2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(message1, message2, localContext))
                CompareAllPublicProperties(message1, message2, localContext);

            return context.Merge(localContext);

            //if (message1.Parameters.Count != message2.Parameters.Count)
            //    localContext.Diffs.Add($" message1.Parameters.Count != message2.Parameters.Count: {message1.Parameters.Count}, {message2.Parameters.Count}");

            //var stringComparer = StringComparer.Ordinal;
            //foreach (var param in message1.Parameters)
            //{
            //    if (!message2.Parameters.TryGetValue(param.Key, out string value2))
            //        localContext.Diffs.Add($" WsFederationMessage.message1.Parameters.param.Key missing in message2: {param.Key}");
            //    else if (param.Value != value2)
            //        localContext.Diffs.Add($" WsFederationMessage.message1.Parameters.param.Value !=  message2.Parameters.param.Value: {param.Key}, {param.Value}, {value2}");
            //}

            //foreach (var param in message2.Parameters)
            //{
            //    if (!message1.Parameters.TryGetValue(param.Key, out string value1))
            //        localContext.Diffs.Add($" WsFederationMessage.message2.Parameters.param.Key missing in message1: {param.Key}");
            //    else if (param.Value != value1)
            //        localContext.Diffs.Add($" WsFederationMessage.message2.Parameters.param.Value !=  message1.Parameters.param.Value: {param.Key}, {param.Value}, {value1}");
            //}
        }

        public static string BuildStringDiff(string label, object str1, object str2)
        {
            return (label ?? "label") + ": '" + GetString(str1) + "', '" + GetString(str2) + "'";
        }

        public static bool CompareAllPublicProperties(object obj1, object obj2, CompareContext context)
        {
            Type type = obj1.GetType();
            var localContext = new CompareContext(context);

            // public instance properties
            PropertyInfo[] propertyInfos = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);

            // Touch each public property
            foreach (PropertyInfo propertyInfo in propertyInfos)
            {
                var propertyContext = new CompareContext(context);
                try
                {
                    // this is true if type is System.Object, no reason to go lower.
                    if (propertyInfo.PropertyType.BaseType == null)
                        continue;

                    if (type == typeof(Claim) && context.IgnoreSubject && propertyInfo.Name == "Subject")
                        continue;

                    if (type == typeof(Signature) && context.IgnoreTokenStreamReader)
                        continue;

                    if (propertyInfo.GetMethod != null)
                    {
                        object val1 = propertyInfo.GetValue(obj1, null);
                        object val2 = propertyInfo.GetValue(obj2, null);
                        if ((val1 == null) && (val2 == null))
                            continue;

                        if ((val1 == null) || (val2 == null))
                        {
                            localContext.Diffs.Add(BuildStringDiff(propertyInfo.Name + ": ", val1, val2));
                        }
                        else if (val1 is int || val1 is long || val1 is DateTime || val1 is bool || val1 is double || val1 is System.TimeSpan)
                        {
                            if (!val1.Equals(val2))
                                localContext.Diffs.Add(BuildStringDiff(propertyInfo.Name + ": ", val1, val2));
                        }
                        else
                        {
                            AreEqual(val1, val2, propertyContext);
                            localContext.Merge("propertyInfo.Name: " + propertyInfo.Name, propertyContext);
                        }
                    }
                }
                catch (Exception ex)
                {
                    localContext.Diffs.Add($"Reflection failed getting 'PropertyInfo: {propertyInfo.Name}'. Exception: '{ex}'.");
                }
            }

            return context.Merge($"CompareAllPublicProperties for: {type}", localContext);
        }

        public static bool ContinueCheckingEquality(object obj1, object obj2, CompareContext context)
        {
            if (obj1 == null && obj2 == null)
                return false;

            if (obj1 == null)
            {
                context.Diffs.Add(BuildStringDiff(obj2.GetType().ToString() + ": ", obj1, obj2));
                return false;
            }

            if (obj2 == null)
            {
                context.Diffs.Add(BuildStringDiff(obj1.GetType().ToString() + ": ", obj1, obj2));
                return false;
            }

            if (object.ReferenceEquals(obj1, obj2))
                return false;

            if (!context.IgnoreType && (obj1.GetType() != obj2.GetType()))
                context.Diffs.Add($"obj1.GetType() != obj2.GetType(). '{obj1} : {obj2}'");

            return true;
        }

        private static string GetString(object str)
        {
            if (str is string retval)
                return retval;

            if (str is IEnumerable<string> enum1)
                return TestUtilities.SerializeAsSingleCommaDelimitedString(enum1);

            else
                return string.Format(CultureInfo.InvariantCulture, "{0}", (str ?? "null"));
        }
    }
}
