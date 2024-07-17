// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//#define CheckIfCompared

// Uncomment 'CheckIfCompared' to find out if any of your types are not being compared.
// The default behavior is to compare all public properties, if there is a type that is not being compared you will get an exception.
// _equalityDict contains all the types that are being compared and how they are compared.
// Add the string representing the type "typeof(YourType)" and matching delegate for comparing to the dictionary.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Newtonsoft.Json.Linq;

namespace Microsoft.IdentityModel.TestUtils
{
    public class IdentityComparer
    {
        // Dictionary of types and the validation function.
        // Keep entries in alphabetical order
        private static readonly Dictionary<string, Func<object, object, CompareContext, bool>> _equalityDict =
            new Dictionary<string, Func<object, object, CompareContext, bool>>
            {
                { typeof(AuthenticationProtocolMessage).ToString(), CompareAllPublicProperties },
                { typeof(bool).ToString(), AreBoolsEqual },
                { typeof(byte[]).ToString(), AreBytesEqual },
                { typeof(CanonicalizingTransfrom).ToString(), CompareAllPublicProperties },
                { typeof(Claim).ToString(), CompareAllPublicProperties },
                { typeof(ClaimsIdentity).ToString(), CompareAllPublicProperties },
                { typeof(CaseSensitiveClaimsIdentity).ToString(), CompareAllPublicProperties },
                { typeof(ClaimsPrincipal).ToString(), CompareAllPublicProperties },
                { typeof(Collection<SecurityKey>).ToString(), ContinueCheckingEquality },
                { typeof(DateTime).ToString(), AreDateTimesEqual },
                { typeof(Dictionary<string, object>).ToString(), AreObjectDictionariesEqual },
                { typeof(Dictionary<string, object>.ValueCollection).ToString(), AreValueCollectionsEqual },
                { typeof(ExclusiveCanonicalizationTransform).ToString(), CompareAllPublicProperties },
                { typeof(EnvelopedSignatureTransform).ToString(), CompareAllPublicProperties },
                { typeof(IDictionary<string, string>).ToString(), AreStringDictionariesEqual},
                { typeof(IEnumerable<Claim>).ToString(), AreClaimsEnumsEqual },
                { typeof(IEnumerable<ClaimsIdentity>).ToString(), AreClaimsIdentitiesEnumsEqual },
                { typeof(IEnumerable<CaseSensitiveClaimsIdentity>).ToString(), AreClaimsIdentitiesEnumsEqual },
                { typeof(IEnumerable<object>).ToString(), AreObjectEnumsEqual },
                { typeof(IEnumerable<SecurityKey>).ToString(), AreSecurityKeyEnumsEqual },
                { typeof(IEnumerable<string>).ToString(), AreStringEnumsEqual },
                { typeof(IEnumerable<X509Data>).ToString(), AreX509DataEnumsEqual },
                { typeof(int).ToString(), AreIntsEqual },
                { typeof(IssuerSerial).ToString(), CompareAllPublicProperties },
                { typeof(IssuerValidationResult).ToString(), AreIssuerValidationResultsEqual },
                { typeof(JArray).ToString(), AreJArraysEqual },
                { typeof(JObject).ToString(), AreJObjectsEqual },
                { typeof(JsonElement).ToString(), AreJsonElementsEqual },
                { typeof(JsonWebKey).ToString(), AreJsonWebKeysEqual },
                { typeof(JsonWebKeySet).ToString(), AreJsonWebKeysEqual },
                { typeof(JsonWebToken).ToString(), CompareAllPublicProperties },
                { typeof(JsonWebTokenHandler).ToString(), CompareAllPublicProperties },
                { typeof(JwtHeader).ToString(), CompareAllPublicProperties },
                { typeof(JwtPayload).ToString(), CompareAllPublicProperties },
                { typeof(JwtSecurityToken).ToString(), CompareAllPublicProperties },
                { typeof(JwtSecurityTokenHandler).ToString(), CompareAllPublicProperties },
                { typeof(KeyInfo).ToString(), CompareAllPublicProperties },
                { typeof(List<JsonWebKey>).ToString(), AreJsonWebKeyEnumsEqual },
                { typeof(List<KeyInfo>).ToString(), AreKeyInfoEnumsEqual },
                { typeof(List<SamlAssertion>).ToString(), AreSamlAssertionEnumsEqual},
                { typeof(List<SamlAttribute>).ToString(), AreSamlAttributeEnumsEqual },
                { typeof(List<SamlAuthorityBinding>).ToString(), AreSamlAuthorityBindingEnumsEqual },
                { typeof(List<SamlAction>).ToString(), AreSamlActionEnumsEqual },
                { typeof(List<SamlStatement>).ToString(), AreSamlStatementEnumsEqual },
                { typeof(List<SamlCondition>).ToString(), AreSamlConditionEnumsEqual },
                { typeof(List<SecurityKey>).ToString(), AreSecurityKeyEnumsEqual },
                { typeof(List<Reference>).ToString(), AreReferenceEnumsEqual },
                { typeof(List<Uri>).ToString(), AreUriEnumsEqual },
                { typeof(long).ToString(), AreLongsEqual },
                { typeof(OpenIdConnectConfiguration).ToString(), CompareAllPublicProperties },
                { typeof(OpenIdConnectMessage).ToString(), CompareAllPublicProperties },
                { typeof(Reference).ToString(), CompareAllPublicProperties },
                { typeof(RSAKeyValue).ToString(), CompareAllPublicProperties },
                { typeof(RsaSecurityKey).ToString(), CompareAllPublicProperties },
                { typeof(RSAParameters).ToString(), AreRsaParametersEqual },
                { typeof(SamlAction).ToString(), CompareAllPublicProperties },
                { typeof(SamlAudienceRestrictionCondition).ToString(), CompareAllPublicProperties },
                { typeof(SamlAssertion).ToString(), CompareAllPublicProperties},
                { typeof(SamlAttribute).ToString(), CompareAllPublicProperties },
                { typeof(SamlAttributeStatement).ToString(), CompareAllPublicProperties },
                { typeof(SamlAuthenticationStatement).ToString(), CompareAllPublicProperties },
                { typeof(SamlAuthorityBinding).ToString(), CompareAllPublicProperties },
                { typeof(SamlAuthorizationDecisionStatement).ToString(), CompareAllPublicProperties },
                { typeof(SamlCondition).ToString(), CompareAllPublicProperties },
                { typeof(SamlDoNotCacheCondition).ToString(), CompareAllPublicProperties },
                { typeof(SamlSecurityToken).ToString(), CompareAllPublicProperties },
                { typeof(SamlSecurityTokenHandler).ToString(), CompareAllPublicProperties },
                { typeof(SamlStatement).ToString(), CompareAllPublicProperties },
                { typeof(SamlSubject).ToString(), CompareAllPublicProperties },
                { typeof(Saml2Action).ToString(), CompareAllPublicProperties },
                { typeof(Saml2Advice).ToString(), CompareAllPublicProperties },
                { typeof(Saml2Assertion).ToString(), CompareAllPublicProperties },
                { typeof(Saml2Attribute).ToString(), CompareAllPublicProperties },
                { typeof(Saml2AttributeStatement).ToString(), CompareAllPublicProperties },
                { typeof(Saml2AudienceRestriction).ToString(), CompareAllPublicProperties },
                { typeof(Saml2AuthenticationContext).ToString(), CompareAllPublicProperties },
                { typeof(Saml2AuthenticationStatement).ToString(), CompareAllPublicProperties },
                { typeof(Saml2AuthorizationDecisionStatement).ToString(), CompareAllPublicProperties },
                { typeof(Saml2Conditions).ToString(), CompareAllPublicProperties },
                { typeof(Saml2Evidence).ToString(), CompareAllPublicProperties },
                { typeof(Saml2Id).ToString(), CompareAllPublicProperties },
                { typeof(Saml2NameIdentifier).ToString(), CompareAllPublicProperties },
                { typeof(Saml2ProxyRestriction).ToString(), CompareAllPublicProperties },
                { typeof(Saml2SecurityToken).ToString(), CompareAllPublicProperties },
                { typeof(Saml2Subject).ToString(), CompareAllPublicProperties },
                { typeof(Saml2SubjectConfirmation).ToString(), CompareAllPublicProperties },
                { typeof(Saml2SubjectConfirmationData).ToString(), CompareAllPublicProperties },
                { typeof(Saml2SubjectLocality).ToString(), CompareAllPublicProperties },
                { typeof(Saml2SecurityTokenHandler).ToString(), CompareAllPublicProperties },
                { typeof(SecurityKey).ToString(), CompareAllPublicProperties },
                { typeof(SecurityToken).ToString(), CompareAllPublicProperties},
                { typeof(SecurityTokenHandler).ToString(), CompareAllPublicProperties},
                { typeof(SecurityTokenExpiredException).ToString(), CompareAllPublicProperties},
                { typeof(SecurityTokenInvalidAlgorithmException).ToString(), CompareAllPublicProperties},
                { typeof(SecurityTokenInvalidAudienceException).ToString(), CompareAllPublicProperties},
                { typeof(SecurityTokenInvalidIssuerException).ToString(), CompareAllPublicProperties},
                { typeof(SecurityTokenInvalidSigningKeyException).ToString(), CompareAllPublicProperties},
                { typeof(SecurityTokenInvalidLifetimeException).ToString(), CompareAllPublicProperties},
                { typeof(SecurityTokenInvalidTypeException).ToString(), CompareAllPublicProperties},
                { typeof(SecurityTokenNotYetValidException).ToString(), CompareAllPublicProperties},
                { typeof(Signature).ToString(), CompareAllPublicProperties },
                { typeof(SignedInfo).ToString(), CompareAllPublicProperties },
                { typeof(SigningCredentials).ToString(), CompareAllPublicProperties },
                { typeof(string).ToString(), AreStringsEqual },
                { typeof(SymmetricSecurityKey).ToString(), CompareAllPublicProperties },
                { typeof(TimeSpan).ToString(), AreTimeSpansEqual },
                { typeof(TokenValidationParameters).ToString(), CompareAllPublicProperties },
                { typeof(Transform).ToString(), CompareAllPublicProperties },
                { typeof(WsFederationConfiguration).ToString(), CompareAllPublicProperties },
                { typeof(WsFederationMessage).ToString(), CompareAllPublicProperties },
                { typeof(Uri).ToString(), AreUrisEqual },
                { typeof(X509Certificate2).ToString(), AreX509Certificate2Equal },
                { typeof(X509Data).ToString(), CompareAllPublicProperties },
                { typeof(X509SigningCredentials).ToString(), CompareAllPublicProperties },
                { typeof(TokenValidationResult).ToString(), CompareAllPublicProperties },
            };

        // Keep methods in alphabetical order
        public static bool AreBoolsEqual(object object1, object object2, CompareContext context)
        {
            return AreBoolsEqual(object1, object2, "bool1", "bool2", context);
        }

        public static bool AreBoolsEqual(object object1, object object2, string name1, string name2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            var bool1 = (bool)object1;
            var bool2 = (bool)object2;

            if (bool1 == bool2)
                return true;

            if (bool1 != bool2)
            {
                localContext.Diffs.Add($"{name1} != {name2}");
                localContext.Diffs.Add($"'{bool1}'");
                localContext.Diffs.Add($"!=");
                localContext.Diffs.Add($"'{bool2}'");
            }

            return context.Merge(localContext);
        }

        public static bool AreBytesEqual(object object1, object object2, CompareContext context)
        {
            return AreBytesEqual(object1, object2, "bytes1", "bytes2", context);
        }

        public static bool AreBytesEqual(object object1, object object2, string name1, string name2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            var bytes1 = (byte[])object1;
            var bytes2 = (byte[])object2;
            if (bytes1.Length != bytes2.Length)
            {
                localContext.Diffs.Add($"{name1} != {name2}");
                localContext.Diffs.Add("(bytes1.Length != bytes2.Length)");
            }
            else
            {
                bool firstDiff = true;
                for (int i = 0; i < bytes1.Length; i++)
                {
                    if (bytes1[i] != bytes2[i])
                    {
                        if (firstDiff)
                        {
                            firstDiff = false;
                            localContext.Diffs.Add($"{name1} != {name2}");
                        }

                        localContext.Diffs.Add($"'{bytes1}'");
                        localContext.Diffs.Add("!=");
                        localContext.Diffs.Add($"'{bytes2}'");
                    }
                }
            }

            return context.Merge(localContext);
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

        public static bool AreEnumsEqual<T>(IEnumerable<T> object1, IEnumerable<T> object2, CompareContext context, Func<T, T, CompareContext, bool> areEqual)
        {
            List<T> toMatch = (object1 == null) ? new List<T>() : new List<T>(object1);
            List<T> expectedValues = (object2 == null) ? new List<T>() : new List<T>(object2);

            if (toMatch.Count != expectedValues.Count)
            {
                context.Diffs.Add("toMatch.Count != expectedToMatch.Count: " + toMatch.Count + ", " + expectedValues.Count + ", typeof: " + object1.GetType().ToString());
                return false;
            }

            int numMatched = 0;
            int numToMatch = toMatch.Count;
            CompareContext localContext = new CompareContext(context);
            List<KeyValuePair<T, T>> matchedTs = new List<KeyValuePair<T, T>>();

            // helps debugging to see what didn't match
            List<T> notMatched = new List<T>();
            foreach (var t in object1)
            {
                var perItemContext = new CompareContext(localContext);
                bool matched = false;
                for (int i = 0; i < expectedValues.Count; i++)
                {
                    if (areEqual(t, expectedValues[i], perItemContext))
                    {
                        numMatched++;
                        matchedTs.Add(new KeyValuePair<T, T>(expectedValues[i], t));
                        matched = true;
                        expectedValues.RemoveAt(i);
                        perItemContext.Diffs.Clear();
                        break;
                    }

                    perItemContext.Diffs.Add("===========================\n\r");
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

        public static bool AreClaimsEnumsEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            var claims1 = new List<Claim>();
            foreach (Claim c1 in (IEnumerable<Claim>)object1)
                if (!context.ClaimTypesToIgnoreWhenComparing.Contains(c1.Type))
                    claims1.Add(c1);

            var claims2 = new List<Claim>();
            foreach (Claim c2 in (IEnumerable<Claim>)object2)
                if (!context.ClaimTypesToIgnoreWhenComparing.Contains(c2.Type))
                    claims2.Add(c2);

            if (claims1.Count != claims2.Count)
            {
                localContext.Diffs.Add($"claims1.Count != claims2.Count: {claims1.Count}, {claims2.Count}");
                localContext.Diffs.Add("claims1:");
                foreach (var claim in claims1)
                    localContext.Diffs.Add(claim.Type + ": " + claim.Value + ": " + claim.ValueType + ": " + claim.Issuer + ": " + claim.OriginalIssuer);

                localContext.Diffs.Add("claims2:");
                foreach (var claim in claims2)
                    localContext.Diffs.Add(claim.Type + ": " + claim.Value + ": " + claim.ValueType + ": " + claim.Issuer + ": " + claim.OriginalIssuer);
            }

            int numMatched = 0;
            int numToMatch = claims1.Count;
            var matchedClaims = new List<Claim>();
            var notMatched = new List<Claim>();
            foreach (Claim claim in claims1)
            {
                var perClaimContext = new CompareContext(localContext);
                bool matched = false;
                for (int i = 0; i < claims2.Count; i++)
                {
                    if (AreClaimsEqual(claim, claims2[i], perClaimContext))
                    {
                        numMatched++;
                        matchedClaims.Add(claim);
                        matched = true;
                        claims2.RemoveAt(i);
                        break;
                    }
                }

                if (!matched)
                    notMatched.Add(claim);
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

        public static bool AreClaimsIdentitiesEnumsEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            IEnumerable<ClaimsIdentity> t1 = (IEnumerable<ClaimsIdentity>)object1;
            IEnumerable<ClaimsIdentity> t2 = (IEnumerable<ClaimsIdentity>)object2;

            var claimsIdentity1 = new List<ClaimsIdentity>(t1);
            var claimsIdentity2 = new List<ClaimsIdentity>(t2);
            if (claimsIdentity1.Count != claimsIdentity2.Count)
            {
                localContext.Diffs.Add($"claimsIdentity1.Count != claimsIdentity2.Count: {claimsIdentity1.Count}, {claimsIdentity2.Count}");
                localContext.Diffs.Add("claimsIdentity1:");
                foreach (var identity in claimsIdentity1)
                    localContext.Diffs.Add(identity.Name + ": " + identity.Label + ": " + identity.IsAuthenticated + ": " + identity.AuthenticationType + ": " + identity.RoleClaimType + ": " + identity.NameClaimType);

                localContext.Diffs.Add("claimsIdentity2:");
                foreach (var identity in claimsIdentity2)
                    localContext.Diffs.Add(identity.Name + ": " + identity.Label + ": " + identity.IsAuthenticated + ": " + identity.AuthenticationType + ": " + identity.RoleClaimType + ": " + identity.NameClaimType);
            }

            int numMatched = 0;
            int numToMatch = claimsIdentity1.Count;
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
                    notMatched.Add(t);
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

        public static bool AreConfigurationValidationResultEqual(ConfigurationValidationResult result1, ConfigurationValidationResult result2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(result1, result2, localContext))
                CompareAllPublicProperties(result1, result2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreDateTimesEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            DateTime dateTime1 = (DateTime)object1;
            DateTime dateTime2 = (DateTime)object2;

            if (dateTime1 != dateTime2)
                localContext.Diffs.Add($"dateTime1 != dateTime2. '{dateTime1}' != '{dateTime2}'.");

            return context.Merge(localContext);
        }

        public static bool AreEqual(object object1, object object2)
        {
            return AreEqual(object1, object2, CompareContext.Default);
        }

        public static bool AreEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);

            // Check if either t1 or t2 are null or references of each other to see if we can terminate early.
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);
#if CheckIfCompared
            bool wasCompared = false;
#endif
            string inter;
            // Use a special function for comparison if required by the specific class of the object.
            if (_equalityDict.TryGetValue(object1.GetType().ToString(), out Func<Object, object, CompareContext, bool> areEqual))
            {
#if CheckIfCompared
                wasCompared = true;
#endif
                areEqual(object1, object2, localContext);
            }
            // Check if any of the interfaces that the class uses require a special function.
            else if ((inter = object1.GetType().GetInterfaces().Select(t => t.ToString()).Intersect(_equalityDict.Keys).FirstOrDefault()) != null)
            {
#if CheckIfCompared
                wasCompared = true;
#endif
                _equalityDict[inter](object1, object2, localContext);
            }

#if CheckIfCompared
            if (!wasCompared)
                localContext.Diffs.Add($"Objects were not handled: '{object1.GetType().ToString()}'.");
#endif

            return context.Merge(localContext);
        }

        public static bool AreIssuerValidationResultsEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, context))
                return context.Merge(localContext);

            return AreIssuerValidationResultsEqual(
                object1 as IssuerValidationResult,
                object2 as IssuerValidationResult,
                "IssuerValidationResult1",
                "IssuerValidationResult2",
                null,
                context);
        }

        internal static bool AreIssuerValidationResultsEqual(
            IssuerValidationResult issuerValidationResult1,
            IssuerValidationResult issuerValidationResult2,
            string name1,
            string name2,
            string stackPrefix,
            CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(issuerValidationResult1, issuerValidationResult2, localContext))
                return context.Merge(localContext);

            if (issuerValidationResult1.Issuer != issuerValidationResult2.Issuer)
                localContext.Diffs.Add($"IssuerValidationResult1.Issuer: {issuerValidationResult1.Issuer} != IssuerValidationResult2.Issuer: {issuerValidationResult2.Issuer}");

            if (issuerValidationResult1.IsValid != issuerValidationResult2.IsValid)
                localContext.Diffs.Add($"IssuerValidationResult1.IsValid: {issuerValidationResult1.IsValid} != IssuerValidationResult2.IsValid: {issuerValidationResult2.IsValid}");

            if (issuerValidationResult1.Source != issuerValidationResult2.Source)
                localContext.Diffs.Add($"IssuerValidationResult1.Source: {issuerValidationResult1.Source} != IssuerValidationResult2.Source: {issuerValidationResult2.Source}");

            // true => both are not null.
            if (ContinueCheckingEquality(issuerValidationResult1.Exception, issuerValidationResult2.Exception, localContext))
            {
                AreStringsEqual(
                    issuerValidationResult1.Exception.Message,
                    issuerValidationResult2.Exception.Message,
                    $"({name1})issuerValidationResult1.Exception.Message",
                    $"({name2})issuerValidationResult1.Exception.Message",
                    localContext);

                AreStringsEqual(
                    issuerValidationResult1.Exception.Source,
                    issuerValidationResult2.Exception.Source,
                    $"({name1})issuerValidationResult1.Exception.Source",
                    $"({name2})issuerValidationResult2.Exception.Source",
                    localContext);

                if (!string.IsNullOrEmpty(stackPrefix))
                    AreStringPrefixesEqual(
                        issuerValidationResult1.Exception.StackTrace.Trim(),
                        issuerValidationResult2.Exception.StackTrace.Trim(),
                        $"({name1})issuerValidationResult1.Exception.StackTrace",
                        $"({name2})issuerValidationResult2.Exception.StackTrace",
                        stackPrefix.Trim(),
                        localContext);
            }

            return context.Merge(localContext);
        }

        public static bool AreAudienceValidationResultsEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, context))
                return context.Merge(localContext);

            return AreAudienceValidationResultsEqual(
                object1 as AudienceValidationResult,
                object2 as AudienceValidationResult,
                "AudienceValidationResult1",
                "AudienceValidationResult2",
                null,
                context);
        }

        internal static bool AreAudienceValidationResultsEqual(
            AudienceValidationResult audienceValidationResult1,
            AudienceValidationResult audienceValidationResult2,
            string name1,
            string name2,
            string stackPrefix,
            CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(audienceValidationResult1, audienceValidationResult2, localContext))
                return context.Merge(localContext);

            if (audienceValidationResult1.Audience != audienceValidationResult2.Audience)
                localContext.Diffs.Add($"AudienceValidationResult1.Audience: '{audienceValidationResult1.Audience}' != AudienceValidationResult2.Audience: '{audienceValidationResult2.Audience}'");

            if (audienceValidationResult1.IsValid != audienceValidationResult2.IsValid)
                localContext.Diffs.Add($"AudienceValidationResult1.IsValid: {audienceValidationResult1.IsValid} != AudienceValidationResult2.IsValid: {audienceValidationResult2.IsValid}");

            // true => both are not null.
            if (ContinueCheckingEquality(audienceValidationResult1.Exception, audienceValidationResult2.Exception, localContext))
            {
                AreStringsEqual(
                    audienceValidationResult1.Exception.Message,
                    audienceValidationResult2.Exception.Message,
                    $"({name1})audienceValidationResult1.Exception.Message",
                    $"({name2})audienceValidationResult2.Exception.Message",
                    localContext);

                AreStringsEqual(
                    audienceValidationResult1.Exception.Source,
                    audienceValidationResult2.Exception.Source,
                    $"({name1})audienceValidationResult1.Exception.Source",
                    $"({name2})audienceValidationResult2.Exception.Source",
                    localContext);

                if (!string.IsNullOrEmpty(stackPrefix))
                    AreStringPrefixesEqual(
                        audienceValidationResult1.Exception.StackTrace.Trim(),
                        audienceValidationResult2.Exception.StackTrace.Trim(),
                        $"({name1})audienceValidationResult1.Exception.StackTrace",
                        $"({name2})audienceValidationResult2.Exception.StackTrace",
                        stackPrefix.Trim(),
                        localContext);
            }

            return context.Merge(localContext);
        }

        public static bool AreSigningKeyValidationResultsEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, context))
                return context.Merge(localContext);

            return AreSigningKeyValidationResultsEqual(
                object1 as SigningKeyValidationResult,
                object2 as SigningKeyValidationResult,
                "SigningKeyValidationResult1",
                "SigningKeyValidationResult2",
                null,
                context);
        }
      
        internal static bool AreSigningKeyValidationResultsEqual(
            SigningKeyValidationResult signingKeyValidationResult1,
            SigningKeyValidationResult signingKeyValidationResult2,
            string name1,
            string name2,
            string stackPrefix,
            CompareContext context)
        {
            var localContext = new CompareContext(context);
            AreSecurityKeysEqual(signingKeyValidationResult1.SigningKey, signingKeyValidationResult2.SigningKey, localContext);

            if (!ContinueCheckingEquality(signingKeyValidationResult1, signingKeyValidationResult2, localContext))
                return context.Merge(localContext);

            if (signingKeyValidationResult1.IsValid != signingKeyValidationResult2.IsValid)
                localContext.Diffs.Add($"SigningKeyValidationResult1.IsValid: {signingKeyValidationResult2.IsValid} != SigningKeyValidationResult2.IsValid: {signingKeyValidationResult2.IsValid}");

            if (signingKeyValidationResult1.ValidationFailureType != signingKeyValidationResult2.ValidationFailureType)
                localContext.Diffs.Add($"SigningKeyValidationResult1.ValidationFailureType: {signingKeyValidationResult1.ValidationFailureType} != SigningKeyValidationResult2.ValidationFailureType: {signingKeyValidationResult2.ValidationFailureType}");

            // true => both are not null.
            if (ContinueCheckingEquality(signingKeyValidationResult1.Exception, signingKeyValidationResult2.Exception, localContext))
            {
                AreStringsEqual(
                    signingKeyValidationResult1.Exception.Message,
                    signingKeyValidationResult2.Exception.Message,
                    $"({name1})signingKeyValidationResult1.Exception.Message",
                    $"({name2})signingKeyValidationResult2.Exception.Message",
                    localContext);

                AreStringsEqual(
                    signingKeyValidationResult1.Exception.Source,
                    signingKeyValidationResult2.Exception.Source,
                    $"({name1})signingKeyValidationResult1.Exception.Source",
                    $"({name2})signingKeyValidationResult2.Exception.Source",
                    localContext);

                if (!string.IsNullOrEmpty(stackPrefix))
                    AreStringPrefixesEqual(
                        signingKeyValidationResult1.Exception.StackTrace.Trim(),
                        signingKeyValidationResult2.Exception.StackTrace.Trim(),
                        $"({name1})signingKeyValidationResult1.Exception.StackTrace",
                        $"({name2})signingKeyValidationResult2.Exception.StackTrace",
                        stackPrefix.Trim(),
                        localContext);
            }
          
            return context.Merge(localContext);
        }
      
        public static bool AreLifetimeValidationResultsEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, context))
                return context.Merge(localContext);

            return AreLifetimeValidationResultsEqual(
                object1 as LifetimeValidationResult,
                object2 as LifetimeValidationResult,
                "LifetimeValidationResult1",
                "LifetimeValidationResult2",
                null,
                context);
        }

        internal static bool AreLifetimeValidationResultsEqual(
            LifetimeValidationResult lifetimeValidationResult1,
            LifetimeValidationResult lifetimeValidationResult2,
            string name1,
            string name2,
            string stackPrefix,
            CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(lifetimeValidationResult1, lifetimeValidationResult2, localContext))
                return context.Merge(localContext);

            if (!AreDatesEqualWithEpsilon(lifetimeValidationResult1.NotBefore, lifetimeValidationResult2.NotBefore, 1))
                localContext.Diffs.Add($"LifetimeValidationResult1.NotBefore: '{lifetimeValidationResult1.NotBefore}' != LifetimeValidationResult2.NotBefore: '{lifetimeValidationResult2.NotBefore}'");

            if (!AreDatesEqualWithEpsilon(lifetimeValidationResult1.Expires, lifetimeValidationResult2.Expires, 1))
                localContext.Diffs.Add($"LifetimeValidationResult1.Expires: '{lifetimeValidationResult1.Expires}' != LifetimeValidationResult2.Expires: '{lifetimeValidationResult2.Expires}'");

            if (lifetimeValidationResult1.IsValid != lifetimeValidationResult2.IsValid)
                localContext.Diffs.Add($"LifetimeValidationResult1.IsValid: {lifetimeValidationResult1.IsValid} != LifetimeValidationResult2.IsValid: {lifetimeValidationResult2.IsValid}");

            if (lifetimeValidationResult1.ValidationFailureType != lifetimeValidationResult2.ValidationFailureType)
                localContext.Diffs.Add($"LifetimeValidationResult1.ValidationFailureType: {lifetimeValidationResult1.ValidationFailureType} != LifetimeValidationResult2.ValidationFailureType: {lifetimeValidationResult2.ValidationFailureType}");

            // true => both are not null.
            if (ContinueCheckingEquality(lifetimeValidationResult1.Exception, lifetimeValidationResult2.Exception, localContext))
            {
                AreStringsEqual(
                    lifetimeValidationResult1.Exception.Message,
                    lifetimeValidationResult2.Exception.Message,
                    $"({name1})lifetimeValidationResult1.Exception.Message",
                    $"({name2})lifetimeValidationResult2.Exception.Message",
                    localContext);

                AreStringsEqual(
                    lifetimeValidationResult1.Exception.Source,
                    lifetimeValidationResult2.Exception.Source,
                    $"({name1})lifetimeValidationResult1.Exception.Source",
                    $"({name2})lifetimeValidationResult2.Exception.Source",
                    localContext);

                if (!string.IsNullOrEmpty(stackPrefix))
                    AreStringPrefixesEqual(
                        lifetimeValidationResult1.Exception.StackTrace.Trim(),
                        lifetimeValidationResult2.Exception.StackTrace.Trim(),
                        $"({name1})lifetimeValidationResult1.Exception.StackTrace",
                        $"({name2})lifetimeValidationResult2.Exception.StackTrace",
                        stackPrefix.Trim(),
                        localContext);
            }

            return context.Merge(localContext);
        }

        public static bool AreTokenReplayValidationResultsEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, context))
                return context.Merge(localContext);

            return AreTokenReplayValidationResultsEqual(
                object1 as ReplayValidationResult,
                object2 as ReplayValidationResult,
                "ReplayValidationResult1",
                "ReplayValidationResult2",
                null,
                context);
        }

        internal static bool AreTokenReplayValidationResultsEqual(
            ReplayValidationResult replayValidationResult1,
            ReplayValidationResult replayValidationResult2,
            string name1,
            string name2,
            string stackPrefix,
            CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(replayValidationResult1, replayValidationResult2, localContext))
                return context.Merge(localContext);

            if (replayValidationResult1.ExpirationTime != replayValidationResult2.ExpirationTime)
                localContext.Diffs.Add($"ReplayValidationResult1.ExpirationTime: '{replayValidationResult1.ExpirationTime}' != ReplayValidationResult2.ExpirationTime: '{replayValidationResult2.ExpirationTime}'");

            if (replayValidationResult1.IsValid != replayValidationResult2.IsValid)
                localContext.Diffs.Add($"ReplayValidationResult1.IsValid: {replayValidationResult1.IsValid} != ReplayValidationResult2.IsValid: {replayValidationResult2.IsValid}");

            if (replayValidationResult1.ValidationFailureType != replayValidationResult2.ValidationFailureType)
                localContext.Diffs.Add($"ReplayValidationResult1.ValidationFailureType: {replayValidationResult1.ValidationFailureType} != ReplayValidationResult2.ValidationFailureType: {replayValidationResult2.ValidationFailureType}");

            // true => both are not null.
            if (ContinueCheckingEquality(replayValidationResult1.Exception, replayValidationResult2.Exception, localContext))
            {
                AreStringsEqual(
                    replayValidationResult1.Exception.Message,
                    replayValidationResult2.Exception.Message,
                    $"({name1}).Exception.Message",
                    $"({name2}).Exception.Message",
                    localContext);

                AreStringsEqual(
                    replayValidationResult1.Exception.Source,
                    replayValidationResult2.Exception.Source,
                    $"({name1}).Exception.Source",
                    $"({name2}).Exception.Source",
                    localContext);

                if (!string.IsNullOrEmpty(stackPrefix))
                    AreStringPrefixesEqual(
                        replayValidationResult1.Exception.StackTrace.Trim(),
                        replayValidationResult2.Exception.StackTrace.Trim(),
                        $"({name1}).Exception.StackTrace",
                        $"({name2}).Exception.StackTrace",
                        stackPrefix.Trim(),
                        localContext);
            }

            return context.Merge(localContext);
        }

        public static bool AreTokenTypeValidationResultsEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, context))
                return context.Merge(localContext);

            return AreTokenTypeValidationResultsEqual(
                object1 as TokenTypeValidationResult,
                object2 as TokenTypeValidationResult,
                "TokenTypeValidationResult1",
                "TokenTypeValidationResult2",
                null,
                context);
        }

        internal static bool AreTokenTypeValidationResultsEqual(
            TokenTypeValidationResult tokenTypeValidationResult1,
            TokenTypeValidationResult tokenTypeValidationResult2,
            string name1,
            string name2,
            string stackPrefix,
            CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(tokenTypeValidationResult1, tokenTypeValidationResult2, localContext))
                return context.Merge(localContext);

            if (tokenTypeValidationResult1.Type != tokenTypeValidationResult2.Type)
                localContext.Diffs.Add($"TokenTypeValidationResult1.Type: '{tokenTypeValidationResult1.Type}' != TokenTypeValidationResult2.ExpirationTime: '{tokenTypeValidationResult2.Type}'");

            if (tokenTypeValidationResult1.IsValid != tokenTypeValidationResult2.IsValid)
                localContext.Diffs.Add($"TokenTypeValidationResult1.IsValid: {tokenTypeValidationResult1.IsValid} != TokenTypeValidationResult2.IsValid: {tokenTypeValidationResult2.IsValid}");

            if (tokenTypeValidationResult1.ValidationFailureType != tokenTypeValidationResult2.ValidationFailureType)
                localContext.Diffs.Add($"TokenTypeValidationResult1.ValidationFailureType: {tokenTypeValidationResult1.ValidationFailureType} != TokenTypeValidationResult2.ValidationFailureType: {tokenTypeValidationResult2.ValidationFailureType}");

            // true => both are not null.
            if (ContinueCheckingEquality(tokenTypeValidationResult1.Exception, tokenTypeValidationResult2.Exception, localContext))
            {
                AreStringsEqual(
                    tokenTypeValidationResult1.Exception.Message,
                    tokenTypeValidationResult2.Exception.Message,
                    $"({name1}).Exception.Message",
                    $"({name2}).Exception.Message",
                    localContext);

                AreStringsEqual(
                    tokenTypeValidationResult1.Exception.Source,
                    tokenTypeValidationResult2.Exception.Source,
                    $"({name1}).Exception.Source",
                    $"({name2}).Exception.Source",
                    localContext);

                if (!string.IsNullOrEmpty(stackPrefix))
                    AreStringPrefixesEqual(
                        tokenTypeValidationResult1.Exception.StackTrace.Trim(),
                        tokenTypeValidationResult2.Exception.StackTrace.Trim(),
                        $"({name1}).Exception.StackTrace",
                        $"({name2}).Exception.StackTrace",
                        stackPrefix.Trim(),
                        localContext);
            }

            return context.Merge(localContext);
        }

        public static bool AreTokenReadingResultsEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, context))
                return context.Merge(localContext);

            return AreTokenReadingResultsEqual(
                object1 as TokenReadingResult,
                object2 as TokenReadingResult,
                "TokenReadingResult1",
                "TokenReadingResult2",
                null,
                context);
        }

        internal static bool AreTokenReadingResultsEqual(
            TokenReadingResult tokenReadingResult1,
            TokenReadingResult tokenReadingResult2,
            string name1,
            string name2,
            string stackPrefix,
            CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(tokenReadingResult1, tokenReadingResult2, localContext))
                return context.Merge(localContext);

            if (tokenReadingResult1.IsValid != tokenReadingResult2.IsValid)
                localContext.Diffs.Add($"TokenReadingResult1.IsValid: {tokenReadingResult1.IsValid} != TokenReadingResult2.IsValid: {tokenReadingResult2.IsValid}");

            if (tokenReadingResult1.TokenInput != tokenReadingResult2.TokenInput)
                localContext.Diffs.Add($"TokenReadingResult1.TokenInput: '{tokenReadingResult1.TokenInput}' != TokenReadingResult2.TokenInput: '{tokenReadingResult2.TokenInput}'");

            // Only compare the security token if both are valid.
            if (tokenReadingResult1.IsValid && (tokenReadingResult1.SecurityToken().ToString() != tokenReadingResult2.SecurityToken().ToString()))
                localContext.Diffs.Add($"TokenReadingResult1.SecurityToken: '{tokenReadingResult1.SecurityToken()}' != TokenReadingResult2.SecurityToken: '{tokenReadingResult2.SecurityToken()}'");

            if (tokenReadingResult1.ValidationFailureType != tokenReadingResult2.ValidationFailureType)
                localContext.Diffs.Add($"TokenReadingResult1.ValidationFailureType: {tokenReadingResult1.ValidationFailureType} != TokenReadingResult2.ValidationFailureType: {tokenReadingResult2.ValidationFailureType}");
            
            // true => both are not null.
            if (ContinueCheckingEquality(tokenReadingResult1.Exception, tokenReadingResult2.Exception, localContext))
            {
                AreStringsEqual(
                    tokenReadingResult1.Exception.Message,
                    tokenReadingResult2.Exception.Message,
                    $"({name1}).Exception.Message",
                    $"({name2}).Exception.Message",
                    localContext);

                AreStringsEqual(
                    tokenReadingResult1.Exception.Source,
                    tokenReadingResult2.Exception.Source,
                    $"({name1}).Exception.Source",
                    $"({name2}).Exception.Source",
                    localContext);

                if (!string.IsNullOrEmpty(stackPrefix))
                    AreStringPrefixesEqual(
                        tokenReadingResult1.Exception.StackTrace.Trim(),
                        tokenReadingResult2.Exception.StackTrace.Trim(),
                        $"({name1}).Exception.StackTrace",
                        $"({name2}).Exception.StackTrace",
                        stackPrefix.Trim(),
                        localContext);
            }

            return context.Merge(localContext);
        }

        public static bool AreJArraysEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            var a1 = (JArray)object1;
            var a2 = (JArray)object2;

            if (a1.Count != a2.Count)
            {
                localContext.Diffs.Add("Count:");
                localContext.Diffs.Add($"a1.Count != a2.Count. '{a1.Count}' : '{a2.Count}'");
            }

            return context.Merge(localContext);
        }

        public static bool AreJObjectsEqual(Object object1, Object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            var a1 = (JObject)object1;
            var a2 = (JObject)object2;

            if (!JToken.DeepEquals(a1, a2))
            {
                localContext.Diffs.Add($"JObjects are not equal.");
            }

            return context.Merge(localContext);
        }

        public static bool AreJsonElementsEqual(object obj1, object obj2, CompareContext context)
        {
            var localContext = new CompareContext(context) { IgnoreType = true };
            if (!ContinueCheckingEquality(obj1, obj2, localContext))
                return context.Merge(localContext);

            JsonElement jsonElement1 = (JsonElement)obj1;
            JsonElement jsonElement2 = (JsonElement)obj2;

            if (jsonElement1.ValueKind != jsonElement2.ValueKind)
            {
                localContext.Diffs.Add($"jsonElement1.ValueKind != jsonElement2.ValueKind. '{jsonElement1.ValueKind}' != '{jsonElement2.ValueKind}'.");
                return context.Merge(localContext);
            }

            string str1 = jsonElement1.GetRawText();
            string str2 = jsonElement2.GetRawText();

            if (str1 != str2)
            {
                localContext.Diffs.Add($"jsonElement1.GetRawText() != jsonElement2.GetRawText(). '{jsonElement1.GetRawText()}' != '{jsonElement2.GetRawText()}'.");
                return context.Merge(localContext);
            }

            return context.Merge(localContext);
        }

        public static bool AreJsonWebKeysEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context) { IgnoreType = true };
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            Type jsonWebKeyType1 = object1.GetType();
            Type jsonWebKeyType2 = object2.GetType();

            if (jsonWebKeyType1 == jsonWebKeyType2)
                CompareAllPublicProperties(object1, object2, localContext);
            else
                CompareAllPublicPropertiesCrossVersion(object1, object2, localContext);

            return context.Merge(localContext);
        }

        public static bool CompareAllPublicPropertiesCrossVersion(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context) { IgnoreType = true };
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            Type objectType1 = object1.GetType();
            Type objectType2 = object2.GetType();

            var propertyInfos1 = objectType1.GetProperties(BindingFlags.Public | BindingFlags.Instance);
            var propertyInfos2 = objectType2.GetProperties(BindingFlags.Public | BindingFlags.Instance);

            foreach (PropertyInfo propertyInfo1 in propertyInfos1)
            {
                bool skipProperty = false;
                if (context.PropertiesToIgnoreWhenComparing != null && context.PropertiesToIgnoreWhenComparing.TryGetValue(objectType1, out List<string> propertiesToIgnore))
                {
                    foreach (var val in propertiesToIgnore)
                        if (string.Equals(val, propertyInfo1.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            skipProperty = true;
                            break;
                        }
                }

                if (skipProperty)
                    continue;

                // find a PropertyInfo in the second object that matches the first
                PropertyInfo propertyInfoFound = null;
                foreach (PropertyInfo propertyInfo2 in propertyInfos2)
                {
                    if (propertyInfo2.Name == propertyInfo1.Name)
                    {
                        propertyInfoFound = propertyInfo2;
                        break;
                    }
                }

                // log an error if the property info cannot be found
                if (propertyInfoFound == null)
                {
                    localContext.AddDiff($"property not found when comparing objects: {propertyInfo1.Name}");
                    continue;
                }

                // ensure there is a get method
                if (propertyInfo1.GetMethod != null)
                {
                    var propertyContext = new CompareContext(context);

                    object val1 = propertyInfo1.GetValue(object1, null);
                    object val2 = propertyInfoFound.GetValue(object2, null);
                    if ((val1 == null) && (val2 == null))
                        continue;

                    if ((val1 == null) || (val2 == null))
                    {
                        propertyContext.Diffs.Add($"{propertyInfo1.Name}:");
                        propertyContext.Diffs.Add(BuildStringDiff(propertyInfoFound.Name, val1, val2));
                    }
                    else if (val1.GetType().BaseType == typeof(System.ValueType) && !_equalityDict.Keys.Contains(val1.GetType().ToString()))
                    {
                        if (!val1.Equals(val2))
                        {
                            propertyContext.Diffs.Add($"{propertyInfo1.Name}:");
                            propertyContext.Diffs.Add(BuildStringDiff(propertyInfoFound.Name, val1, val2));
                        }
                    }
                    else
                    {
                        AreEqual(val1, val2, propertyContext);
                        localContext.Merge($"{propertyInfoFound.Name}:", propertyContext);
                    }
                }
            }

            return context.Merge(localContext);
        }

        public static bool AreJsonWebKeyEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<JsonWebKey>(object1 as IEnumerable<JsonWebKey>, object2 as IEnumerable<JsonWebKey>, context, AreEqual);
        }

        public static bool AreJwtSecurityTokensEqual(JwtSecurityToken jwt1, JwtSecurityToken jwt2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(jwt1, jwt2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(jwt1, jwt2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreIntsEqual(object object1, object object2, CompareContext context)
        {
            return AreIntsEqual((int)object1, Convert.ToInt32(object2), "int1", "int2", context);
        }

        public static bool AreIntsEqual(int int1, int int2, string name1, string name2, CompareContext context)
        {
            var localContext = new CompareContext(context);

            if (int1 == int2)
                return true;

            if (int1 != int2)
            {
                localContext.Diffs.Add($"{name1} != {name2}");
                localContext.Diffs.Add($"'{int1}'");
                localContext.Diffs.Add($"!=");
                localContext.Diffs.Add($"'{int2}'");
            }

            return context.Merge(localContext);
        }

        public static bool AreKeyInfosEqual(KeyInfo keyInfo1, KeyInfo keyInfo2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(keyInfo1, keyInfo2, context))
                CompareAllPublicProperties(keyInfo1, keyInfo2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreKeyInfoEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<KeyInfo>(object1 as IEnumerable<KeyInfo>, object2 as IEnumerable<KeyInfo>, context, AreEqual);
        }

        public static bool AreLongsEqual(object object1, object object2, CompareContext context)
        {
            return AreLongsEqual(object1, object2, "long1", "long2", context);
        }

        public static bool AreLongsEqual(object object1, object object2, string name1, string name2, CompareContext context)
        {
            var localContext = new CompareContext(context);

            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            long long1 = (long)object1;
            long long2;

            if (object2 is long || object2 is int)
                long2 = (long)object2;
            else if (object2 is string)
                long2 = Convert.ToInt64(double.Parse((string)object2));
            else
                long2 = Convert.ToInt64(object2);

            if (long1 == long2)
                return true;

            if (long1 != long2)
            {
                localContext.Diffs.Add($"{name1} != {name2}");
                localContext.Diffs.Add($"'{long1}'");
                localContext.Diffs.Add($"!=");
                localContext.Diffs.Add($"'{long2}'");
            }

            return context.Merge(localContext);
        }

        public static bool AreObjectDictionariesEqual(Object object1, Object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            IDictionary<string, object> dictionary1 = new Dictionary<string, object>();
            foreach (var kv in (IDictionary<string, object>)object1)
                if (!context.DictionaryKeysToIgnoreWhenComparing.Contains(kv.Key))
                    dictionary1.Add(kv);

            IDictionary<string, object> dictionary2 = new Dictionary<string, object>();
            foreach (var kv in (IDictionary<string, object>)object2)
                if (!context.DictionaryKeysToIgnoreWhenComparing.Contains(kv.Key))
                    dictionary2.Add(kv);

            if (dictionary1.Count != dictionary2.Count)
                localContext.Diffs.Add($"(dictionary1.Count != dictionary2.Count: {dictionary1.Count}, {dictionary2.Count})");

            int numMatched = 0;
            foreach (string key in dictionary1.Keys)
            {
                if (context.ClaimTypesToIgnoreWhenComparing.Contains(key))
                    continue;

                if (dictionary2.ContainsKey(key))
                {
                    if (!dictionary1.ContainsKey(key))
                    {
                        localContext.Diffs.Add($"dictionary1.ContainsKey({key}) == false, key is found in dictionary2");
                        continue;
                    }

                    if (dictionary1[key] == null && dictionary2[key] == null)
                        continue;

                    if (dictionary1[key] == null)
                    {
                        localContext.Diffs.Add($"dictionary1[{key}] == null, dictionary2[{key}] != null == '{dictionary2[key]}'");
                        continue;
                    }

                    if (dictionary2[key] == null)
                    {
                        localContext.Diffs.Add($"dictionary2[{key}] == null, dictionary1[{key}] != null == '{dictionary1[key]}'");
                        continue;
                    }

                    if (dictionary1[key].GetType() != dictionary2[key].GetType() && dictionary1[key].GetType() != typeof(JsonWebKey))
                    {
                        localContext.Diffs.Add($"dictionary1[{key}].GetType() != dictionary2[{key}].GetType(). '{dictionary1[key].GetType()}' : '{dictionary2[key].GetType()}'");
                        continue;
                    }

                    var obj1 = dictionary1[key];
                    var obj2 = dictionary2[key];
                    if (obj1.GetType().BaseType == typeof(System.ValueType))
                    {
                        if (_equalityDict.TryGetValue(obj1.GetType().ToString(), out var func))
                        {
                            if (!func(obj1, obj2, context))
                                localContext.Diffs.Add(BuildStringDiff(key, obj1, obj2));
                        }
                        else
                        {
                            if (!obj1.Equals(obj2))
                                localContext.Diffs.Add(BuildStringDiff(key, obj1, obj2));
                        }
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

        private static bool AreObjectsEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            AreEqual(object1, object2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreObjectEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<object>(object1 as IEnumerable<object>, object2 as IEnumerable<object>, context, AreObjectsEqual);
        }

        public static bool AreReferenceEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<Reference>(object1 as IEnumerable<Reference>, object2 as IEnumerable<Reference>, context, AreEqual);
        }

        public static bool AreRsaParametersEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            RSAParameters rsaParameters1 = (RSAParameters)object1;
            RSAParameters rsaParameters2 = (RSAParameters)object2;

            if (!AreBytesEqual(rsaParameters1.D, rsaParameters2.D, context))
            {
                localContext.Diffs.Add("D:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.D, rsaParameters2.D)");
            }

            if (!AreBytesEqual(rsaParameters1.DP, rsaParameters2.DP, context))
            {
                localContext.Diffs.Add("DP:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.DP, rsaParameters2.DP)");
            }

            if (!AreBytesEqual(rsaParameters1.DQ, rsaParameters2.DQ, context))
            {
                localContext.Diffs.Add("DQ:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.DQ, rsaParameters2.DQ)");
            }

            if (!AreBytesEqual(rsaParameters1.Exponent, rsaParameters2.Exponent, context))
            {
                localContext.Diffs.Add("Exponent:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.Exponent, rsaParameters2.Exponent)");
            }

            if (!AreBytesEqual(rsaParameters1.InverseQ, rsaParameters2.InverseQ, context))
            {
                localContext.Diffs.Add("InverseQ:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.InverseQ, rsaParameters2.InverseQ)");
            }

            if (!AreBytesEqual(rsaParameters1.Modulus, rsaParameters2.Modulus, context))
            {
                localContext.Diffs.Add("Modulus:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.Modulus, rsaParameters2.Modulus)");
            }

            if (!AreBytesEqual(rsaParameters1.P, rsaParameters2.P, context))
            {
                localContext.Diffs.Add("P:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.P, rsaParameters2.P)");
            }

            if (!AreBytesEqual(rsaParameters1.Q, rsaParameters2.Q, context))
            {
                localContext.Diffs.Add("Q:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.Q, rsaParameters2.Q)");
            }

            return context.Merge(localContext);
        }

        public static bool AreSamlAttributeEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SamlAttribute>(object1 as IEnumerable<SamlAttribute>, object2 as IEnumerable<SamlAttribute>, context, AreEqual);
        }

        public static bool AreSamlConditionEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SamlCondition>(object1 as IEnumerable<SamlCondition>, object2 as IEnumerable<SamlCondition>, context, AreEqual);
        }

        public static bool AreSamlStatementEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SamlStatement>(object1 as IEnumerable<SamlStatement>, object2 as IEnumerable<SamlStatement>, context, AreEqual);
        }

        public static bool AreSamlActionEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SamlAction>(object1 as IEnumerable<SamlAction>, object2 as IEnumerable<SamlAction>, context, AreEqual);
        }

        public static bool AreSamlAuthorityBindingEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SamlAuthorityBinding>(object1 as IEnumerable<SamlAuthorityBinding>, object2 as IEnumerable<SamlAuthorityBinding>, context, AreEqual);
        }

        public static bool AreSamlAssertionEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SamlAssertion>(object1 as IEnumerable<SamlAssertion>, object2 as IEnumerable<SamlAssertion>, context, AreEqual);
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
            }

            return context.Merge(localContext);
        }

        public static bool AreSecurityKeyEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SecurityKey>(object1 as IEnumerable<SecurityKey>, object2 as IEnumerable<SecurityKey>, context, AreSecurityKeysEqual);
        }

        public static bool AreSignedInfosEqual(SignedInfo signedInfo1, SignedInfo signedInfo2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(signedInfo1, signedInfo2, localContext))
                CompareAllPublicProperties(signedInfo1, signedInfo2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreStringDictionariesEqual(Object object1, Object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            IDictionary<string, string> dictionary1 = (IDictionary<string, string>)object1;
            IDictionary<string, string> dictionary2 = (IDictionary<string, string>)object2;

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

        public static bool AreStringsEqual(object object1, object object2, CompareContext context)
        {
            return AreStringsEqual(object1, object2, "str1", "str2", context);
        }

        public static bool AreStringsEqual(object object1, object object2, string name1, string name2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            string str1 = (string)object1;
            string str2 = (string)object2;

            if (string.IsNullOrEmpty(str1) && string.IsNullOrEmpty(str2))
                return true;

            if (ReferenceEquals(str1, str2))
                return true;

            if (str1 == null)
                localContext.Diffs.Add($"({name1} == null, {name2} == {str2}.");

            if(str2 == null)
                localContext.Diffs.Add($"({name1} == {str1}, {name2} == null.");

            if (!string.Equals(str1, str2, context.StringComparison))
            {
                localContext.Diffs.Add($"'{name1}' != '{name2}', StringComparison: '{context.StringComparison}'");
                localContext.Diffs.Add($"'{str1}'");
                localContext.Diffs.Add($"!=");
                localContext.Diffs.Add($"'{str2}'");
            }

            return context.Merge(localContext);
        }

        public static bool AreStringPrefixesEqual(
            string string1,
            string string2,
            string name1,
            string name2,
            string prefix,
            CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(string1, string2, localContext))
                return context.Merge(localContext);

            if (!string1.StartsWith(prefix, context.StringComparison))
            {
                localContext.Diffs.Add($"'{name1}': does not start with prefix: '{prefix}', StringComparison: '{context.StringComparison}'");
                localContext.Diffs.Add($"'{string1}'");
            }

            if (!string2.StartsWith(prefix, context.StringComparison))
            {
                localContext.Diffs.Add($"'{name2}': does not start with prefix: '{prefix}', StringComparison: '{context.StringComparison}'");
                localContext.Diffs.Add($"'{string2}'");
            }

            return context.Merge(localContext);
        }


        public static bool AreStringEnumDictionariesEqual(IDictionary<string, IEnumerable<string>> dictionary1, IDictionary<string, IEnumerable<string>> dictionary2, CompareContext context)
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
                    var obj1 = dictionary1[key];
                    var obj2 = dictionary2[key];
                    if (obj1.GetType().BaseType == typeof(System.ValueType))
                    {
                        if (!obj1.Equals(obj2))
                            localContext.Diffs.Add(BuildStringDiff(key, obj1, obj2));
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

        public static bool AreStringEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<string>(object1 as IEnumerable<string>, object2 as IEnumerable<string>, context, AreStringsEqual);
        }

        public static bool AreTimeSpansEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            TimeSpan timeSpan1 = (TimeSpan)object1;
            TimeSpan timeSpan2 = (TimeSpan)object2;

            if (timeSpan1 != timeSpan2)
                localContext.Diffs.Add($"timeSpan1 != timeSpan2. '{timeSpan1}' != '{timeSpan2}'.");

            return context.Merge(localContext);
        }

        private static bool AreValueCollectionsEqual(Object object1, Object object2, CompareContext context)
        {
            Dictionary<string, object>.ValueCollection vc1 = (Dictionary<string, object>.ValueCollection)object1;
            Dictionary<string, object>.ValueCollection vc2 = (Dictionary<string, object>.ValueCollection)object2;
            return true;
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
        }

        public static bool AreX509Certificate2Equal(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            var certificate1 = (X509Certificate2)object1;
            var certificate2 = (X509Certificate2)object2;

            if (certificate1 == null && certificate2 == null)
                return true;

            if (certificate1 == null || certificate2 == null || !certificate1.Equals(certificate2))
            {
                localContext.Diffs.Add("X509Certificate2:");
                if (certificate1 == null)
                    localContext.Diffs.Add($"certificate: null");
                else
                    localContext.Diffs.Add($"certificate: {certificate1}");
                localContext.Diffs.Add("!=");
                if (certificate2 == null)
                    localContext.Diffs.Add($"certificate: null");
                else
                    localContext.Diffs.Add($"certificate: {certificate2}");
            }

            return context.Merge(localContext);
        }

        public static bool AreX509DataEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<X509Data>(object1 as IEnumerable<X509Data>, object2 as IEnumerable<X509Data>, context, AreEqual);
        }

        public static bool AreUrisEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            Uri uri1 = (Uri)object1;
            Uri uri2 = (Uri)object2;

            if (!string.Equals(uri1.OriginalString, uri2.OriginalString, context.StringComparison))
            {
                localContext.Diffs.Add($"'{uri1.OriginalString}'");
                localContext.Diffs.Add($"!=");
                localContext.Diffs.Add($"'{uri2.OriginalString}'");
                localContext.Diffs.Add($"'{context.StringComparison}'");
            }

            return context.Merge(localContext);
        }

        public static bool AreUriEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<Uri>(object1 as IEnumerable<Uri>, object2 as IEnumerable<Uri>, context, AreEqual);
        }

        public static string BuildStringDiff(string label, object str1, object str2)
        {
            return (label ?? "label") + ": '" + GetString(str1) + "', '" + GetString(str2) + "'";
        }

        public static bool CompareAllPublicProperties(object obj1, object obj2, CompareContext context)
        {
            Type type = obj1.GetType();
            var localContext = new CompareContext(context);

            // exclude all public instance properties that have index parameter(s), for example, an indexer
            var propertyInfos = type.GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(p => !p.GetIndexParameters().Any());

            // Touch each public property
            foreach (var propertyInfo in propertyInfos)
            {
                bool skipProperty = false;
                if (context.PropertiesToIgnoreWhenComparing != null && context.PropertiesToIgnoreWhenComparing.TryGetValue(type, out List<string> propertiesToIgnore))
                {
                    foreach(var val in propertiesToIgnore)
                        if(string.Equals(val, propertyInfo.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            skipProperty = true;
                            break;
                        }
                }

                if (skipProperty)
                    continue;

                var propertyContext = new CompareContext(context);
                try
                {
                    if (type == typeof(Claim))
                    {
                        if (context.IgnoreSubject && propertyInfo.Name == "Subject")
                            continue;

                        if (context.IgnoreProperties && propertyInfo.Name == "Properties")
                            continue;
                    }

                    if (type == typeof(CaseSensitiveClaimsIdentity))
                    {
                        if (propertyInfo.Name == "SecurityToken")
                            continue;
                    }

                    if (propertyInfo.GetMethod != null)
                    {
                        object val1 = propertyInfo.GetValue(obj1, null);
                        object val2 = propertyInfo.GetValue(obj2, null);
                        if ((val1 == null) && (val2 == null))
                            continue;

                        if ((val1 == null) || (val2 == null))
                        {
                            localContext.Diffs.Add($"{propertyInfo.Name}:");
                            localContext.Diffs.Add(BuildStringDiff(propertyInfo.Name, val1, val2));
                        }
                        else if (val1.GetType().BaseType == typeof(System.ValueType) && !_equalityDict.Keys.Contains(val1.GetType().ToString()))
                        {
                            if (!val1.Equals(val2))
                            {
                                localContext.Diffs.Add($"{propertyInfo.Name}:");
                                localContext.Diffs.Add(BuildStringDiff(propertyInfo.Name, val1, val2));
                            }
                        }
                        else
                        {
                            AreEqual(val1, val2, propertyContext);
                            localContext.Merge($"{propertyInfo.Name}:", propertyContext);
                        }
                    }
                }
                catch (Exception ex)
                {
                    localContext.Diffs.Add($"Reflection failed getting 'PropertyInfo: {propertyInfo.Name}'. Exception: '{ex}'.");
                }
            }

            return context.Merge($"CompareAllPublicProperties: {type}", localContext);
        }

        public static bool IsOnlyOneObjectNull(object object1, object object2, CompareContext context)
        {
            if (object1 == null && object2 == null)
                return false;

            if (object1 == null)
            {
                context.Diffs.Add(BuildStringDiff(object2.GetType().ToString(), object1, object2));
                return true;
            }

            if (object2 == null)
            {
                context.Diffs.Add(BuildStringDiff(object1.GetType().ToString(), object1, object2));
                return true;
            }

            return false;
        }

        public static bool ContinueCheckingEquality(object obj1, object obj2, CompareContext context)
        {
            if (obj1 == null && obj2 == null)
                return false;

            if (obj1 == null)
            {
                context.Diffs.Add(BuildStringDiff(obj2.GetType().ToString(), obj1, obj2));
                return false;
            }

            if (obj2 == null)
            {
                context.Diffs.Add(BuildStringDiff(obj1.GetType().ToString(), obj1, obj2));
                return false;
            }

            if (object.ReferenceEquals(obj1, obj2))
                return false;

            if (!context.IgnoreType && (obj1.GetType() != obj2.GetType()))
            {
                context.Diffs.Add($"obj1.GetType() != obj2.GetType(). '{obj1.GetType()} : {obj2.GetType()}'");
                return false;
            }

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

        public static bool AreDatesEqualWithEpsilon(DateTime? dateTime1, DateTime? dateTime2, int epsilon)
        {
            if (dateTime1 is DateTime date1 && dateTime2 is DateTime date2)
                return Math.Abs((date1 - date2).TotalSeconds) <= epsilon;

            return dateTime1 == dateTime2;
        }

    }
}
