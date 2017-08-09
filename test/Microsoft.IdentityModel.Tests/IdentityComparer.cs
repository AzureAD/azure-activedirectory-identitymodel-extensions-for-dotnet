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
using System.Collections.ObjectModel;
using System.Linq;

namespace Microsoft.IdentityModel.Tests
{
    public class IdentityComparer
    {
        private static readonly Dictionary<string, Func<Object, object, CompareContext, bool>> _equalityDict =
            new Dictionary<string, Func<Object, object, CompareContext, bool>>()
        {
            { typeof(IEnumerable<Claim>).ToString(), AreClaimsEnumsEqual },
            { typeof(IEnumerable<ClaimsIdentity>).ToString(), AreClaimsIdentitiesEnumsEqual },
            { typeof(IEnumerable<string>).ToString(), AreStringEnumsEqual },
            { typeof(IEnumerable<SecurityKey>).ToString(), AreSecurityKeyEnumsEqual },
            { typeof(Newtonsoft.Json.Linq.JArray).ToString(), AreJArraysEqual },
            { typeof(string).ToString(), AreStringsEqual },
            { typeof(IDictionary<string, string>).ToString(), AreStringDictionariesEqual},
            { typeof(Dictionary<string, object>).ToString(), AreObjectDictionariesEqual },
            { typeof(Dictionary<string, object>.ValueCollection).ToString(), AreValueCollectionsEqual },
            { typeof(IEnumerable<object>).ToString(), AreObjectEnumsEqual },
            { typeof(Collection<SecurityKey>).ToString(), ContinueCheckingEquality },
        };

        public static bool AreStringEnumsEqual(object object1, object object2, CompareContext context)
        {
            IEnumerable<string> stringEnum1 = (IEnumerable<string>)object1;
            IEnumerable<string> stringEnum2 = (IEnumerable<string>)object2;
            return AreEnumsEqual<string>(stringEnum1, stringEnum2, context, AreStringsEqual);
        }

        public static bool AreSecurityKeyEnumsEqual(object object1, object object2, CompareContext context)
        {
            IEnumerable<SecurityKey> securityKeyEnum1 = (IEnumerable<SecurityKey>)object1;
            IEnumerable<SecurityKey> securityKeyEnum2 = (IEnumerable<SecurityKey>)object2;
            return AreEnumsEqual<SecurityKey>(securityKeyEnum1, securityKeyEnum2, context, AreSecurityKeysEqual);
        }

        public static bool AreObjectEnumsEqual(object object1, object object2, CompareContext context)
        {
            IEnumerable<object> objectEnum1 = (IEnumerable<object>)object1;
            IEnumerable<object> objectEnum2 = (IEnumerable<object>)object2;
            return AreEnumsEqual<object>(objectEnum1, objectEnum2, context, AreObjectsEqual);
        }

        public static bool AreEnumsEqual<T>(IEnumerable<T> t1, IEnumerable<T> t2, CompareContext context, Func<T, T, CompareContext, bool> areEqual)
        {
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

        public static bool AreClaimsEnumsEqual(object object1, object object2, CompareContext context)
        {

            IEnumerable<Claim> t1 = (IEnumerable<Claim>)object1;
            IEnumerable<Claim> t2 = (IEnumerable<Claim>)object2;

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

        public static bool AreClaimsIdentitiesEnumsEqual(Object object1, Object object2, CompareContext context)
        {
            IEnumerable<ClaimsIdentity> t1 = (IEnumerable<ClaimsIdentity>)object1;
            IEnumerable<ClaimsIdentity> t2 = (IEnumerable<ClaimsIdentity>)object2;

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
            var localContext = new CompareContext(context);
          
            // Check if either t1 or t2 are null or references of each other to see if we can terminate early.
            if (!ContinueCheckingEquality(t1, t2, localContext))
                return context.Merge(localContext);

            string inter;
            // Use a special function for comparison if required by the specific class of the object.
            if (_equalityDict.TryGetValue(t1.GetType().ToString(), out Func<Object, object, CompareContext, bool> areEqual))
            {
                return areEqual(t1, t2, localContext);
            } 
            // Check if any of the interfaces that the class uses require a special function.
            else if ((inter = t1.GetType().GetInterfaces().Select(t => t.ToString()).Intersect(_equalityDict.Keys).FirstOrDefault()) != null)
            {
                return _equalityDict[inter](t1, t2, localContext);
            }
            // Use default comparison for any other types.
            else
            {
                if (ContinueCheckingEquality(t1, t2, localContext))
                    CompareAllPublicProperties(t1, t2, localContext);

                return context.Merge(localContext);
            }
            
        }

        public static bool AreJArraysEqual(Object object1, Object object2, CompareContext context)
        {

            Newtonsoft.Json.Linq.JArray a1 = (Newtonsoft.Json.Linq.JArray)object1;
            Newtonsoft.Json.Linq.JArray a2 = (Newtonsoft.Json.Linq.JArray)object2;

            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(a1, a2, localContext))
                return context.Merge(localContext);

            if (a1.Count != a2.Count)
                localContext.Diffs.Add($"a1.Count != a2.Count. '{a1.Count}' : '{a2.Count}'");

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

        private static bool AreValueCollectionsEqual(Object object1, Object object2, CompareContext context)
        {
            Dictionary<string, object>.ValueCollection vc1 = (Dictionary<string, object>.ValueCollection)object1;
            Dictionary<string, object>.ValueCollection vc2 = (Dictionary<string, object>.ValueCollection)object2;
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

        public static bool AreObjectDictionariesEqual(Object object1, Object object2, CompareContext context)
        {
            IDictionary<string, object> dictionary1 = (IDictionary<string, object>)object1;
            IDictionary<string, object> dictionary2 = (IDictionary<string, object>)object2;

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

        public static bool AreStringDictionariesEqual(Object object1, Object object2, CompareContext context)
        {
            IDictionary<string, string> dictionary1 = (IDictionary<string, string>)object1;
            IDictionary<string, string> dictionary2 = (IDictionary<string, string>)object2;

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

        public static bool AreJwtSecurityTokensEqual(JwtSecurityToken jwt1, JwtSecurityToken jwt2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(jwt1, jwt2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(jwt1, jwt2, localContext);
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

        public static bool AreStringsEqual(object object1, object object2, CompareContext context)
        {
            string str1 = (string)object1;
            string str2 = (string)object2;

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

        public static bool AreKeyInfosEqual(KeyInfo keyInfo1, KeyInfo keyInfo2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(keyInfo1, keyInfo2, context))
                CompareAllPublicProperties(keyInfo1, keyInfo2, localContext);

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
            PropertyInfo[] propertyInfos = type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

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
