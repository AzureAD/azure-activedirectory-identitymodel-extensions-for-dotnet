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

using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Test;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace System.IdentityModel.Test
{
    public class CompareContext
    {
        public CompareContext()
        {
            IgnoreSubject = true;
            StringComparison = System.StringComparison.Ordinal;
        }

        public static CompareContext Default = new CompareContext();

        public bool ExpectRawData { get; set; }
        public bool IgnoreProperties { get; set; }
        public bool IgnoreSubject { get; set; }
        public bool IgnoreType { get; set; }
        public StringComparison StringComparison { get; set; }
    }

    public class IdentityComparer
    {
        private static bool AreEnumsEqual<T>(IEnumerable<T> t1, IEnumerable<T> t2, CompareContext context, Func<T, T, CompareContext, bool> areEqual)
        {
            if (t1 == null && t2 == null)
                return true;

            if (t1 == null || t2 == null)
                return false;

            if (object.ReferenceEquals(t1, t2))
                return true;

            int numToMatch = 0;
            int numMatched = 0;

            List<T> toMatch = new List<T>(t2);
            
            // helps debugging to see what didn't match
            List<T> notMatched = new List<T>();
            foreach (var t in t1)
            {
                numToMatch++;
                bool matched = false;
                for (int i = 0; i < toMatch.Count; i++)
                {
                    if (areEqual(t, toMatch[i], context))
                    {
                        numMatched++;
                        matched = true;
                        toMatch.RemoveAt(i);
                        break;
                    }
                }

                if (!matched)
                {
                    notMatched.Add(t);
                }
            }

            return (toMatch.Count == 0 && numMatched == numToMatch && notMatched.Count == 0);
        }

        public static bool AreEqual<T>(T t1, T t2)
        {
            return AreEqual<T>(t1, t2, CompareContext.Default);
        }

        public static bool AreEqual<T>(T t1, T t2, CompareContext context)
        {
            if (t1 is TokenValidationParameters)
                return AreEqual<TokenValidationParameters>(t1 as TokenValidationParameters, t2 as TokenValidationParameters, context, AreTokenValidationParametersEqual);
            else if (t1 is JwtSecurityToken)
                return AreEqual<JwtSecurityToken>(t1 as JwtSecurityToken, t2 as JwtSecurityToken, context, AreJwtSecurityTokensEqual);
            else if (t1 is ClaimsIdentity)
                return AreEqual<ClaimsIdentity>(t1 as ClaimsIdentity, t2 as ClaimsIdentity, context, AreClaimsIdentitiesEqual);
            else if (t1 is ClaimsPrincipal)
                return AreEqual<ClaimsPrincipal>(t1 as ClaimsPrincipal, t2 as ClaimsPrincipal, context, AreClaimsPrincipalsEqual);
            else if (t1 is JsonWebKey)
                return AreEqual<JsonWebKey>(t1 as JsonWebKey, t2 as JsonWebKey, context, AreJsonWebKeysEqual);
            else if (t1 is JsonWebKeys)
                return AreEqual<JsonWebKeys>(t1 as JsonWebKeys, t2 as JsonWebKeys, context, AreJsonWebKeyKeysEqual);
            else if (t1 is OpenIdConnectConfiguration)
                return AreEqual<OpenIdConnectConfiguration>(t1 as OpenIdConnectConfiguration, t2 as OpenIdConnectConfiguration, context, AreOpenIdConnectMetadataEqual);
            if (t1 is IEnumerable<Claim>)
                return AreEnumsEqual<Claim>(t1 as IEnumerable<Claim>, t2 as IEnumerable<Claim>, context, AreClaimsEqual);
            else if (t1 is IEnumerable<string>)
                return AreEnumsEqual<string>(t1 as IEnumerable<string>, t2 as IEnumerable<string>, context, AreStringsEqual);
            else if (t1 is IEnumerable<SecurityKey>)
                return AreEnumsEqual<SecurityKey>(t1 as IEnumerable<SecurityKey>, t2 as IEnumerable<SecurityKey>, context, AreSecurityKeysEqual);
            else if (t1 is JwtPayload)
                return AreEqual<JwtPayload>(t1 as JwtPayload, t2 as JwtPayload, context, AreJwtPayloadsEqual);

            throw new InvalidOperationException("type not known");
        }

        public static bool AreEqual<T>(T t1, T t2, CompareContext context, Func<T, T, CompareContext, bool> areEqual)
        {
            if (t1 == null && t2 == null)
                return true;

            if (t1 == null || t2 == null)
                return false;

            if (object.ReferenceEquals(t1, t2))
                return true;

            return areEqual(t1, t2, context);
        }

        private static bool AreDictionariesEqual(IDictionary<string, string> dictionary1, IDictionary<string, string> dictionary2, CompareContext context)
        {
            if (dictionary1.Count != dictionary2.Count)
                return false;

            // have to assume same order here
            int numMatched = 0;
            foreach (KeyValuePair<string, string> kvp1 in dictionary1)
            {
                foreach (string key in dictionary2.Keys)
                {
                    if (kvp1.Key == key)
                    {
                        if (kvp1.Value != dictionary2[key])
                            return false;
                        numMatched++;
                        break;
                    }
                }
            }

            return numMatched == dictionary1.Count;
        }

        private static bool AreClaimsEqual(Claim claim1, Claim claim2, CompareContext context)
        {
            Dictionary<string, object> matchingFailures = new Dictionary<string, object>();

            if (claim1.Type != claim2.Type)
                matchingFailures.Add("Type", new KeyValuePair<string, string>(claim1.Type, claim2.Type));

            if (claim1.Issuer != claim2.Issuer)
                matchingFailures.Add("Issuer", new KeyValuePair<string, string>(claim1.Issuer, claim2.Issuer));

            if (claim1.OriginalIssuer != claim2.OriginalIssuer)
                matchingFailures.Add("Issuer", new KeyValuePair<string, string>(claim1.OriginalIssuer, claim2.OriginalIssuer));

            if (!context.IgnoreProperties && !AreEqual<IDictionary<string, string>>(claim1.Properties, claim2.Properties, context, AreDictionariesEqual))
                matchingFailures.Add("Properties", new KeyValuePair<IDictionary<string,string>, IDictionary<string, string>>(claim1.Properties, claim2.Properties));

            if (claim1.Value != claim2.Value)
                matchingFailures.Add("Value", new KeyValuePair<string, string>(claim1.Value, claim2.Value));

            if (claim1.ValueType != claim2.ValueType)
                matchingFailures.Add("ValueType", new KeyValuePair<string, string>(claim1.ValueType, claim2.ValueType));

            if (!context.IgnoreSubject && !AreEqual<ClaimsIdentity>(claim1.Subject, claim2.Subject, context, AreClaimsIdentitiesEqual))
                matchingFailures.Add("Subject", new KeyValuePair<ClaimsIdentity, ClaimsIdentity>(claim1.Subject, claim2.Subject));

            return matchingFailures.Count == 0;
        }

        private static bool AreClaimsPrincipalsEqual(ClaimsPrincipal principal1, ClaimsPrincipal principal2, CompareContext context)
        {
            if (!context.IgnoreType)
            {
                if (principal1.GetType() != principal2.GetType())
                    return false;
            }

            int numMatched = 0;
            int numToMatch = 0;
            List<ClaimsIdentity> identities2 = new List<ClaimsIdentity>(principal2.Identities);
            foreach (ClaimsIdentity identity in principal1.Identities)
            {
                numToMatch++;
                for (int i = 0; i < identities2.Count; i++)
                {
                    if (AreEqual<ClaimsIdentity>(identity, identities2[i], context, AreClaimsIdentitiesEqual))
                    {
                        numMatched++;
                        identities2.RemoveAt(i);
                        break;
                    }
                }
            }

            return identities2.Count == 0 && numToMatch == numMatched;
        }

        private static bool AreBootstrapContextsEqual(BootstrapContext bc1, BootstrapContext bc2, CompareContext context)
        {
            if (!AreEqual<SecurityToken>(bc1.SecurityToken, bc2.SecurityToken, context, AreSecurityTokensEqual))
                return false;

            if (!AreEqual<string>(bc1.Token, bc2.Token, context, AreStringsEqual))
                return false;

            return true;
        }

        private static bool AreClaimsIdentitiesEqual(ClaimsIdentity ci1, ClaimsIdentity ci2, CompareContext compareContext)
        {
            if (!string.Equals(ci1.AuthenticationType, ci2.AuthenticationType, compareContext.StringComparison))
                return false;

            if (!string.Equals(ci1.Label, ci2.Label, compareContext.StringComparison))
                return false;

            if (!string.Equals(ci1.Name, ci2.Name, compareContext.StringComparison))
                return false;

            if (!string.Equals(ci1.NameClaimType, ci2.NameClaimType))
                return false;

            if (!string.Equals(ci1.RoleClaimType, ci2.RoleClaimType))
                return false;

            if (!AreEnumsEqual<Claim>(ci1.Claims, ci2.Claims, compareContext, AreClaimsEqual))
                return false;

            if (ci1.IsAuthenticated != ci2.IsAuthenticated)
                return false;

            if (!AreEqual<ClaimsIdentity>(ci1.Actor, ci2.Actor, compareContext, AreClaimsIdentitiesEqual))
                return false;

            if (!compareContext.IgnoreType && (ci1.GetType() != ci2.GetType()))
                return false;

            // || TODO compare bootstrapcontext

            return true;
        }

        private static bool AreJwtSecurityTokensEqual(JwtSecurityToken jwt1, JwtSecurityToken jwt2, CompareContext compareContext)
        {
            if (!AreEqual<JwtHeader>(jwt1.Header, jwt2.Header, compareContext, AreJwtHeadersEqual))
                return false;

            if (!AreEqual<JwtPayload>(jwt1.Payload, jwt2.Payload, compareContext, AreJwtPayloadsEqual))
                return false;

            if (!AreEnumsEqual<Claim>(jwt1.Claims, jwt2.Claims, compareContext, AreClaimsEqual))
                return false;

            if (!string.Equals(jwt1.Actor, jwt2.Actor, compareContext.StringComparison))
                return false;

            if (!AreEnumsEqual<string>(jwt1.Audiences, jwt2.Audiences, compareContext, AreStringsEqual))
                return false;

            if (!string.Equals(jwt1.Id, jwt2.Id, compareContext.StringComparison))
                return false;

            if (!string.Equals(jwt1.Issuer, jwt2.Issuer, compareContext.StringComparison))
                return false;

            if (compareContext.ExpectRawData && !string.Equals( jwt1.RawData, jwt2.RawData, compareContext.StringComparison))
                return false;

            if (!string.Equals(jwt1.SignatureAlgorithm, jwt2.SignatureAlgorithm, compareContext.StringComparison))
                return false;

            if (jwt1.ValidFrom != jwt2.ValidFrom)
                return false;

            if (jwt1.ValidTo != jwt2.ValidTo)
                return false;

            if (!AreEnumsEqual<SecurityKey>(jwt1.SecurityKeys, jwt2.SecurityKeys, compareContext, AreSecurityKeysEqual))
                return false;

            // no reason to check keys, as they are always empty for now.
            //ReadOnlyCollection<SecurityKey> keys = jwt.SecurityKeys;

            return true;
        }

        private static bool AreSecurityKeyIdentifiersEqual(SecurityKeyIdentifier ski1, SecurityKeyIdentifier ski2, CompareContext context)
        {
            if (ski1.GetType() == ski1.GetType())
                return false;

            if (ski1.Count != ski2.Count)
                return false;

            return true;
        }

        private static bool AreSecurityTokensEqual(SecurityToken token1, SecurityToken token2, CompareContext context)
        {
            if (token1.GetType() == token2.GetType())
                return false;

            if (!AreEnumsEqual<SecurityKey>(token1.SecurityKeys, token2.SecurityKeys, CompareContext.Default, AreSecurityKeysEqual))
                return false;

            return true;
        }

        private static bool AreSigningCredentialsEqual(SigningCredentials cred1, SigningCredentials cred2, CompareContext context)
        {
            if (cred1.GetType() != cred2.GetType())
                return false;

            if (!string.Equals(cred1.DigestAlgorithm, cred2.DigestAlgorithm, context.StringComparison))
                return false;

            if (!string.Equals(cred1.SignatureAlgorithm, cred2.SignatureAlgorithm, context.StringComparison))
                return false;

            // SigningKey, null match and type
            if (!AreEqual<SecurityKey>(cred1.SigningKey, cred2.SigningKey, context, AreSecurityKeysEqual))
                return false;

            if (!AreEqual<SecurityKeyIdentifier>(cred1.SigningKeyIdentifier, cred2.SigningKeyIdentifier, context, AreSecurityKeyIdentifiersEqual))
                return false;

            return true;
        }

        public static bool AreJwtHeadersEqual(JwtHeader header1, JwtHeader header2, CompareContext context)
        {
            if (header1.Count != header2.Count)
            {
                return false;
            }

            return true;
        }

        public static bool AreJwtPayloadsEqual(JwtPayload payload1, JwtPayload payload2, CompareContext context)
        {
            if (payload1.Count != payload2.Count)
            {
                return false;
            }

            if (!AreEnumsEqual<Claim>(payload1.Claims, payload2.Claims, context, AreClaimsEqual))
            {
                return false;
            }

            return true;
        }

        private static bool AreStringsEqual(string string1, string string2, CompareContext context)
        {
            return string.Equals(string1, string2, context.StringComparison);
        }


        private static bool AreJsonWebKeyKeysEqual(JsonWebKeys jsonWebkeys1, JsonWebKeys jsonWebkeys2, CompareContext compareContext)
        {
            if (!AreEnumsEqual<JsonWebKey>(jsonWebkeys1.Keys, jsonWebkeys2.Keys, compareContext, AreJsonWebKeysEqual))
            {
                return false;
            }

            return true;
        }

        private static bool AreJsonWebKeysEqual(JsonWebKey jsonWebkey1, JsonWebKey jsonWebkey2, CompareContext compareContext)
        {
            if(!string.Equals(jsonWebkey1.Alg, jsonWebkey2.Alg, compareContext.StringComparison))
                return false;

            if( !string.Equals(jsonWebkey1.KeyOps, jsonWebkey2.KeyOps, compareContext.StringComparison))
                return false;

            if( !string.Equals(jsonWebkey1.Kid, jsonWebkey2.Kid, compareContext.StringComparison))
                return false;

            if( !string.Equals(jsonWebkey1.Kty, jsonWebkey2.Kty, compareContext.StringComparison))
                return false;

            if( !string.Equals(jsonWebkey1.Use, jsonWebkey2.Use, compareContext.StringComparison))
                return false;

            if (!string.Equals(jsonWebkey1.X5t, jsonWebkey2.X5t, compareContext.StringComparison))
                return false;

            if (!string.Equals(jsonWebkey1.X5u, jsonWebkey2.X5u, compareContext.StringComparison))
                return false;

            if (!AreEnumsEqual<string>(jsonWebkey1.X5c, jsonWebkey2.X5c, compareContext, AreStringsEqual))
                return false;

            return true;
        }

        private static bool AreBytesEqual(byte[] bytes1, byte[] bytes2)
        {
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

        private static bool AreOpenIdConnectMetadataEqual(OpenIdConnectConfiguration metadata1, OpenIdConnectConfiguration metadata2, CompareContext context)
        {
            if (!string.Equals(metadata1.AuthorizationEndpoint, metadata2.AuthorizationEndpoint, context.StringComparison))
                return false;

            if (!string.Equals(metadata1.CheckSessionIframe, metadata2.CheckSessionIframe, context.StringComparison))
                return false;

            if (!string.Equals(metadata1.EndSessionEndpoint, metadata2.EndSessionEndpoint, context.StringComparison))
                return false;

            if (!string.Equals(metadata1.Issuer, metadata2.Issuer, context.StringComparison))
                return false;

            if (!string.Equals(metadata1.JwksUri, metadata2.JwksUri, context.StringComparison))
                return false;

            if (!AreEnumsEqual<SecurityKey>(metadata1.SigningKeys, metadata2.SigningKeys, context, AreSecurityKeysEqual))
                return false;

            if (!string.Equals(metadata1.TokenEndpoint, metadata2.TokenEndpoint, context.StringComparison))
                return false;

            return true;
        }

        private static bool AreSecurityKeysEqual(SecurityKey securityKey1, SecurityKey securityKey2, CompareContext context)
        {
            if( !context.IgnoreType && (securityKey1.GetType() != securityKey2.GetType()))
                return false;

            // Check X509SecurityKey first so we don't have to use reflection to get cert.
            X509SecurityKey x509Key1 = securityKey1 as X509SecurityKey;
            if (x509Key1 != null)
            {
                X509SecurityKey x509Key2 = securityKey2 as X509SecurityKey;
                if (x509Key1.Certificate.Thumbprint == x509Key2.Certificate.Thumbprint)
                {
                    return true;
                }

                return false;
            }

            X509AsymmetricSecurityKey x509AsymmKey1 = securityKey1 as X509AsymmetricSecurityKey;
            if (x509AsymmKey1 != null)
            {
                X509AsymmetricSecurityKey x509AsymmKey2 = securityKey2 as X509AsymmetricSecurityKey;
                X509Certificate2 x509Cert1 = TestUtilities.GetProperty(x509AsymmKey1, "certificate") as X509Certificate2;
                X509Certificate2 x509Cert2 = TestUtilities.GetProperty(x509AsymmKey2, "certificate") as X509Certificate2;
                if (x509Cert1 == null && x509Cert2 == null)
                {
                    return true;
                }

                if (x509Cert1 != null || x509Cert2 != null)
                {
                    return false;
                }

                if (x509Cert1.Thumbprint != x509Cert2.Thumbprint)
                {
                    return false;
                }
            }

            SymmetricSecurityKey symKey1 = securityKey1 as SymmetricSecurityKey;
            if (symKey1 != null)
            {
                SymmetricSecurityKey symKey2 = securityKey2 as SymmetricSecurityKey;
                if (!AreBytesEqual(symKey1.GetSymmetricKey(), symKey2.GetSymmetricKey()))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool AreKeyRetrieversEqual(Func<string, IEnumerable<SecurityKey>> keyRetrevier1, Func<string, IEnumerable<SecurityKey>> keyRetrevier2, CompareContext compareContext)
        {
            if (!AreEnumsEqual<SecurityKey>(keyRetrevier1("keys"), keyRetrevier2("keys"), compareContext, AreSecurityKeysEqual))
                return false;

            return true;
        }

        private static bool AreAudValidatorsEqual(Action<IEnumerable<string>, SecurityToken, TokenValidationParameters> validator1, Action<IEnumerable<string>, SecurityToken, bool> validator2, CompareContext compareContext)
        {
            //validator1(new string[]{"str"}, null, IdentityUtilities.DefaultTokenValidationParameters);
            //validator2(new string[]{"str"}, null, IdentityUtilities.DefaultTokenValidationParameters);

            return true;
        }

        private static bool AreLifetimeValidatorsEqual(Func<SecurityToken, bool> validator1, Func<SecurityToken, bool> validator2, CompareContext compareContext)
        {
            if (validator1(null) != validator2(null))
                return false;

            return true;
        }

        private static bool AreIssValidatorsEqual(Func<string, SecurityToken, bool> validator1, Func<string, SecurityToken, bool> validator2, CompareContext compareContext)
        {
            if (validator1("bob", null) != validator2("bob", null))
                return false;

            return true;
        }

        private static bool AreTokenValidationParametersEqual(TokenValidationParameters validationParameters1, TokenValidationParameters validationParameters2, CompareContext compareContext)
        {
            HashSet<string> matchingFailures = new HashSet<string>();

            if ((validationParameters1.AudienceValidator == null && validationParameters2.AudienceValidator != null) || (validationParameters1.AudienceValidator != null && validationParameters2.AudienceValidator == null))
                matchingFailures.Add("AudienceValidator");

            if (validationParameters1.AuthenticationType != validationParameters2.AuthenticationType)
                matchingFailures.Add("AuthenticationType");

            if ((validationParameters1.CertificateValidator == null && validationParameters2.CertificateValidator != null) || (validationParameters1.CertificateValidator != null && validationParameters2.CertificateValidator == null))
                matchingFailures.Add("CertificateValidator");

            if (validationParameters1.CertificateValidator != null)
            { 
                if (validationParameters1.CertificateValidator.GetType() != validationParameters2.CertificateValidator.GetType())
                    matchingFailures.Add("CertificateValidatorType");
            }
            if (validationParameters1.ClockSkew != validationParameters2.ClockSkew)
                matchingFailures.Add("ClockSkew");

            if (validationParameters1.ClockSkew != validationParameters2.ClockSkew)
                matchingFailures.Add("ClockSkew");

            if (!AreEqual<SecurityKey>(validationParameters1.IssuerSigningKey, validationParameters2.IssuerSigningKey, compareContext, AreSecurityKeysEqual))
                matchingFailures.Add("IssuerSigningKey");

            if (!AreEqual<Func<string, IEnumerable<SecurityKey>>>(validationParameters1.IssuerSigningKeyRetriever, validationParameters2.IssuerSigningKeyRetriever, compareContext, AreKeyRetrieversEqual))
                matchingFailures.Add("IssuerSigningKeyRetriever");

            if (!AreEnumsEqual<SecurityKey>(validationParameters1.IssuerSigningKeys, validationParameters2.IssuerSigningKeys, compareContext, AreSecurityKeysEqual))
                matchingFailures.Add("IssuerSigningKeys");

            if ((validationParameters1.IssuerSigningKeyValidator == null && validationParameters2.IssuerSigningKeyValidator != null) || (validationParameters1.IssuerSigningKeyValidator != null && validationParameters2.IssuerSigningKeyValidator == null))
                matchingFailures.Add("IssuerSigningKeyValidator");

            if (!AreEqual<SecurityToken>(validationParameters1.IssuerSigningToken, validationParameters2.IssuerSigningToken, compareContext, AreSecurityTokensEqual))
                matchingFailures.Add("IssuerSigningKey");

            if (!AreEnumsEqual<SecurityToken>(validationParameters1.IssuerSigningTokens, validationParameters2.IssuerSigningTokens, compareContext, AreSecurityTokensEqual))
                matchingFailures.Add("IssuerSigningTokens");

            if ((validationParameters1.IssuerValidator == null && validationParameters2.IssuerValidator != null) || (validationParameters1.IssuerValidator != null && validationParameters2.IssuerValidator == null))
                matchingFailures.Add("IssuerValidator");

            if ((validationParameters1.LifetimeValidator == null && validationParameters2.LifetimeValidator != null) || (validationParameters1.LifetimeValidator != null && validationParameters2.LifetimeValidator == null))
                matchingFailures.Add("LifetimeValidator");

            if (validationParameters1.NameClaimType != validationParameters2.NameClaimType)
                matchingFailures.Add("NameClaimType");

            if ((validationParameters1.NameClaimTypeRetriever == null && validationParameters2.NameClaimTypeRetriever != null) || (validationParameters1.NameClaimTypeRetriever != null && validationParameters2.NameClaimTypeRetriever == null))
                matchingFailures.Add("NameClaimTypeRetriever");

            if (validationParameters1.RequireSignedTokens != validationParameters2.RequireSignedTokens)
                matchingFailures.Add("RequireSignedTokens");

            if (validationParameters1.RequireExpirationTime != validationParameters2.RequireExpirationTime)
                matchingFailures.Add("RequireExpirationTime");

            if (validationParameters1.RoleClaimType != validationParameters2.RoleClaimType)
                matchingFailures.Add("RoleClaimType");

            if ((validationParameters1.RoleClaimTypeRetriever == null && validationParameters2.RoleClaimTypeRetriever != null) || (validationParameters1.RoleClaimTypeRetriever != null && validationParameters2.RoleClaimTypeRetriever == null))
                matchingFailures.Add("RoleClaimTypeRetriever");

            if (validationParameters1.SaveSigninToken != validationParameters2.SaveSigninToken)
                matchingFailures.Add("SaveSigninToken");

            if ((validationParameters1.TokenReplayCache == null && validationParameters2.TokenReplayCache != null) || (validationParameters1.TokenReplayCache != null && validationParameters2.TokenReplayCache == null))
                matchingFailures.Add("TokenReplayCache");

            if (validationParameters1.ValidateActor != validationParameters2.ValidateActor)
                matchingFailures.Add("ValidateActor");

            if (validationParameters1.ValidateAudience != validationParameters2.ValidateAudience)
                matchingFailures.Add("ValidateAudience");

            if (validationParameters1.ValidateIssuer != validationParameters2.ValidateIssuer)
                matchingFailures.Add("ValidateIssuer");

            if (validationParameters1.ValidateIssuerSigningKey != validationParameters2.ValidateIssuerSigningKey)
                matchingFailures.Add("ValidateIssuerSigningKey");

            if (validationParameters1.ValidateLifetime != validationParameters2.ValidateLifetime)
                matchingFailures.Add("ValidateLifetime");

            if (!String.Equals(validationParameters1.ValidAudience, validationParameters2.ValidAudience, StringComparison.Ordinal))
                matchingFailures.Add("ValidAudience");

            if (!AreEnumsEqual<string>(validationParameters1.ValidAudiences, validationParameters2.ValidAudiences, new CompareContext { StringComparison = System.StringComparison.Ordinal }, AreStringsEqual))
                matchingFailures.Add("ValidAudiences");

            if (!String.Equals(validationParameters1.ValidIssuer, validationParameters2.ValidIssuer, StringComparison.Ordinal))
                matchingFailures.Add("ValidIssuer");

            if (!AreEnumsEqual<string>(validationParameters1.ValidIssuers, validationParameters2.ValidIssuers, CompareContext.Default, AreStringsEqual))
                matchingFailures.Add("ValidIssuers");

            return matchingFailures.Count == 0;
        }
    }
}
