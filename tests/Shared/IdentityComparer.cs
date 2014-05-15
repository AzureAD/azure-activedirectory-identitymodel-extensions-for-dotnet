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
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace System.IdentityModel.Test
{
    public class IdentityComparer
    {
        public static bool AreEqual(IDictionary<string, string> dictionary1, IDictionary<string, string> dictionary2)
        {
            if (dictionary1 == null && dictionary2 == null)
                return true;

            if (dictionary1 == null || dictionary2 == null)
                return false;

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

        public static bool AreEqual(Claim claim1, Claim claim2, bool ignoreSubject = true, bool ignoreProperties = false)
        {

            if (claim1 == null && claim2 == null)
                return true;

            if (claim1 == null || claim2 == null)
                return false;

            if (claim1.Type != claim2.Type)
                return false;

            if (claim1.Issuer != claim2.Issuer)
                return false;

            if (claim1.OriginalIssuer != claim2.OriginalIssuer)
                return false;

            if (!ignoreProperties && !IdentityComparer.AreEqual(claim1.Properties, claim2.Properties))
                    return false;

            if (claim1.Value != claim2.Value)
                return false;

            if (claim1.ValueType != claim2.ValueType)
                return false;

            if (!ignoreSubject && !IdentityComparer.AreEqual(claim1.Subject, claim2.Subject))
                    return false;

            return true;
        }

        public static bool AreEqual(IEnumerable<Claim> claims1, IEnumerable<Claim> claims2, bool ignoreSubject = true, bool ignoreProperties = false)
        {
            if (claims1 == null && claims2 == null)
                return true;

            if (claims1 == null || claims2 == null)
                return false;

            int numMatched = 0;
            int numToMatch = 0;
            List<Claim> claims2Claims = new List<Claim>(claims2);
            foreach (Claim claim in claims1)
            {
                numToMatch++;
                for (int i = 0; i < claims2Claims.Count; i++)
                {
                    if (AreEqual(claim, claims2Claims[i], ignoreSubject, ignoreProperties))
                    {
                        numMatched++;
                        claims2Claims.RemoveAt(i);
                        break;
                    }
                }
            }

            return claims2Claims.Count == 0 && numToMatch == numMatched;
        }

        public static bool AreEqual(ClaimsPrincipal principal1, ClaimsPrincipal principal2, bool ignoreType = false, bool ignoreSubject = true, bool ignoreProperties = false)
        {
            if (principal1 == null && principal2 == null)
                return true;

            if (principal1 == null || principal2 == null)
                return false;

            if (!ignoreType)
            {
                if (principal1.GetType() != principal2.GetType())
                    return false;
            }

            int numMatched = 0;
            int numToMatch = 0;
            List<ClaimsIdentity> identities2 = new List<ClaimsIdentity>(principal2.Identities);
            foreach(ClaimsIdentity identity in principal1.Identities)
            {
                numToMatch++;
                for( int i = 0; i < identities2.Count; i++)
                {
                    if(AreEqual(identity, identities2[i], ignoreType, ignoreSubject, ignoreProperties))
                    {
                        numMatched++;
                        identities2.RemoveAt(i);
                        break;
                    }
                }
            }

            return identities2.Count == 0 && numToMatch == numMatched;
        }

        public static bool AreEqual(BootstrapContext bc1, BootstrapContext bc2)
        {
            if(bc1 == null && bc2 == null)
                return true;

            if(bc1 == null || bc2 == null)
                return false;

            if (bc1.SecurityToken == null && bc2.SecurityToken != null)
            {
                return false;
            }

            if (bc1.SecurityToken != null && bc2.SecurityToken == null)
            {
                return false;
            }

            if (bc1.SecurityToken != null && bc2.SecurityToken != null)
            {
                if (bc1.SecurityToken.GetType() != bc2.SecurityToken.GetType())
                {
                    return false;
                }
            }

            if (bc1.Token == null && bc2.Token != null)
            {
                return false;
            }

            if (bc1.Token != null && bc2.Token == null)
            {
                return false;
            }

            if (bc1.Token != null && bc2.Token != null)
            {
                if (bc1.Token.GetType() != bc2.Token.GetType())
                {
                    return false;
                }
            }

            return true;
        }

        public static bool AreEqual(ClaimsIdentity ci1, ClaimsIdentity ci2, bool ignoreType = false, bool ignoreSubject = true, bool ignoreProperties = false)
        {
            if (ci1 == null && ci2 == null)
                return true;

            if (ci1 == null || ci2 == null)
                return false;

            if (!ignoreType)
            {
                if (ci1.GetType() != ci2.GetType())
                    return false;
            }

            if (!IdentityComparer.AreEqual(ci1.Actor, ci2.Actor))
                return false;

            if (StringComparer.OrdinalIgnoreCase.Compare(ci1.AuthenticationType, ci2.AuthenticationType) != 0)
                return false;

            //if (!IdentityComparer45.AreEqual(ci1.BootstrapContext as ISerializable, ci2.BootstrapContext as ISerializable))
            //    return false;

            if (!IdentityComparer.AreEqual(ci1.Claims, ci2.Claims, ignoreSubject, ignoreProperties))
                return false;

            if (ci1.IsAuthenticated != ci2.IsAuthenticated)
                return false;

            if (StringComparer.Ordinal.Compare(ci1.Label, ci2.Label) != 0)
                return false;

            if (StringComparer.Ordinal.Compare(ci1.Name, ci2.Name) != 0)
                return false;

            if (StringComparer.OrdinalIgnoreCase.Compare(ci1.NameClaimType, ci2.NameClaimType) != 0)
                return false;

            if (StringComparer.OrdinalIgnoreCase.Compare(ci1.RoleClaimType, ci2.RoleClaimType) != 0)
                return false;

            return true;
        }

        public static bool AreEqual( JwtSecurityToken jwt1, JwtSecurityToken jwt2, bool expectRawData = false )
        {
            if ( jwt1 == null && jwt2 == null )
            {
                return true;
            }

            if ( null == jwt1 || null == jwt2 )
            {
                return false;
            }

            if ( !AreEqual( jwt1.Header, jwt2.Header ) )
            {
                return false;
            }

            if ( !AreEqual( jwt1.Payload, jwt2.Payload ) )
            {
                return false;
            }

            if ( !IdentityComparer.AreEqual( jwt1.Claims, jwt2.Claims ) )
            {
                return false;
            }

            if ( jwt1.Actor != jwt2.Actor )
            {
                return false;
            }

            if ( !AreEqual( jwt1.Audience, jwt2.Audience ) )
            {
                return false;
            }

            if ( !AreEqual( jwt1.Id, jwt2.Id ) )
            {
                return false;
            }

            if ( !AreEqual( jwt1.Issuer, jwt2.Issuer ) )
            {
                return false;
            }

            if ( expectRawData && !AreEqual( jwt1.RawData, jwt2.RawData ) )
            {
                return false;
            }

            if ( !AreEqual( jwt1.SignatureAlgorithm, jwt2.SignatureAlgorithm ) )
            {
                return false;
            }

            if ( jwt1.ValidFrom != jwt2.ValidFrom )
            {
                return false;
            }

            if ( jwt1.ValidTo != jwt2.ValidTo )
            {
                return false;
            }

            // no reason to check keys, as they are always empty.
            //ReadOnlyCollection<SecurityKey> keys = jwt.SecurityKeys;

            return true;
        }

        public static bool AreEqual( SecurityToken token1, SecurityToken token2 )
        {
            // null match and type
            if ( token1 == null && token2 == null )
            {
                return true;
            }

            if ( null == token1 || null == token2 )
            {
                return false;
            }

            return token1.GetType() == token1.GetType();
        }

        public static bool AreEqual( SigningCredentials cred1, SigningCredentials cred2 )
        {
            // null match and type
            if ( cred1 == null && cred2 == null )
            {
                return true;
            }

            if ( null == cred1 || null == cred2 )
            {
                return false;
            }

            if ( cred1.GetType() != cred2.GetType() )
            {
                return false;
            }

            if ( !string.Equals( cred1.DigestAlgorithm, cred2.DigestAlgorithm, StringComparison.Ordinal ) )
            {
                return false;
            }

            if ( !string.Equals( cred1.SignatureAlgorithm, cred2.SignatureAlgorithm, StringComparison.Ordinal ) )
            {
                return false;
            }

            // SigningKey, null match and type
            if ( cred1.SigningKey == null && cred2.SigningKey != null )
            {
                return false;
            }

            if ( cred1.SigningKey != null && cred2.SigningKey == null )
            {
                return false;
            }

            if ( cred1.SigningKey.GetType() != cred2.SigningKey.GetType() )
            {
                return false;
            }

            // SigningKeyIdentifier, null match and type
            if ( cred1.SigningKeyIdentifier == null && cred2.SigningKeyIdentifier != null )
            {
                return false;
            }

            if ( cred1.SigningKeyIdentifier != null && cred2.SigningKeyIdentifier == null )
            {
                return false;
            }

            if ( cred1.SigningKeyIdentifier.GetType() != cred2.SigningKeyIdentifier.GetType() )
            {
                return false;
            }

            return true;
        }

        public static bool AreEqual(IList<string> strings1, IList<string> strings2, StringComparison stringComparison = StringComparison.Ordinal)
        {
            int numMatched = 0;
            int numToMatch = 0;
            List<string> strings = new List<string>(strings2);
            foreach(string str in strings1)
            {
                numToMatch++;
                for(int i = 0; i< strings.Count; i++)
                {
                    if(string.Equals(str, strings[i], stringComparison))
                    {
                        numMatched++;
                        strings.RemoveAt(i);
                    }
                }
            }

            return strings.Count == 0 && numMatched == numToMatch;
        }

        public static bool AreEqual(string string1, string string2, StringComparison stringComparison = StringComparison.Ordinal)
        {
            if ( string1 == null && string2 == null )
            {
                return true;
            }

            if ( null == string1 || null == string2 )
            {
                return false;
            }

            return string.Equals(string1, string2, stringComparison);
        }

        public static bool AreEqual( JwtHeader header1, JwtHeader header2 )
        {
            if ( header1 == null && header2 == null )
            {
                return true;
            }

            if ( null == header1 || null == header2 )
            {
                return false;
            }

            if ( header1.Count != header2.Count )
            {
                return false;
            }

            return true;
        }

        public static bool AreEqual( JwtPayload payload1, JwtPayload payload2 )
        {
            if ( payload1 == null && payload2 == null )
            {
                return true;
            }

            if ( null == payload1 || null == payload2 )
            {
                return false;
            }

            if ( payload1.Count != payload2.Count )
            {
                return false;
            }

            if ( !IdentityComparer.AreEqual( payload1.Claims, payload2.Claims ) )
            {
                return false;
            }

            return true;
        }

        public static bool AreEqual(ICollection<SecurityKey> securityKeys1, ICollection<SecurityKey> securityKeys2)
        {
            if (securityKeys1 == null && securityKeys2 == null)
            {
                return true;
            }

            if (securityKeys1 == null || securityKeys2 == null)
            {
                return false;
            }

            if (object.ReferenceEquals(securityKeys1, securityKeys2))
            {
                return true;
            }

            if (securityKeys1.Count != securityKeys2.Count)
            {
                return false;
            }

            List<X509SecurityKey> keys1 = new List<X509SecurityKey>();
            foreach (var key in securityKeys1)
            {
                if (key is X509SecurityKey)
                {
                    keys1.Add(key as X509SecurityKey);
                }
            }

            List<X509SecurityKey> keys2 = new List<X509SecurityKey>();
            foreach (var key in securityKeys2)
            {
                if (key is X509SecurityKey)
                {
                    keys2.Add(key as X509SecurityKey);
                }
            }

            foreach (var key in keys1)
            {
                for (int i = 0; i < keys2.Count; i++)
                {
                    if (key.Certificate.Thumbprint == keys2[i].Certificate.Thumbprint)
                    {
                        keys2.RemoveAt(i);
                    }
                }
            }

            return (keys2.Count == 0);
        }

        public static bool AreEqual(OpenIdConnectMetadata metadata1, OpenIdConnectMetadata metadata2)
        {
            if (metadata1 == null && metadata2 == null)
            {
                return true;
            }

            if (metadata1 == null || metadata2 == null)
            {
                return false;
            }

            if (object.ReferenceEquals(metadata1, metadata2))
            {
                return true;
            }

            if (!IdentityComparer.AreEqual(metadata1.AuthorizationEndpoint, metadata2.AuthorizationEndpoint))
            {
                return false;
            }

            if (!IdentityComparer.AreEqual(metadata1.CheckSessionIframe, metadata2.CheckSessionIframe))
            {
                return false;
            }

            if (!IdentityComparer.AreEqual(metadata1.EndSessionEndpoint, metadata2.EndSessionEndpoint))
            {
                return false;
            }

            if (!IdentityComparer.AreEqual(metadata1.Issuer, metadata2.Issuer))
            {
                return false;
            }

            if (!IdentityComparer.AreEqual(metadata1.JwksUri, metadata2.JwksUri))
            {
                return false;
            }

            if (!AreEqual(metadata1.SigningKeys, metadata2.SigningKeys))
            {
                return false;
            }

            if (!IdentityComparer.AreEqual(metadata1.TokenEndpoint, metadata2.TokenEndpoint))
            {
                return false;
            }

            return true;
        }

        public static bool AreEqual( JsonWebKeys jsonWebkeys1, JsonWebKeys jsonWebkeys2)
        {
            if (jsonWebkeys1 == null && jsonWebkeys2 == null)
            {
                return true;
            }

            if (null == jsonWebkeys1 || null == jsonWebkeys2)
            {
                return false;
            }

            if (!AreEqual(jsonWebkeys1.Keys, jsonWebkeys2.Keys))
            {
                return false;
            }

            return true;
        }

        public static bool AreEqual(IList<JsonWebKey> jsonWebkeys1, IList<JsonWebKey> jsonWebkeys2)
        {
            if (jsonWebkeys1 == null && jsonWebkeys2 == null)
            {
                return true;
            }

            if (null == jsonWebkeys1 || null == jsonWebkeys2)
            {
                return false;
            }

            List<JsonWebKey> jsonWebKeys = new List<JsonWebKey>(jsonWebkeys2);
            foreach(JsonWebKey webKey in jsonWebkeys1)
            {
                for( int i=0; i<jsonWebKeys.Count;i++)
                {
                    if(AreEqual(jsonWebKeys[i], webKey))
                    {
                        jsonWebKeys.RemoveAt(i);
                    }
                }
            }

            return jsonWebKeys.Count == 0;
        }

        public static bool AreEqual(JsonWebKey jsonWebkey1, JsonWebKey jsonWebkey2)
        {
            if (jsonWebkey1 == null && jsonWebkey2 == null)
            {
                return true;
            }

            if (null == jsonWebkey1 || null == jsonWebkey2)
            {
                return false;
            }

            if(!AreEqual(jsonWebkey1.Alg, jsonWebkey2.Alg))
            {
                return false;
            }

            if (!AreEqual(jsonWebkey1.KeyOps, jsonWebkey2.KeyOps))
            {
                return false;
            }

            if (!AreEqual(jsonWebkey1.Kid, jsonWebkey2.Kid))
            {
                return false;
            }

            if (!AreEqual(jsonWebkey1.Kty, jsonWebkey2.Kty))
            {
                return false;
            }

            if (!AreEqual(jsonWebkey1.Use, jsonWebkey2.Use))
            {
                return false;
            }

            if (!AreEqual(jsonWebkey1.X5c, jsonWebkey2.X5c))
            {
                return false;
            }

            if (!AreEqual(jsonWebkey1.X5t, jsonWebkey2.X5t))
            {
                return false;
            }

            if (!AreEqual(jsonWebkey1.X5u, jsonWebkey2.X5u))
            {
                return false;
            }

            return true;
        }
    }
}
