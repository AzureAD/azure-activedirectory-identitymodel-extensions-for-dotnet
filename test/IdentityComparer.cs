//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Collections.Generic;
using System.Collections.ObjectModel;
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

        public static bool AreEqual(Claim claim1, Claim claim2, bool ignoreSubject = true)
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

            if (!IdentityComparer.AreEqual(claim1.Properties, claim2.Properties))
                return false;

            if (claim1.Value != claim2.Value)
                return false;

            if (claim1.ValueType != claim2.ValueType)
                return false;

            if (!ignoreSubject)
                if (!IdentityComparer.AreEqual(claim1.Subject, claim2.Subject))
                    return false;

            return true;
        }

        public static bool AreEqual( ReadOnlyCollection<Claim> claims1, ReadOnlyCollection<Claim> claims2 )
        {

            if (claims1 == null && claims2 == null)
                return true;

            if (claims1 == null || claims2 == null)
                return false;

            if (claims1.Count != claims2.Count)
                return false;

            bool[] claims2Matched = new bool[claims2.Count];
            for (int b = 0; b < claims2.Count; b++)
                claims2Matched[b] = false;

            for (int i = 0; i < claims1.Count; i++)
            {
                bool matched = false;
                for (int j = 0; j < claims2.Count; j++)
                {
                    if (IdentityComparer.AreEqual(claims1[i], claims2[j]))
                    {
                        if (!claims2Matched[j])
                        {
                            matched = true;
                        }
                        else
                        {
                            claims2Matched[j] = true;
                            break;
                        }
                    }
                }

                if (!matched)
                    return false;
            }

            return true;
        }

        public static bool AreEqual(IEnumerable<Claim> claims1, IEnumerable<Claim> claims2)
        {
            if (claims1 == null && claims2 == null)
                return true;

            if (claims1 == null || claims2 == null)
                return false;

            List<Claim> claims1Claims = new List<Claim>();
            List<Claim> claims1ClaimsMatched = new List<Claim>();
            List<Claim> claims2Claims = new List<Claim>();

            List<bool> claims2Matched = new List<bool>();

            foreach (Claim c in claims1)
            {
                claims1Claims.Add(c);
            }

            foreach (Claim c in claims2)
            {
                claims2Matched.Add(false);
                claims2Claims.Add(c);
            }

            if (claims1Claims.Count != claims2Claims.Count)
                return false;

            int numDups = 0;
            Claim c1 = null;
            Claim c2 = null;

            for (int i = 0; i < claims1Claims.Count; i++)
            {
                bool matched = false;

                c1 = claims1Claims[i];

                for (int j = 0; j < claims2Claims.Count; j++)
                {
                    c2 = claims2Claims[j];

                    if (IdentityComparer.AreEqual(c1, c2))
                    {
                        // claim can only match once.
                        if (!claims2Matched[j])
                        {
                            matched = true;
                            claims2Matched[j] = true;
                            claims1ClaimsMatched.Add(c1);
                            break;
                        }
                        else
                        {
                            numDups++;
                        }
                    }
                }

                if (!matched)
                    return false;
            }

            foreach (bool found in claims2Matched)
                if (!found)
                    return false;

            return true;
        }

        public static bool AreEqual(ReadOnlyCollection<ClaimsIdentity> identityCollection1, ReadOnlyCollection<ClaimsIdentity> identityCollection2)
        {
            if (identityCollection1 == null && identityCollection2 == null)
                return true;

            if (identityCollection1 == null || identityCollection2 == null)
                return false;

            if (identityCollection1.Count != identityCollection2.Count)
                return false;

            bool[] collections2Matched = new bool[identityCollection2.Count];
            for (int b = 0; b < identityCollection2.Count; b++)
                collections2Matched[b] = false;

            for (int i = 0; i < identityCollection1.Count; i++)
            {
                bool matched = false;
                for (int j = 0; j < identityCollection2.Count; j++)
                {
                    if (IdentityComparer.AreEqual(identityCollection1[i], identityCollection2[j]))
                    {
                        if (!collections2Matched[j])
                        {
                            matched = true;
                            collections2Matched[j] = true;
                            break;
                        }
                    }
                }

                if (!matched)
                    return false;
            }

            return true;
        }

        public static bool AreEqual(ClaimsPrincipal principal1, ClaimsPrincipal principal2, bool ignoreType = false)
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

            //if (!AreEqual(principal1.Identities as ReadOnlyCollection<ClaimsIdentity>, principal2.Identities as ReadOnlyCollection<ClaimsIdentity>))
            //    return false;

            return true;
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

        public static bool AreEqual(ClaimsIdentity ci1, ClaimsIdentity ci2, bool ignoreType = false)
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

            if (!IdentityComparer.AreEqual(ci1.Claims, ci2.Claims))
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

        public static bool AreEqual( string string1, string string2 )
        {
            if ( string1 == null && string2 == null )
            {
                return true;
            }

            if ( null == string1 || null == string2 )
            {
                return false;
            }

            return string.Equals( string1, string2, StringComparison.Ordinal );
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
    }
}
