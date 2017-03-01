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
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public enum DefaultClaimType
    {
        Country,
        Email,
        GivenName,
        HomePhone,
        Role,
    }

    /// <summary>
    /// Contains a nubmer of different claims sets used to test roundtripping claims sets.
    /// </summary>
    public static class ClaimSets
    {
        static ClaimSets()
        {
            AllReserved = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Actort, IdentityUtilities.CreateJwtSecurityToken(IdentityUtilities.ActorIssuer, IdentityUtilities.ActorIssuer).ToString()),
                new Claim(JwtRegisteredClaimNames.Aud, "audClaimSets.Value"),
                new Claim(JwtHeaderParameterNames.Typ, "BADDTYPE"),
                new Claim(JwtRegisteredClaimNames.Exp, "BADDATEFORMAT"),
                new Claim(JwtRegisteredClaimNames.Iat, "issuedatClaimSets.Value"),
                new Claim(JwtRegisteredClaimNames.Iss, "issuerClaimSets.Value"),
                new Claim(JwtRegisteredClaimNames.Jti, "jwtIdClaimSets.Value"),
                new Claim(JwtRegisteredClaimNames.Nbf, "BADDATEFORMAT"),
                new Claim(JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.UtcNow + TimeSpan.FromHours(1)).ToString()),
                new Claim(JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(DateTime.UtcNow).ToString()),
                new Claim(JwtRegisteredClaimNames.Prn, "princlipalClaimSets.Value"),
                new Claim(JwtRegisteredClaimNames.Sub, "Subject.Value"),
                new Claim(JwtRegisteredClaimNames.Typ, "Type.Value"),
            };

            DefaultClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim(ClaimTypes.NameIdentifier, "Bob", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim(ClaimTypes.Email, "Bob@contoso.com", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim(ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim(ClaimTypes.Role, "Developer", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim(ClaimTypes.Role, "Sales", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim(ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("role", "role1", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("roles", "roles1", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
            };

            DerivedGlobalClaims = new List<Claim>()
            {
                new Claim("Arabic", @"?????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("Turkish1", @"??I?i???çöÇÖ", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("Turkish2", @"???Ö", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("Chinese1", @"???", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("Chinese2", @"??", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("Japanese1", @"???", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("Japanese2", @"????<", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("ExtA1", @"????????????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("ExtA2", @"???????????????????????????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("ExtA3", @"????????????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("ExtA4", @"?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("ExtA4", @"????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("ExtB1", @"????????????????????????????????????????????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("ExtB2", @"??????????????????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("ExtB3", @"????????????????????????????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("ExtB4", @"????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????<", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("ExtB5", @"??????????????????????????????????????????????????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("EnteringIntlChars1", @"????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("EnteringIntlChars2", @"????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("EnteringIntlChars3", @"????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("EnteringIntlChars4", @"??a??z??4??M??f??N??g??S??l??T??m??Y??r??Y??E??K??7??P??i??P??i??U??n??)??B??G??3??L??e??M??9??R??k??S??l??X??q??X??D??]??v??1??J??c??K??7??P??i??Q??i", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("EnteringIntlChars5", @"??9??R??k??S??l??X??q??Y??E??J??gtOyYeqMY9E6??O??h??P??i??U??n??)??A??Z??s??y??e??L??8??Q??j??R??k??????????????????????W??p??X??D??]??v??1??I??b??J??6??O??h??P??i??U??n??)??B??Z??s", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("CommonSurrogates1", @"??????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("CommonSurrogates2", @"??????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("CommonSurrogates3", @"??????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("CommonSurrogates4", @"??????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("STBSample1", @"!#)6=@Aa}~<", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("STBSample2", @"????????????????????????????€????????????????????????????????????????€", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("STBSample3", @"??????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("STBSample4", @"????????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("STBSample5", @"??????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("STBSample6", @"???????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("STBSample7", @"??????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("STBSample8", @"???????????????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("STBSample9", @"??????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                new Claim("STBSample10", @"??????????", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
            };

            var claims = new List<Claim>();
            claims.AddRange(DefaultClaims);
            foreach (var claim in DefaultClaims)
            {
                claims.Add(new DerivedClaim(claim, Guid.NewGuid().ToString(), Guid.NewGuid().ToByteArray()));
            }
            DerivedClaims = claims;

            claims = new List<Claim>();
            foreach (var claim in DerivedGlobalClaims)
            {
                claims.Add(new DerivedClaim(claim, Guid.NewGuid().ToString(), Guid.NewGuid().ToByteArray()));
            }
            DerivedGlobalClaims = claims;

            claims = new List<Claim>();
            claims.AddRange(DefaultClaims);
            claims.AddRange(DefaultClaims);
            DefaultDuplicatedClaims = claims;

            DefaultClaimsIdentity = new ClaimsIdentity(DefaultClaims, IdentityUtilities.DefaultAuthenticationType);
            DefaultClaimsIdentity.Label = IdentityUtilities.DefaultClaimsIdentityLabel;
            DefaultClaimsIdentityClaimsDuplicated = new ClaimsIdentity(DefaultDuplicatedClaims, IdentityUtilities.DefaultAuthenticationType);
            DefaultClaimsIdentityClaimsDuplicated.Label = IdentityUtilities.DefaultClaimsIdentityLabelDup;
            ClaimsIdentityDerivedClaims = new ClaimsIdentity(DerivedClaims, IdentityUtilities.DefaultAuthenticationType);
            DerivedClaimsIdentityDefaultClaims = new DerivedClaimsIdentity(DefaultClaims, Guid.NewGuid().ToString(), Guid.NewGuid().ToByteArray());
            DerivedClaimsIdentityDerivedClaims = new DerivedClaimsIdentity(DerivedClaims, Guid.NewGuid().ToString(), Guid.NewGuid().ToByteArray());
            DefaultClaimsPrincipal = new ClaimsPrincipal(DefaultClaimsIdentity);
        }

        public static List<Claim> DefaultClaims
        {
            get;
            private set;
        }

        public static List<Claim> DerivedClaims
        {
            get;
            private set;
        }

        public static List<Claim> DerivedGlobalClaims
        {
            get;
            private set;
        }

        public static List<Claim> DefaultDuplicatedClaims
        {
            get;
            private set;
        }

        public static ClaimsIdentity DefaultClaimsIdentity
        {
            get;
            private set;
        }

        public static ClaimsIdentity DefaultClaimsIdentityClaimsDuplicated
        {
            get;
            private set;
        }

        public static ClaimsIdentity ClaimsIdentityDerivedClaims
        {
            get;
            private set;
        }

        public static ClaimsIdentity DerivedClaimsIdentityDefaultClaims
        {
            get;
            private set;
        }

        public static ClaimsIdentity DerivedClaimsIdentityDerivedClaims
        {
            get;
            private set;
        }

        public static ClaimsPrincipal DefaultClaimsPrincipal
        {
            get;
            private set;
        }

        /// <summary>
        /// Claims containing global unicode chars. Gleemed from a number of sources.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="originalIssuer"></param>
        /// <returns></returns>
        public static List<Claim> GlobalClaims
        {
            get;
            private set;
        }


        public static List<Claim> AllReserved
        {
            get;
            private set;
        }

        public static List<Claim> Empty
        {
            get { return new List<Claim>(); }
        }

        public static List<Claim> MultipleAudiences(string issuer = IdentityUtilities.DefaultIssuer, string orignalIssuer = IdentityUtilities.DefaultIssuer)
        {
            var claims = new List<Claim>();
            foreach(var aud in IdentityUtilities.DefaultAudiences)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Aud, aud, ClaimValueTypes.String, issuer, orignalIssuer));
            }

            return claims;
        }

        public static List<Claim> SingleAudience(string issuer = IdentityUtilities.DefaultIssuer, string orignalIssuer = IdentityUtilities.DefaultIssuer)
        {
            return new List<Claim> { new Claim(JwtRegisteredClaimNames.Aud, IdentityUtilities.DefaultAudience, ClaimValueTypes.String, issuer, orignalIssuer) };
        }

        public static List<string> GetDefaultRoles()
        {
            return new List<string>{"role1", "roles1"};
        }

        public static Dictionary<string, string> GetDefaultRolePairs()
        {
            return new Dictionary<string, string> {{"role","role1"},{"roles","roles1"}};
        }

        public static List<Claim> GetDefaultRoleClaims(JwtSecurityTokenHandler handler)
        {
            var claims = new List<Claim>();
            foreach(var kv in GetDefaultRolePairs())
                AddMappedClaim(kv.Key, kv.Value, handler, claims);

            return claims;
        }

        private static void AddMappedClaim(string claimTypeIn, string claimValue, JwtSecurityTokenHandler handler, List<Claim> claims)
        {
            string claimType;
            if (handler == null || !handler.InboundClaimTypeMap.TryGetValue(claimTypeIn, out claimType))
            {
                claims.Add(new Claim(claimTypeIn, claimValue, ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer));
            }
            else
            {
                var claim = new Claim(claimType, claimValue, ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer);
                claim.Properties[JwtSecurityTokenHandler.ShortClaimTypeProperty] = claimTypeIn;
                claims.Add(claim);
            }
        }

        public static List<Claim> Simple(string issuer = IdentityUtilities.DefaultIssuer, string originalIssuer = IdentityUtilities.DefaultOriginalIssuer )
        {
            return new List<Claim>()
            {
                new Claim( ClaimTypes.Country, "USA", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Email, "user@contoso.com", ClaimValueTypes.String, issuer, originalIssuer),
                new Claim( ClaimTypes.GivenName, "Tony", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, issuer, originalIssuer),
                new Claim( ClaimTypes.Role, "Sales", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien", ClaimValueTypes.String, issuer, originalIssuer ),
            };
        }

        public static IEnumerable<Claim> SimpleShortClaimtypes(string issuer, string originalIssuer)
        {
            return new List<Claim>()
            {                
                NewClaimWithShortType(ClaimTypes.Country, "USA", ClaimValueTypes.String, issuer, originalIssuer),
                NewClaimWithShortType(ClaimTypes.Email, "user@contoso.com", ClaimValueTypes.String, issuer, originalIssuer),
                NewClaimWithShortType(ClaimTypes.GivenName, "Tony", ClaimValueTypes.String, issuer, originalIssuer ),
                NewClaimWithShortType(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, issuer, originalIssuer),
                NewClaimWithShortType(ClaimTypes.Role, "Sales", ClaimValueTypes.String, issuer, originalIssuer ),
                NewClaimWithShortType(ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien", ClaimValueTypes.String, issuer, originalIssuer ),
            };
        }

        public static Claim NewClaimWithShortType(string claimType, string claimValue, string claimValueType, string issuer, string originalIssuer)
        {
            return new Claim(JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.ContainsKey(ClaimTypes.Country) ? JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[ClaimTypes.Country] : ClaimTypes.Country, claimValue, claimValueType, issuer, originalIssuer);
        }

        public static IEnumerable<Claim> ActorClaimNotJwt(string issuer, string originalIssuer )
        {
            return new List<Claim>()
            {
                new Claim( ClaimTypes.Actor, "USA", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Email, "user@contoso.com", ClaimValueTypes.String, issuer, originalIssuer),
                new Claim( ClaimTypes.GivenName, "Tony", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, issuer, originalIssuer),
                new Claim( ClaimTypes.Role, "Sales", ClaimValueTypes.String, issuer, originalIssuer ),
            };
        }

        public static IEnumerable<Claim> DefaultClaimsAsCreatedInPayload()
        {
            return new List<Claim>()
            {
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country", "USA"),
                new Claim("email", "Bob@contoso.com"),
                new Claim("given_name", "Bob"),
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone", "555.1212"),
                new Claim("unique_name", "Jean-Sébastien"),
                new Claim("iss", "http://Default.Issuer.com"),
                new Claim("aud", "http://Default.Audience.com")
            };
        }

        public static IEnumerable<Claim> AllInboundShortClaimTypes(string issuer, string originalIssuer, IEnumerable<Claim> extraClaims = null)
        {
            foreach ( KeyValuePair<string, string> pair in JwtSecurityTokenHandler.DefaultInboundClaimTypeMap )
            {
                yield return new Claim( pair.Key, pair.Value, ClaimValueTypes.String, issuer, originalIssuer );
            }

            if ( extraClaims != null )
            {
                foreach ( Claim c in extraClaims )
                {
                    yield return c;
                }
            }
        }

        public static IEnumerable<Claim> ExpectedInClaimsIdentityUsingAllInboundShortClaimTypes(string issuer, string originalIssuer, IEnumerable<Claim> extraClaims = null)
        {
            foreach (KeyValuePair<string, string> pair in JwtSecurityTokenHandler.DefaultInboundClaimTypeMap)
            {
                Claim claim = new Claim(pair.Value, pair.Value, ClaimValueTypes.String, issuer, originalIssuer);
                claim.Properties.Add(new KeyValuePair<string, string>(JwtSecurityTokenHandler.ShortClaimTypeProperty, pair.Key));
                yield return claim;
            }

            if (extraClaims != null)
            {
                foreach (Claim c in extraClaims)
                {
                    yield return c;
                }
            }
        }

        /// <summary>
        /// Returns an enumeration containing duplicate claims. Used to test dups.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="originalIssuer"></param>
        /// <returns></returns>
        public static List<Claim> DuplicateTypes( string issuer = IdentityUtilities.DefaultIssuer, string originalIssuer = IdentityUtilities.DefaultOriginalIssuer)
        {
            return new List<Claim>
            {
                new Claim( ClaimTypes.Country, "USA", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Email, "user@contoso.com", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.GivenName, "Tony", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Role, "Sales", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Country, "USA_2", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Email, "user@contoso.com_2", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.GivenName, "Tony_2", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.HomePhone, "555.1212_2", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Role, "Sales_2", ClaimValueTypes.String, issuer, originalIssuer )
            };
        }

        public static List<Claim> EntityAsJsonClaim( string issuer, string orginalIssuer )
        {
            return new List<Claim> { new Claim(typeof(Entity).ToString(), JsonExtensions.SerializeToJson(Entity.Default), JsonClaimValueTypes.Json, issuer, orginalIssuer) };
        }
    }

    /// <summary>
    /// Complex type. Used for testing roundtripping using complex claims.
    /// </summary>
    public class Entity
    {
        public static Entity Default
        {
            get
            {
                Entity entity = new Entity
                {
                    Address = new Address
                    {
                        Country = "Country",
                        Locality = "Locality",
                        Region = "Region"
                    },
                    Email = "email@email.com",
                    Email_Verified = false,
                    Exp = 1234567891,
                    FavoriteColors = new string[] { "blue", "red", "orange" },
                    Nothing = null,
                    pi = 3.14159,
                    Request = new Request
                    {
                        Acr = new Acr()
                        {
                            Values = new string[] { "urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze" }
                        },
                        AuthTime = new AuthTime()
                        {
                            Essential = false
                        },
                        NicKName = null
                    },
                    Urn = "urn:example:attributes"
                };

                return entity;
            }
        }

        public string Email { get; set; }

        public bool Email_Verified { get; set; }

        public string Urn { get; set; }

        public long   Exp { get; set; }

        public double pi  { get; set; }

        public string Nothing { get; set; }

        public string[] FavoriteColors { get; set; }

        public Address Address { get; set; }

        public Request Request { get; set; }
    }

    /// <summary>
    /// Contained in Entity class to test complext claims
    /// </summary>
    public class AuthTime
    {
        public bool Essential { get; set;}
    }

    /// <summary>
    /// Contained in Entity class to test complext claims
    /// </summary>
    public class Acr
    {
        public string[] Values{ get; set;}
    }

    /// <summary>
    /// Contained in Entity class to test complext claims
    /// </summary>
    public class Request
    {
        public string NicKName { get; set; }

        public AuthTime AuthTime { get; set; }

        public Acr Acr { get; set; }
    }

    /// <summary>
    /// Contained in Entity class to test complext claims
    /// </summary>
    public class Address
    {
        public string Locality { get; set; }

        public string Region   { get; set; }

        public string Country  { get; set; }
    }
}
