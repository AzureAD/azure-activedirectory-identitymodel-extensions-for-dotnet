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

using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace System.IdentityModel.Tokens.Tests
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
        public static string ActorIssuer = "http://www.GotJwt.com/Actor";

        public const string DefaultAuthenticationType = "DefaultAuthenticationType";
        public const string DefaultClaimsIdentityLabel = "DefaultClaimsIdentityLabel";
        public const string DefaultClaimsIdentityLabelDup = "DefaultClaimsIdentityLabelDup";
        public const string DefaultIssuer = "DefaultIssuer";
        public const string DefaultLabel = "DefaultLabel";
        public const string DefaultOriginalIssuer = "DefaultOriginalIssuer";
        public const string DefaultNameClaimType = "DefaultNameClaimType";
        public const string DefaultRoleClaimType = "DefaultRoleClaimType";
        public const string NotDefaultAuthenticationType = "NotDefaultAuthenticationType";
        public const string NotDefaultClaimsIdentityLabel = "NotDefaultClaimsIdentityLabel";
        public const string NotDefaultIssuer = "NotDefaultIssuer";
        public const string NotDefaultLabel = "NOTDefaultLabel";
        public const string NotDefaultOriginalIssuer = "NotDefaultOriginalIssuer";
        public const string NotDefaultNameClaimType = "NotDefaultNameClaimType";
        public const string NotDefaultRoleClaimType = "NotDefaultRoleClaimType";

        private static List<Claim> _defaultClaims;
        private static List<Claim> _defaultClaimsWithoutEmail;
        private static List<Claim> _defaultDuplicatedClaims;
        private static List<Claim> _derivedDefaultClaims;
        private static List<Claim> _derivedGlobalClaims;
        private static List<Claim> _globalClaims;

        private static ClaimsIdentity  _defaultClaimsIdentity;
        private static ClaimsIdentity  _defaultClaimsIdentityClaimsDuplicated;
        private static ClaimsPrincipal _defaultClaimsPrincipal;
        private static ClaimsIdentity  _claimsIdentityDerivedClaims;
        //private static ClaimsIdentity  _derivedDefaultClaimsIdentity;
        private static ClaimsIdentity  _derivedClaimsIdentityDefaultClaims;
        private static ClaimsIdentity  _derivedClaimsIdentityDerivedClaims;

        static Claim _actor             = new Claim( JwtRegisteredClaimNames.Actort, IdentityUtilities.CreateJwtSecurityToken( ActorIssuer, ActorIssuer ).ToString() );
        static Claim _audience          = new Claim( JwtRegisteredClaimNames.Aud, "audClaimSets.Value" );
        static Claim _badHeaderType     = new Claim( JwtHeaderParameterNames.Typ, "BADDTYPE" );
        static Claim _expBadDateFormat  = new Claim( JwtRegisteredClaimNames.Exp, "BADDATEFORMAT" );
        static Claim _issuedAt          = new Claim( JwtRegisteredClaimNames.Iat, "issuedatClaimSets.Value" );
        static Claim _issuer            = new Claim( JwtRegisteredClaimNames.Iss,   "issuerClaimSets.Value" );
        static Claim _jwtId             = new Claim( JwtRegisteredClaimNames.Jti, "jwtIdClaimSets.Value" );
        static Claim _nbfBadDateFormat  = new Claim( JwtRegisteredClaimNames.Nbf, "BADDATEFORMAT" );
        static Claim _notAfter          = new Claim( JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate( DateTime.UtcNow + TimeSpan.FromHours( 1 ) ).ToString() );
        static Claim _notBefore         = new Claim( JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(DateTime.UtcNow).ToString() );
        static Claim _principal         = new Claim( JwtRegisteredClaimNames.Prn, "princlipalClaimSets.Value" );
        static Claim _sub               = new Claim( JwtRegisteredClaimNames.Sub, "Subject.Value" );
        static Claim _type              = new Claim( JwtRegisteredClaimNames.Typ, "Type.Value" );

        static ClaimSets()
        {
            _defaultClaimsWithoutEmail = new List<Claim>
            {
                new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim(ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim(ClaimTypes.Role, "Developer", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),

            };

            _defaultClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim(ClaimTypes.Email, "Bob@contoso.com", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim(ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim(ClaimTypes.Role, "Developer", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim( ClaimTypes.Role, "Sales", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer ),
                new Claim( ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer ),
                new Claim( "role", "role1", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim( "roles", "roles1", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),

            };

            _globalClaims = new List<Claim>()
            {
                new Claim("Arabic", @"?????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("Turkish1", @"igISiGIsçöÇÖ", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("Turkish2", @"GIsÖ", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("Chinese1", @"???", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("Chinese2", @"??", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("Japanese1", @"???", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("Japanese2", @"????<", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("ExtA1", @"????????????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("ExtA2", @"???????????????????????????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("ExtA3", @"????????????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("ExtA4", @"?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("ExtA4", @"????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("ExtB1", @"????????????????????????????????????????????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("ExtB2", @"??????????????????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("ExtB3", @"????????????????????????????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("ExtB4", @"????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????<", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("ExtB5", @"??????????????????????????????????????????????????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("EnteringIntlChars1", @"????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("EnteringIntlChars2", @"????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("EnteringIntlChars3", @"????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("EnteringIntlChars4", @"??a??z??4??M??f??N??g??S??l??T??m??Y??r??Y??E??K??7??P??i??P??i??U??n??)??B??G??3??L??e??M??9??R??k??S??l??X??q??X??D??]??v??1??J??c??K??7??P??i??Q??i", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("EnteringIntlChars5", @"??9??R??k??S??l??X??q??Y??E??J??gtOyYeqMY9E6??O??h??P??i??U??n??)??A??Z??s??y??e??L??8??Q??j??R??k??????????????????????W??p??X??D??]??v??1??I??b??J??6??O??h??P??i??U??n??)??B??Z??s", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("CommonSurrogates1", @"??????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("CommonSurrogates2", @"??????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("CommonSurrogates3", @"??????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("CommonSurrogates4", @"??????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("STBSample1", @"!#)6=@Aa}~<", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("STBSample2", @"??????????´?¦?????-?????????€????!???????????ag??-???????????g???????€", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("STBSample3", @"??????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("STBSample4", @"????????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("STBSample5", @"??????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("STBSample6", @"???????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("STBSample7", @"??????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("STBSample8", @"???????????????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("STBSample9", @"??????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),
                new Claim("STBSample10", @"??????????", ClaimValueTypes.String, DefaultIssuer, DefaultOriginalIssuer),

            };

            _defaultDuplicatedClaims = new List<Claim>();
            _defaultDuplicatedClaims.AddRange(_defaultClaims);
            _defaultDuplicatedClaims.AddRange(_defaultClaims);

            _derivedDefaultClaims = new List<Claim>();
            foreach (var claim in _defaultClaims)
            {
                _derivedDefaultClaims.Add(new DerivedClaim(claim, Guid.NewGuid().ToString(), Guid.NewGuid().ToByteArray()));
            }

            _derivedGlobalClaims = new List<Claim>();
            foreach (var claim in _globalClaims)
            {
                _derivedGlobalClaims.Add(new DerivedClaim(claim, Guid.NewGuid().ToString(), Guid.NewGuid().ToByteArray()));
            }

            _defaultClaimsIdentity = new ClaimsIdentity(_defaultClaims, DefaultAuthenticationType);
            _defaultClaimsIdentity.Label = DefaultClaimsIdentityLabel;
            _defaultClaimsIdentityClaimsDuplicated = new ClaimsIdentity(_defaultDuplicatedClaims, DefaultAuthenticationType);
            _defaultClaimsIdentityClaimsDuplicated.Label = DefaultClaimsIdentityLabelDup;
            _claimsIdentityDerivedClaims = new ClaimsIdentity(_derivedDefaultClaims, DefaultAuthenticationType);
            _derivedClaimsIdentityDefaultClaims = new DerivedClaimsIdentity(_defaultClaims, Guid.NewGuid().ToString(), Guid.NewGuid().ToByteArray());
            _derivedClaimsIdentityDerivedClaims = new DerivedClaimsIdentity(_derivedDefaultClaims, Guid.NewGuid().ToString(), Guid.NewGuid().ToByteArray());

            _defaultClaimsPrincipal = new ClaimsPrincipal(_defaultClaimsIdentity);
        }

        public static List<Claim> DefaultClaims
        {
            get { return _defaultClaims; }
        }

        public static IList<Claim> DerivedClaims
        {
            get { return _derivedDefaultClaims; }
        }

        public static IEnumerable<Claim> DerivedGlobalClaims
        {
            get { return _derivedGlobalClaims; }
        }

        public static IEnumerable<Claim> DefaultClaimsDuplicated
        {
            get
            {
                return _defaultDuplicatedClaims;
            }
        }

        public static List<Claim> DefaultClaimsWithoutEmail
        {
            get
            {
                return _defaultClaimsWithoutEmail;
            }
        }

        public static ClaimsIdentity DefaultClaimsIdentity
        {
            get
            {
                return _defaultClaimsIdentity;
            }
        }

        public static ClaimsIdentity DefaultClaimsIdentityClaimsDuplicated
        {
            get
            {
                return _defaultClaimsIdentityClaimsDuplicated;
            }
        }
        public static ClaimsIdentity ClaimsIdentityDerivedClaims
        {
            get
            {
                return _claimsIdentityDerivedClaims;
            }
        }
        public static ClaimsIdentity DerivedClaimsIdentityDefaultClaims
        {
            get
            {
                return _derivedClaimsIdentityDefaultClaims;
            }
        }

        public static ClaimsIdentity DerivedClaimsIdentityDerivedClaims
        {
            get
            {
                return _derivedClaimsIdentityDerivedClaims;
            }
        }

        public static ClaimsPrincipal DefaultClaimsPrincipal
        {
            get
            {
                return _defaultClaimsPrincipal;
            }
        }
        public static Claim GetDefaultClaim(DefaultClaimType claimType, ClaimsIdentity identity = null, string issuer = null, string originalIssuer = null)
        {
            string localIssuer = string.IsNullOrWhiteSpace(issuer) ? DefaultIssuer : issuer;
            string localOriginalIssuer = string.IsNullOrWhiteSpace(originalIssuer) ? DefaultOriginalIssuer : originalIssuer;

            switch (claimType)
            {
                case DefaultClaimType.Country:
                    return new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, localIssuer, localOriginalIssuer, identity);
                case DefaultClaimType.Email:
                    return new Claim(ClaimTypes.Email, "Bob@contoso.com", ClaimValueTypes.String, localIssuer, localOriginalIssuer, identity);
                case DefaultClaimType.GivenName:
                    return new Claim(ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, localIssuer, localOriginalIssuer, identity);
                case DefaultClaimType.HomePhone:
                    return new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, localIssuer, localOriginalIssuer, identity);
                case DefaultClaimType.Role:
                    return new Claim(ClaimTypes.Role, "Developer", ClaimValueTypes.String, localIssuer, localOriginalIssuer, identity);
                default:
                    throw new ArgumentException("unknown claimtype: " + claimType.ToString());
            }
        }

        public static List<Claim> GetDefaultClaims(string issuer = null, string originalIssuer = null)
        {
            var claims = new List<Claim>
            {
                GetDefaultClaim(DefaultClaimType.Country, null, issuer, originalIssuer),
                GetDefaultClaim(DefaultClaimType.Email, null, issuer, originalIssuer),
                GetDefaultClaim(DefaultClaimType.GivenName, null, issuer, originalIssuer),
                GetDefaultClaim(DefaultClaimType.HomePhone, null, issuer, originalIssuer),
                GetDefaultClaim(DefaultClaimType.Role, null, issuer, originalIssuer),
            };

            return claims;
        }

        /// <summary>
        /// Claims containing global unicode chars. Gleemed from a number of sources.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="originalIssuer"></param>
        /// <returns></returns>
        public static List<Claim> GlobalClaims
        {
            get { return _globalClaims; }
        }


        public static IEnumerable<Claim> AllReserved
        {
            // these are all current reserved claims.
            // should be updated as the spec changes, refer to
            // JwtConstants.cs
            get
            {
                yield return _actor;
                yield return _audience;
                yield return _issuedAt;
                yield return _issuer;
                yield return _jwtId;
                yield return _notAfter;
                yield return _notBefore;
                yield return _principal;
                yield return _sub;
                yield return _type;
            }
        }

        public static IEnumerable<Claim> Audience
        {
            get { yield return _audience; }
        }

        public static IEnumerable<Claim> BadDateFormats
        {
            get
            {
                yield return _nbfBadDateFormat;
                yield return _expBadDateFormat;
            }
        }

        public static IEnumerable<Claim> BadHeaderType
        {
            get { yield return _badHeaderType; }
        }

        public static IEnumerable<Claim> Empty
        {
            get { return new List<Claim>(); }
        }

        public static IEnumerable<Claim> Issuer
        {
            get { yield return _issuer; }
        }

        public static IEnumerable<Claim> MultipleAudiences(string issuer = IdentityUtilities.DefaultIssuer, string orignalIssuer = IdentityUtilities.DefaultIssuer)
        {
            foreach(var aud in IdentityUtilities.DefaultAudiences)
            {
                yield return new Claim("aud", aud, ClaimValueTypes.String, issuer, orignalIssuer);
            }

            yield return new Claim("iss", issuer, ClaimValueTypes.String, issuer, orignalIssuer);
            foreach (var c in SimpleShortClaimtypes(issuer, orignalIssuer))
            {
                yield return c;
            }
        }

        public static IEnumerable<Claim> SingleAudience(string issuer = IdentityUtilities.DefaultIssuer, string orignalIssuer = IdentityUtilities.DefaultIssuer)
        {
            yield return new Claim("aud", IdentityUtilities.DefaultAudience, ClaimValueTypes.String, issuer, orignalIssuer);
            yield return new Claim("iss", issuer, ClaimValueTypes.String, issuer, orignalIssuer);
            foreach (var c in SimpleShortClaimtypes(issuer, orignalIssuer))
            {
                yield return c;
            }
        }

        public static List<Claim> RoleClaimsShortType()
        {
            return RoleClaimsShortType(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer);
        }

        public static List<Claim> RoleClaimsShortType(string issuer, string originalIssuer)
        {
            return new List<Claim>()
            {
                new Claim( "role", "role1", ClaimValueTypes.String, issuer, originalIssuer),
                new Claim( "roles", "roles1", ClaimValueTypes.String, issuer, originalIssuer),
            };
        }

        public static List<Claim> RoleClaimsLongType()
        {
            return RoleClaimsLongType(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer);
        }

        public static List<Claim> RoleClaimsLongType(string issuer, string originalIssuer)
        {
            var claims = new List<Claim>();

            var claim = new Claim(ClaimTypes.Role, "role1", ClaimValueTypes.String, issuer, originalIssuer);
            claim.Properties.Add(JwtSecurityTokenHandler.ShortClaimTypeProperty, "role");
            claims.Add(claim);

            claim = new Claim(ClaimTypes.Role, "roles1", ClaimValueTypes.String, issuer, originalIssuer);
            claim.Properties.Add(JwtSecurityTokenHandler.ShortClaimTypeProperty, "roles");
            claims.Add(claim);

            return claims;
        }

        public static IEnumerable<Claim> Simple( string issuer, string originalIssuer )
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
        public static IEnumerable<Claim> DuplicateTypes( string issuer = IdentityUtilities.DefaultIssuer, string originalIssuer = IdentityUtilities.DefaultOriginalIssuer)
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

        public static IEnumerable<Claim> OutboundClaimTypeTransform(IEnumerable<Claim> claims, IDictionary<string, string> outboundClaimTypeMap)
        {
            foreach (Claim claim in claims)
            {
                string type = null;
                if (outboundClaimTypeMap.TryGetValue(claim.Type, out type))
                {
                    Claim mappedClaim = new Claim(type, claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer, claim.Subject);
                    foreach (KeyValuePair<string, string> kv in claim.Properties)
                    {
                        mappedClaim.Properties.Add(kv);
                    }
                    yield return mappedClaim;
                }
                else
                    yield return claim;
            }
        }

        public static IEnumerable<Claim> ClaimsPlus( IEnumerable<Claim> claims = null, SigningCredentials signingCredential = null, DateTime? notBefore = null, DateTime? expires = null, string issuer = null, string originalIssuer = null, string audience = null )
        {
            string thisIssuer = issuer ?? ClaimsIdentity.DefaultIssuer;
            string thisOriginalIssuer = originalIssuer ?? thisIssuer;

            if ( claims != null )
            {
                foreach ( Claim claim in claims ) yield return claim;
            }

            if ( signingCredential != null )
            {
                JwtHeader header = new JwtHeader( signingCredential );

                foreach ( string key in header.Keys )
                {
                    string value = JsonExtensions.SerializeToJson(header[key]);
                    yield return new Claim( key, value, ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );
                }
            }

            if (notBefore.HasValue)
                yield return new Claim(JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(notBefore.Value).ToString(), ClaimValueTypes.String, thisIssuer, thisOriginalIssuer);

            if (expires.HasValue)
                yield return new Claim( JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate( expires.Value ).ToString(), ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );

            if ( audience != null )
                yield return new Claim( JwtRegisteredClaimNames.Aud, audience, ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );

            if ( issuer != null )
                yield return new Claim( JwtRegisteredClaimNames.Iss, issuer, ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );
        }

        public static IEnumerable<Claim> EntityAsJsonClaim( string issuer, string orginalIssuer )
        {
            yield return new Claim( typeof( Entity ).ToString(), JsonExtensions.SerializeToJson(Entity.Default), "JsonClaimType", issuer, orginalIssuer );
        }

        /// <summary>
        /// Uses JwtSecurityTokenHandler.OutboundClaimTypeMap to map claimtype.
        /// </summary>
        /// <param name="jwtClaim"></param>
        /// <returns></returns>
        public static Claim OutboundClaim( Claim claim )
        {
            Claim outboundClaim = claim;
            if ( JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.ContainsKey( claim.Type ) )
            {
                outboundClaim = new Claim( JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[claim.Type], claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer, claim.Subject );
                foreach ( KeyValuePair< string, string > kv in claim.Properties )
                {
                    outboundClaim.Properties.Add( kv );
                }
            }

            return outboundClaim;
        }

        /// <summary>
        /// Simulates that a jwtClaim arrived and was mapped, adds the short name property for any claims that would have been translated
        /// </summary>
        /// <param name="jwtClaim"></param>
        /// <returns></returns>
        public static Claim InboundClaim( Claim claim )
        {
            if ( JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.ContainsKey( claim.Type ) )
            {
                if ( JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.ContainsKey( JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[claim.Type] ) )
                {
                    if ( !claim.Properties.ContainsKey( JwtSecurityTokenHandler.ShortClaimTypeProperty ) )
                    {
                        claim.Properties.Add( JwtSecurityTokenHandler.ShortClaimTypeProperty, JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[claim.Type] );
                    }
                }
            }

            return claim;
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
