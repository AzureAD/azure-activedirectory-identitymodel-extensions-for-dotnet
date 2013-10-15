// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.Security.Claims;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// The <see cref="JwtPayload"/> contains JSON objects representing the claims contained in the JWT. Each claim is a JSON object of the form { Name, Value }.
    /// </summary>
    public class JwtPayload : Dictionary<string, object>
    {
        /// <summary>
        /// Creates a empty <see cref="JwtPayload"/>
        /// </summary>
        public JwtPayload( )
            : base( StringComparer.Ordinal )
        {
        }

        /// <summary>
        /// Creates a <see cref="JwtPayload"/> with claims added for each of the parameters were specified.
        /// </summary>
        /// <param name="issuer">if this value is not null, a { iss, 'issuer' } claim will be added.</param>
        /// <param name="audience">if this value is not null, a { aud, 'audience' } claim will be added</param>
        /// <param name="claims">if this value is not null then for each <see cref="Claim"/> a { 'Claim.Type', 'Claim.Value' } is added. If duplicate claims are found then a { 'Claim.Type', List&lt;object> } will be created to contain the duplicate values.</param>
        /// <param name="lifetime">if this value is not null, then if <para><see cref="Lifetime" />.Created.HasValue a { nbf, 'value' } is added.</para><para>if <see cref="Lifetime"/>.Expires.HasValue a { exp, 'value' } claim is added.</para></param>
        /// <remarks>Comparison is set to <see cref="StringComparer.Ordinal"/></remarks>
        public JwtPayload( string issuer = null, string audience = null, IEnumerable<Claim> claims = null, Lifetime lifetime = null )
            : base( StringComparer.Ordinal )
        {
            if ( null != issuer )
            {
                Add( JwtConstants.ReservedClaims.Issuer, issuer );
            }

            if ( null != audience )
            {
                Add( JwtConstants.ReservedClaims.Audience, audience );
            }

            if ( lifetime != null )
            {
                if ( lifetime.Created.HasValue )
                {
                    Add( JwtConstants.ReservedClaims.NotBefore, EpochTime.GetIntDate( lifetime.Created.Value ) );
                }

                if ( lifetime.Expires.HasValue )
                {
                    Add( JwtConstants.ReservedClaims.ExpirationTime, EpochTime.GetIntDate( lifetime.Expires.Value ) );
                }
            }

            if ( claims != null )
            {
                AddClaims( claims );
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'actor' claim { actort, 'value' }.
        /// </summary>
        /// <remarks>If the 'actor' claim is not found, null is returned.</remarks>
        public string Actor
        {
            get
            {
                return GetStandardClaim( JwtConstants.ReservedClaims.Actor );
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'audience' claim { aud, 'value' }.
        /// </summary>
        /// <remarks>If the 'audience' claim is not found, null is returned.</remarks>
        public string Audience
        {
            get { return GetStandardClaim( JwtConstants.ReservedClaims.Audience ); }
        }

        /// <summary>
        /// Gets the 'value' of the 'expiration' claim { exp, 'value' }.
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found OR could not be converted to <see cref="Int32"/>, null is returned.</remarks>
        public Int32? Expiration
        {
            get { return GetIntClaim( JwtConstants.ReservedClaims.ExpirationTime ); }
        }

        /// <summary>
        /// Gets the 'value' of the 'JWT ID' claim { jti, 'value' }.
        /// </summary>
        /// <remarks>If the 'JWT ID' claim is not found, null is returned.</remarks>
        public string Id
        {
            get
            {
                return GetStandardClaim( JwtConstants.ReservedClaims.JwtId );
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'Issued At' claim { iat, 'value' }.
        /// </summary>
        /// <remarks>If the 'Issued At' claim is not found OR cannot be converted to <see cref="Int32"/> null is returned.</remarks>
        public Int32? IssuedAt
        {
            get { return GetIntClaim( JwtConstants.ReservedClaims.IssuedAt ); }
        }

        /// <summary>
        /// Gets 'value' of the 'issuer' claim { iss, 'value' }.
        /// </summary>
        /// <remarks>If the 'issuer' claim is not found, null is returned.</remarks>
        public string Issuer
        {
            get
            {
                return GetStandardClaim( JwtConstants.ReservedClaims.Issuer );
            }
        }

        /// <summary>
        /// Gets "value" of the 'subject' claim { sub, 'value' }.
        /// </summary>
        /// <remarks>If the 'subject' claim is not found, null is returned.</remarks>
        public string Subject
        {
            get
            {
                return GetStandardClaim( JwtConstants.ReservedClaims.Subject );
            }
        }

        /// <summary>
        /// Gets 'value' of the 'notbefore' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime ValidFrom
        {
            get
            {
                return GetDateTime( JwtConstants.ReservedClaims.NotBefore );
            }
        }

        /// <summary>
        /// Gets 'value' of the 'expiration' claim { exp, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime ValidTo
        {
            get
            {
                return GetDateTime( JwtConstants.ReservedClaims.ExpirationTime );
            }
        }

        /// <summary>
        /// Gets a <see cref="IEnumerable{Claim}"/><see cref="Claim"/> for each JSON { name, value }.
        /// </summary>
        /// <remarks>Each <see cref="Claim"/>(s) returned will have the <see cref="Claim.Type"/> translated according to the mapping found in <see cref="JwtSecurityTokenHandler.InboundClaimTypeMap"/>. Adding and removing to <see cref="JwtSecurityTokenHandler.InboundClaimTypeMap"/> will affect the value of the <see cref="Claim.Type"/>.
        /// <para><see cref="Claim.Issuer"/> and <see cref="Claim.OriginalIssuer"/> will be set to the value of <see cref="Issuer"/> ( <see cref="string.Empty"/> if null).</para></remarks>
        public virtual IEnumerable<Claim> Claims
        {
            get
            {
                List<Claim> claims = new List<Claim>();
                string issuer = Issuer ?? ClaimsIdentity.DefaultIssuer;                   

                foreach ( KeyValuePair<string, object> keyValuePair in this )
                {
                    string claimType = keyValuePair.Key;
                    IEnumerable<object> values = keyValuePair.Value as IEnumerable<object>;
                    if ( values != null )
                    {
                        claims.AddRange( from claimValue in values
                                         select new Claim( claimType, claimValue.ToString(), ClaimValueTypes.String, issuer, issuer ) );
                    }
                    else
                    {
                        Claim claim = new Claim( claimType, keyValuePair.Value.ToString(), ClaimValueTypes.String, issuer, issuer );
                        claims.Add( claim );
                    }
                }

                return claims;
            }
        }

        /// <summary>
        /// Adds a JSON object representing the <see cref="Claim"/> to the <see cref="JwtPayload"/>
        /// </summary>
        /// <param name="claim">{ 'Claim.Type', 'Claim.Value' } is added. If a JSON object is found with the name == <see cref="Claim.Type"/> then a { 'Claim.Type', List&lt;object> } will be created to contain the duplicate values.</param>
        /// <remarks>See <see cref="AddClaims"/> for details on how <see cref="JwtSecurityTokenHandler.OutboundClaimTypeMap"/> is applied.</remarks>
        /// <exception cref="ArgumentNullException">'claim' is null.</exception>
        public void AddClaim( Claim claim )
        {
            if ( claim == null )
            {
                throw new ArgumentNullException( "claim" );
            }

            AddClaims( new Claim[] { claim } );
        }

        /// <summary>
        /// Adds a number of <see cref="Claim"/> to the <see cref="JwtPayload"/> as JSON { name, value } pairs.
        /// </summary>
        /// <param name="claims">for each <see cref="Claim"/> a JSON pair { 'Claim.Type', 'Claim.Value' } is added. If duplicate claims are found then a { 'Claim.Type', List&lt;object> } will be created to contain the duplicate values.</param>
        /// <remarks><para>Each <see cref="Claim"/> added will have <see cref="Claim.Type"/> translated according to the mapping found in <see cref="JwtSecurityTokenHandler.OutboundClaimTypeMap"/>. Adding and removing to <see cref="JwtSecurityTokenHandler.OutboundClaimTypeMap"/> 
        /// will affect the name component of the Json claim</para>
        /// <para>Any <see cref="Claim"/> in the <see cref="IEnumerable{claims}"/> that is null, will be ignored.</para></remarks>
        /// <exception cref="ArgumentNullException">'claims' is null.</exception>
        public void AddClaims( IEnumerable<Claim> claims )
        {
            if ( claims == null )
            {
                throw new ArgumentNullException( "claims" );
            }

            foreach ( Claim claim in claims )
            {
                if ( claim == null )
                {
                    continue;
                }

                string jsonClaimType = claim.Type;
                if ( JwtSecurityTokenHandler.OutboundClaimTypeMap.ContainsKey( jsonClaimType ) )
                {
                    jsonClaimType = JwtSecurityTokenHandler.OutboundClaimTypeMap[jsonClaimType];
                }

                object value;
                if ( this.TryGetValue( jsonClaimType, out value ) )
                {
                    IList<object> claimValues = value as IList<object>;
                    if ( claimValues == null )
                    {
                        claimValues = new List<object>();
                        claimValues.Add( value );
                        this[jsonClaimType] = claimValues;
                    }

                    claimValues.Add( claim.Value );
                }
                else
                {
                    Add( jsonClaimType, claim.Value );
                }
            }
        }

        /// <summary>
        /// Encodes this instance as a Base64UrlEncoded string.
        /// </summary>
        /// <remarks>Returns the current state. If this instance has changed since the last call, the value will be different.
        /// <para>No cryptographic operations are performed. See <see cref="JwtSecurityTokenHandler"/> for details.</para></remarks>
        public string Encode()
        {
            return Base64UrlEncoder.Encode( this.SerializeToJson() );
        }

        internal string GetStandardClaim( string claimType )
        {
            object value;
            if ( this.TryGetValue( claimType, out value ) )
            {
                IList<object> claimValues = value as IList<object>;
                if ( claimValues != null )
                {
                    return claimValues.SerializeToJson();
                }

                return value.ToString();
            }

            return null;
        }

        internal Int32? GetIntClaim( string claimType )
        {
            object value;
            Int32? retval = null;

            if ( this.TryGetValue( claimType, out value ) )
            {
                IList<object> claimValues = value as IList<object>;
                if ( claimValues != null )
                {
                    foreach ( object obj in claimValues )
                    {
                        retval = null;
                        if ( obj == null )
                        {
                            continue;
                        }

                        try
                        {
                            retval = Convert.ToInt32( obj, CultureInfo.InvariantCulture );
                        }
                        catch ( System.FormatException )
                        {
                            retval = null;
                        }
                        catch ( System.InvalidCastException )
                        {
                            retval = null;
                        }
                        catch ( OverflowException )
                        {
                            retval = null;
                        }

                        if ( retval != null )
                        {
                            return retval;
                        }
                    }
                }
                else
                {
                    try
                    {
                        retval = Convert.ToInt32( value, CultureInfo.InvariantCulture );
                    }
                    catch ( System.FormatException )
                    {
                        retval = null;
                    }
                    catch ( OverflowException )
                    {
                        retval = null;
                    }
                }

                return retval;
            }

            return retval;
        }

        /// <summary>
        /// Gets the DateTime using the number of seconds from 1970-01-01T0:0:0Z (UTC)
        /// </summary>
        /// <param name="key">Claim in the payload that should map to an integer.</param>
        /// <remarks>If the claim is not found, the function returns: DateTime.MinValue
        /// </remarks>
        /// <exception cref="SecurityTokenException">if value fails to parse.</exception>
        private DateTime GetDateTime( string key )
        {
            object dateValue;
            
            if ( !TryGetValue( key, out dateValue ) )
            {
                return DateTime.MinValue;
            }

            // if there are multiple dates, take the first one.
            try
            {
                Int64 secondsAfterBaseTime;
                IList<object> dateValues = dateValue as IList<object>;
                if ( dateValues != null )
                {
                    if ( dateValues.Count == 0 )
                    {
                        return DateTime.MinValue;
                    }
                    else
                    {
                        dateValue = dateValues[0];
                    }
                }

                // null converts to 0.
                secondsAfterBaseTime = Convert.ToInt64( dateValue, CultureInfo.InvariantCulture );
                return EpochTime.DateTime( secondsAfterBaseTime );
            }
            catch ( Exception ex )
            {
                if ( ex is FormatException || ex is ArgumentException || ex is InvalidCastException )
                {
                    throw new SecurityTokenException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10100, key, dateValue ?? "<null>", ex ) );
                }

                if ( ex is OverflowException )
                {
                    throw new SecurityTokenException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10101, key, dateValue ?? "<null>", ex ) );
                }

                throw;
            }            
        }
    }
}