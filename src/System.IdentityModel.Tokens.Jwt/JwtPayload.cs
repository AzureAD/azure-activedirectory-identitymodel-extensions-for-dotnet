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

using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;

namespace System.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// Initializes a new instance of <see cref="JwtPayload"/> which contains JSON objects representing the claims contained in the JWT. Each claim is a JSON object of the form { Name, Value }.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2237:MarkISerializableTypesWithSerializable"), System.Diagnostics.CodeAnalysis.SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Serialize not really supported.")]
    public class JwtPayload : Dictionary<string, object>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class with no claims. Default string comparer <see cref="StringComparer.Ordinal"/>. 
        /// Creates a empty <see cref="JwtPayload"/>
        /// </summary>
        public JwtPayload()
            : this(issuer: null, audience: null, claims: null, notBefore: null, expires: null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class with <see cref="IEnumerable{Claim}"/>. Default string comparer <see cref="StringComparer.Ordinal"/>.
        /// <param name="claims">the claims to add.</param>
        /// </summary>
        public JwtPayload(IEnumerable<Claim> claims)
            : this(issuer: null, audience: null, claims: claims, notBefore: null, expires: null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class with claims added for each parameter specified. Default string comparer <see cref="StringComparer.Ordinal"/>. 
        /// </summary>
        /// <param name="issuer">if this value is not null, a { iss, 'issuer' } claim will be added.</param>
        /// <param name="audience">if this value is not null, a { aud, 'audience' } claim will be added</param>
        /// <param name="claims">if this value is not null then for each <see cref="Claim"/> a { 'Claim.Type', 'Claim.Value' } is added. If duplicate claims are found then a { 'Claim.Type', List&lt;object> } will be created to contain the duplicate values.</param>
        /// <param name="notBefore">if notbefore.HasValue is 'true' a { nbf, 'value' } claim is added.</param>
        /// <param name="expires">if expires.HasValue is 'true' a { exp, 'value' } claim is added.</param>
        /// <remarks>Comparison is set to <see cref="StringComparer.Ordinal"/>
        /// <para>The 4 parameters: 'issuer', 'audience', 'notBefore', 'expires' take precednece over <see cref="Claim"/>(s) in 'claims'. The values in 'claims' will be overridden.</para></remarks>
        /// <exception cref="ArgumentException">if 'expires' &lt;= 'notbefore'.</exception>
        public JwtPayload(string issuer, string audience, IEnumerable<Claim> claims, DateTime? notBefore, DateTime? expires)
            : base(StringComparer.Ordinal)
        {
            if (expires.HasValue && notBefore.HasValue)
            {
                if (notBefore >= expires)
                {
                    throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10401, expires.Value, notBefore.Value));
                }
            }

            if (claims != null)
            {
                this.AddClaims(claims);
            }

            if (!string.IsNullOrWhiteSpace(issuer))
            {
                this[JwtRegisteredClaimNames.Iss] = issuer;
            }

            if (!string.IsNullOrWhiteSpace(audience))
            {
                this[JwtRegisteredClaimNames.Aud] = audience;
            }

            if (expires.HasValue)
            {
                this[JwtRegisteredClaimNames.Exp] = EpochTime.GetIntDate(expires.Value.ToUniversalTime());
            }

            if (notBefore.HasValue)
            {
                this[JwtRegisteredClaimNames.Nbf] = EpochTime.GetIntDate(notBefore.Value.ToUniversalTime());
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'actor' claim { actort, 'value' }.
        /// </summary>
        /// <remarks>If the 'actor' claim is not found, null is returned.</remarks>
        public string Actort
        {
            get
            {
                return this.GetStandardClaim(JwtRegisteredClaimNames.Actort);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'acr' claim { acr, 'value' }.
        /// </summary>
        /// <remarks>If the 'acr' claim is not found, null is returned.</remarks>
        public string Acr
        {
            get
            {
                return this.GetStandardClaim(JwtRegisteredClaimNames.Acr);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'amr' claim { amr, 'value' }.
        /// </summary>
        /// <remarks>If the 'amr' claim is not found, null is returned.</remarks>
        public string Amr
        {
            get
            {
                return this.GetStandardClaim(JwtRegisteredClaimNames.Amr);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'auth_time' claim { auth_time, 'value' }.
        /// </summary>
        /// <remarks>If the 'auth_time' claim is not found, null is returned.</remarks>
        public string AuthTime
        {
            get
            {
                return this.GetStandardClaim(JwtRegisteredClaimNames.AuthTime);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'audience' claim { aud, 'value' } as a list of strings.
        /// </summary>
        /// <remarks>If the 'audience' claim is not found, an empty enumerable is returned.</remarks>
        public IList<string> Aud
        {
            get
            {
                List<string> audiences = new List<string>();

                object value = null;
                if (!TryGetValue(JwtRegisteredClaimNames.Aud, out value))
                {
                    return audiences;
                }

                string str = value as string;
                if (str != null)
                {
                    audiences.Add(str);
                    return audiences;
                }

                // Audiences must be an array of string;
                IEnumerable<object> values = value as IEnumerable<object>;
                if (values != null)
                {
                    foreach (var item in values)
                    {
                        str = item as string;
                        if (str != null)
                        {
                            audiences.Add(str);
                        }
                        else
                        {
                            audiences.Add(item.ToString());
                        }
                    }
                }
                else
                {
                    audiences.Add(JsonExtensions.SerializeToJson(value));
                }

                return audiences;
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'azp' claim { azp, 'value' }.
        /// </summary>
        /// <remarks>If the 'azp' claim is not found, null is returned.</remarks>
        public string Azp
        {
            get
            {
                return this.GetStandardClaim(JwtRegisteredClaimNames.Azp);
            }
        }

        /// <summary>
        /// Gets 'value' of the 'c_hash' claim { c_hash, 'value' }.
        /// </summary>
        /// <remarks>If the 'c_hash' claim is not found, null is returned.</remarks>
        public string CHash
        {
            get
            {
                return this.GetStandardClaim(JwtRegisteredClaimNames.CHash);
            }
        }
        
        /// <summary>
        /// Gets the 'value' of the 'expiration' claim { exp, 'value' }.
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found OR could not be converted to <see cref="Int32"/>, null is returned.</remarks>
        public int? Exp
        {
            get { return this.GetIntClaim(JwtRegisteredClaimNames.Exp); }
        }

        /// <summary>
        /// Gets the 'value' of the 'JWT ID' claim { jti, 'value' }.
        /// </summary>
        /// <remarks>If the 'JWT ID' claim is not found, null is returned.</remarks>
        public string Jti
        {
            get
            {
                return this.GetStandardClaim(JwtRegisteredClaimNames.Jti);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'Issued At' claim { iat, 'value' }.
        /// </summary>
        /// <remarks>If the 'Issued At' claim is not found OR cannot be converted to <see cref="Int32"/> null is returned.</remarks>
        public int? Iat
        {
            get { return this.GetIntClaim(JwtRegisteredClaimNames.Iat); }
        }

        /// <summary>
        /// Gets 'value' of the 'issuer' claim { iss, 'value' }.
        /// </summary>
        /// <remarks>If the 'issuer' claim is not found, null is returned.</remarks>
        public string Iss
        {
            get
            {
                return this.GetStandardClaim(JwtRegisteredClaimNames.Iss);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'expiration' claim { nbf, 'value' }.
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found OR could not be converted to <see cref="Int32"/>, null is returned.</remarks>
        public int? Nbf
        {
            get { return this.GetIntClaim(JwtRegisteredClaimNames.Nbf); }
        }

        /// <summary>
        /// Gets 'value' of the 'nonce' claim { nonce, 'value' }.
        /// </summary>
        /// <remarks>If the 'nonce' claim is not found, null is returned.</remarks>
        public string Nonce
        {
            get
            {
                return this.GetStandardClaim(JwtRegisteredClaimNames.Nonce);
            }
        }
        
        /// <summary>
        /// Gets "value" of the 'subject' claim { sub, 'value' }.
        /// </summary>
        /// <remarks>If the 'subject' claim is not found, null is returned.</remarks>
        public string Sub
        {
            get
            {
                return this.GetStandardClaim(JwtRegisteredClaimNames.Sub);
            }
        }

        /// <summary>
        /// Gets 'value' of the 'notbefore' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found, then <see cref="DateTime.MinValue"/> is returned. Time is returned as UTC.</remarks>
        public DateTime ValidFrom
        {
            get
            {
                return this.GetDateTime(JwtRegisteredClaimNames.Nbf);
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
                return this.GetDateTime(JwtRegisteredClaimNames.Exp);
            }
        }

        /// <summary>
        /// Gets a <see cref="IEnumerable{Claim}"/><see cref="Claim"/> for each JSON { name, value }.
        /// </summary>
        /// <remarks>Each <see cref="Claim"/>(s) returned will have the <see cref="Claim.Type"/> translated according to the mapping found in <see cref="JwtSecurityTokenHandler.InboundClaimTypeMap"/>. Adding and removing to <see cref="JwtSecurityTokenHandler.InboundClaimTypeMap"/> will affect the value of the <see cref="Claim.Type"/>.
        /// <para><see cref="Claim.Issuer"/> and <see cref="Claim.OriginalIssuer"/> will be set to the value of <see cref="Iss"/> ( <see cref="string.Empty"/> if null).</para></remarks>
        public virtual IEnumerable<Claim> Claims
        {
            get
            {
                List<Claim> claims = new List<Claim>();
                string issuer = this.Iss ?? ClaimsIdentity.DefaultIssuer;

                // there is some code redundancy here that was not factored as this is a high use method. Each identity received from the host will pass through here.
                foreach (KeyValuePair<string, object> keyValuePair in this)
                {
                    // do not add claims with null value
                    if (keyValuePair.Value == null)
                    {
                        continue;
                    }

                    string claimType = keyValuePair.Key;
                    string claimValue = keyValuePair.Value as string;
                    Claim c = null;

                    if (claimValue != null)
                    {
                        claims.Add(new Claim(keyValuePair.Key, claimValue, ClaimValueTypes.String, issuer, issuer));
                    }
                    else
                    {

                        var values = keyValuePair.Value as Newtonsoft.Json.Linq.JArray;
                        if (values != null)
                        {
                            foreach(var item in values)
                            {
                                claims.Add(new Claim(keyValuePair.Key, item.ToString()));
                            }
                            continue;
                        }

                        var objects = keyValuePair.Value as IEnumerable<object>;
                        if (objects != null)
                        {
                            foreach (var obj in objects)
                            {
                                string str = obj as string;
                                if (str != null)
                                {
                                    claims.Add(new Claim(keyValuePair.Key, str, ClaimValueTypes.String, issuer, issuer));
                                    continue;
                                }
                                else
                                {
                                    c = new Claim(keyValuePair.Key, JsonExtensions.SerializeToJson(obj), JwtConstants.JsonClaimValueType, issuer, issuer);
                                    c.Properties[JwtSecurityTokenHandler.JsonClaimTypeProperty] = obj.GetType().ToString();
                                    claims.Add(c);
                                }
                            }
                        }
                        else
                        {
                            IDictionary<string, object> dictionary = keyValuePair.Value as IDictionary<string, object>;
                            if (dictionary != null)
                            {
                                foreach (var item in dictionary)
                                {
                                    c = new Claim(claimType, "{" + JsonExtensions.SerializeToJson(item.Key) + ":" + JsonExtensions.SerializeToJson(item.Value) + "}", JwtConstants.JsonClaimValueType, issuer, issuer);
                                    c.Properties[JwtSecurityTokenHandler.JsonClaimTypeProperty] = typeof(IDictionary<string, object>).ToString();
                                    claims.Add(c);
                                }
                            }
                            else
                            {
                                c = new Claim(claimType, JsonExtensions.SerializeToJson(keyValuePair.Value), JwtConstants.JsonClaimValueType, issuer, issuer);
                                c.Properties[JwtSecurityTokenHandler.JsonClaimTypeProperty] = keyValuePair.Value.GetType().ToString();
                                claims.Add(c);
                            }
                        }
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
        public void AddClaim(Claim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }

            this.AddClaims(new Claim[] { claim });
        }

        /// <summary>
        /// Adds a number of <see cref="Claim"/> to the <see cref="JwtPayload"/> as JSON { name, value } pairs.
        /// </summary>
        /// <param name="claims">for each <see cref="Claim"/> a JSON pair { 'Claim.Type', 'Claim.Value' } is added. If duplicate claims are found then a { 'Claim.Type', List&lt;object> } will be created to contain the duplicate values.</param>
        /// <remarks>
        /// <para>Any <see cref="Claim"/> in the <see cref="IEnumerable{Claim}"/> that is null, will be ignored.</para></remarks>
        /// <exception cref="ArgumentNullException">'claims' is null.</exception>
        public void AddClaims(IEnumerable<Claim> claims)
        {
            if (claims == null)
            {
                throw new ArgumentNullException("claims");
            }

            foreach (Claim claim in claims)
            {
                if (claim == null)
                {
                    continue;
                }

                string jsonClaimType = claim.Type;
                object jsonClaimValue = claim.ValueType.Equals(ClaimValueTypes.String, StringComparison.Ordinal) ? claim.Value : GetClaimValueUsingValueType(claim);
                object value;
                if (TryGetValue(jsonClaimType, out value))
                {
                    IList<object> claimValues = value as IList<object>;
                    if (claimValues == null)
                    {
                        claimValues = new List<object>();
                        claimValues.Add(value);
                        this[jsonClaimType] = claimValues;
                    }

                    claimValues.Add(jsonClaimValue);
                }
                else
                {
                    this[jsonClaimType] = jsonClaimValue;
                }
            }
        }

        internal static object GetClaimValueUsingValueType(Claim claim)
        {
            if (claim.ValueType == ClaimValueTypes.Integer)
            {
                int intValue;
                if (int.TryParse(claim.Value, out intValue))
                {
                    return intValue;
                }
            }

            if (claim.ValueType == ClaimValueTypes.Integer32)
            {
                Int32 intValue;
                if (Int32.TryParse(claim.Value, out intValue))
                {
                    return intValue;
                }
            }

            if (claim.ValueType == ClaimValueTypes.Integer64)
            {
                Int64 intValue;
                if (Int64.TryParse(claim.Value, out intValue))
                {
                    return intValue;
                }
            }

            if (claim.ValueType == ClaimValueTypes.Boolean)
            {
                bool boolValue;
                if (bool.TryParse(claim.Value, out boolValue))
                {
                    return boolValue;
                }
            }

            if (claim.ValueType == ClaimValueTypes.Double)
            {
                double doubleValue;
                if (double.TryParse(claim.Value, out doubleValue))
                {
                    return doubleValue;
                }
            }

            return claim.Value;
        }

        internal string GetStandardClaim(string claimType)
        {
            object value = null;
            if (TryGetValue(claimType, out value))
            {
                string str = value as string;
                if (str != null)
                {
                    return str;
                }

                return JsonExtensions.SerializeToJson(value);
            }

            return null;
        }

        internal int? GetIntClaim(string claimType)
        {
            int? retval = null;

            object value;
            if (TryGetValue(claimType, out value))
            {
                IList<object> claimValues = value as IList<object>;
                if (claimValues != null)
                {
                    foreach (object obj in claimValues)
                    {
                        retval = null;
                        if (obj == null)
                        {
                            continue;
                        }

                        try
                        {
                            retval = Convert.ToInt32(obj, CultureInfo.InvariantCulture);
                        }
                        catch (System.FormatException)
                        {
                            retval = null;
                        }
                        catch (System.InvalidCastException)
                        {
                            retval = null;
                        }
                        catch (OverflowException)
                        {
                            retval = null;
                        }

                        if (retval != null)
                        {
                            return retval;
                        }
                    }
                }
                else
                {
                    try
                    {
                        retval = Convert.ToInt32(value, CultureInfo.InvariantCulture);
                    }
                    catch (System.FormatException)
                    {
                        retval = null;
                    }
                    catch (OverflowException)
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
        /// <exception cref="SecurityTokenException">if an overflow exception is thrown by the runtime.</exception>
        /// <returns>the DateTime representation of a claim.</returns>
        private DateTime GetDateTime(string key)
        {
            object dateValue;
            if (!TryGetValue(key, out dateValue))
            {
                return DateTime.MinValue;
            }

            // if there are multiple dates, take the first one.
            try
            {
                long secondsAfterBaseTime;
                IList<object> dateValues = dateValue as IList<object>;
                if (dateValues != null)
                {
                    if (dateValues.Count == 0)
                    {
                        return DateTime.MinValue;
                    }
                    else
                    {
                        dateValue = dateValues[0];
                    }
                }

                // null converts to 0.
                secondsAfterBaseTime = Convert.ToInt64(dateValue, CultureInfo.InvariantCulture);
                return EpochTime.DateTime(secondsAfterBaseTime);
            }
            catch (Exception ex)
            {
                if (ex is FormatException || ex is ArgumentException || ex is InvalidCastException)
                {
                    throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10700, key, dateValue ?? "<null>", ex));
                }

                if (ex is OverflowException)
                {
                    throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10701, key, dateValue ?? "<null>", ex));
                }

                throw;
            }
        }

        /// <summary>
        /// Serializes this instance to JSON.
        /// </summary>
        /// <returns>this instance as JSON.</returns>
        /// <remarks>use <see cref="JsonExtensions.Serializer"/> to customize JSON serialization.</remarks>
        public virtual string SerializeToJson()
        {
            return JsonExtensions.SerializeToJson(this as IDictionary<string, object>);
        }

        /// <summary>
        /// Encodes this instance as Base64UrlEncoded JSON.
        /// </summary>
        /// <returns>Base64UrlEncoded JSON.</returns>
        /// <remarks>use <see cref="JsonExtensions.Serializer"/> to customize JSON serialization.</remarks>
        public virtual string Base64UrlEncode()
        {
            return Base64UrlEncoder.Encode(SerializeToJson());
        }

        /// <summary>
        /// Deserializes Base64UrlEncoded JSON into a <see cref="JwtPayload"/> instance.
        /// </summary>
        /// <param name="base64UrlEncodedJsonString">base64url encoded JSON to deserialize.</param>
        /// <returns>an instance of <see cref="JwtPayload"/>.</returns>
        /// <remarks>use <see cref="JsonExtensions.Deserializer"/> to customize JSON serialization.</remarks>
        public static JwtPayload Base64UrlDeserialize(string base64UrlEncodedJsonString)
        {
            return JsonExtensions.DeserializeJwtPayload(Base64UrlEncoder.Decode(base64UrlEncodedJsonString));
        }

        /// <summary>
        /// Deserialzes JSON into a <see cref="JwtPayload"/> instance.
        /// </summary>
        /// <param name="jsonString">the JSON to deserialize.</param>
        /// <returns>an instance of <see cref="JwtPayload"/>.</returns>
        /// <remarks>use <see cref="JsonExtensions.Deserializer"/> to customize JSON serialization.</remarks>
        public static JwtPayload Deserialize(string jsonString)
        {
            return JsonExtensions.DeserializeJwtPayload(jsonString);
        }
    }
}
