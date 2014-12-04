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

namespace System.IdentityModel.Tokens
{
    using System.Collections.Generic;
    using System.Globalization;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Initializes a new instance of <see cref="JwtHeader"/> which contains JSON objects representing the cryptographic operations applied to the JWT and optionally any additional properties of the JWT. 
    /// The member names within the JWT Header are referred to as Header Parameter Names. 
    /// <para>These names MUST be unique and the values must be <see cref="string"/>(s). The corresponding values are referred to as Header Parameter Values.</para>
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2237:MarkISerializableTypesWithSerializable"), System.Diagnostics.CodeAnalysis.SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Serialize not really supported.")]
    public class JwtHeader : Dictionary<string, object>
    {
        private SigningCredentials signingCredentials;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class. Default string comparer <see cref="StringComparer.Ordinal"/>.
        /// </summary>
        public JwtHeader()
            : base(StringComparer.Ordinal)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class. With the Header Parameters as follows: 
        /// <para>{ { typ, JWT }, { alg, Mapped( <see cref="System.IdentityModel.Tokens.SigningCredentials.SignatureAlgorithm"/> } }
        /// See: Algorithm Mapping below.</para>
        /// </summary>
        /// <param name="signingCredentials">The <see cref="SigningCredentials"/> that will be or were used to sign the <see cref="JwtSecurityToken"/>.</param>
        /// <remarks>
        /// <para>For each <see cref="SecurityKeyIdentifierClause"/> in signingCredentials.SigningKeyIdentifier</para>
        /// <para>if the clause  is a <see cref="NamedKeySecurityKeyIdentifierClause"/> Header Parameter { clause.Name, clause.Id } will be added.</para>
        /// <para>For example, if clause.Name == 'kid' and clause.Id == 'SecretKey99'. The JSON object { kid, SecretKey99 } would be added.</para>
        /// <para>In addition, if the <see cref="SigningCredentials"/> is a <see cref="X509SigningCredentials"/> the JSON object { x5t, Base64UrlEncoded( <see cref="X509Certificate.GetCertHashString()"/> } will be added.</para>
        /// <para>This simplifies the common case where a X509Certificate is used.</para>
        /// <para>================= </para>
        /// <para>Algorithm Mapping</para>
        /// <para>================= </para>
        /// <para><see cref="System.IdentityModel.Tokens.SigningCredentials.SignatureAlgorithm"/> describes the algorithm that is discoverable by the CLR runtime.</para>
        /// <para>The  { alg, 'value' } placed in the header reflects the JWT specification.</para>
        /// <see cref="JwtSecurityTokenHandler.OutboundAlgorithmMap"/> contains a signature mapping where the 'value' above will be translated according to this mapping.
        /// <para>Current mapping is:</para>
        /// <para>&#160;&#160;&#160;&#160;'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => 'RS256'</para>
        /// <para>&#160;&#160;&#160;&#160;'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256' => 'HS256'</para>
        /// </remarks>
        public JwtHeader(SigningCredentials signingCredentials)
            : base(StringComparer.Ordinal)
        {
            this[JwtHeaderParameterNames.Typ] = JwtConstants.HeaderType;

            if (signingCredentials != null)
            {
                this.signingCredentials = signingCredentials;

                string algorithm = signingCredentials.SignatureAlgorithm;
                if (JwtSecurityTokenHandler.OutboundAlgorithmMap.ContainsKey(signingCredentials.SignatureAlgorithm))
                {
                    algorithm = JwtSecurityTokenHandler.OutboundAlgorithmMap[algorithm];
                }

                this[JwtHeaderParameterNames.Alg] = algorithm;
                this[JwtHeaderParameterNames.Kid] = signingCredentials.SigningKey.KeyId;

                //if (signingCredentials.SigningKeyIdentifier != null)
                //{
                //    foreach (SecurityKeyIdentifierClause clause in signingCredentials.SigningKeyIdentifier)
                //    {
                //        NamedKeySecurityKeyIdentifierClause namedKeyClause = clause as NamedKeySecurityKeyIdentifierClause;
                //        if (namedKeyClause != null)
                //        {
                //            this[namedKeyClause.Name] = namedKeyClause.Id;
                //        }
                //    }
                //}

                //X509SigningCredentials x509SigningCredentials = signingCredentials as X509SigningCredentials;
                //if (x509SigningCredentials != null && x509SigningCredentials.Certificate != null)
                //{
                //    this[JwtHeaderParameterNames.X5t] = Base64UrlEncoder.Encode(x509SigningCredentials.Certificate.GetCertHash());
                //}
            }
            else
            {
                this[JwtHeaderParameterNames.Alg] = JwtAlgorithms.NONE;
            }
        }

        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        /// <remarks>If the signature algorithm is not found, null is returned.</remarks>
        public string Alg
        {
            get
            {
                return this.GetStandardClaim(JwtHeaderParameterNames.Alg);
            }
        }

        /// <summary>
        /// Gets the <see cref="SigningCredentials"/> passed in the constructor.
        /// </summary>
        /// <remarks>This value may be null.</remarks>
        public SigningCredentials SigningCredentials
        {
            get
            {
                return this.signingCredentials;
            }
        }

        /// <summary>
        /// Gets the mime type (Typ) of the token.
        /// </summary>
        /// <remarks>If the mime type is not found, null is returned.</remarks>
        public string Typ
        {
            get
            {
                return this.GetStandardClaim(JwtHeaderParameterNames.Typ);
            }
        }

        ///// <summary>
        ///// Gets a <see cref="SecurityKeyIdentifier"/> that contains a <see cref="SecurityKeyIdentifierClause"/> for each key found.
        ///// </summary>
        ///// <remarks>
        ///// Keys are identified by matching a 'Reserved Header Parameter Name' found in the in JSON Web Signature specification.
        ///// <para>Names recognized are: jku, jkw, kid, x5c, x5t, x5u</para>
        ///// <para>'x5t' adds a <see cref="X509ThumbprintKeyIdentifierClause"/> passing a the Base64UrlDecoded( Value ) to the constructor.</para>
        ///// <para>'jku', 'jkw', 'kid', 'x5u', 'x5c' each add a <see cref="NamedKeySecurityKeyIdentifierClause"/> with the { Name, Value } passed to the <see cref=" NamedKeySecurityKeyIdentifierClause( string, string )"/>.</para>
        ///// <para>   </para>
        ///// <para>If no keys are found, an empty <see cref="SecurityKeyIdentifier"/> will be returned.</para>
        ///// </remarks>
        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations", Justification="Back compat")]
        //public virtual SecurityKeyIdentifier SigningKeyIdentifier
        //{
        //    get
        //    {
        //        SecurityKeyIdentifier ski = new SecurityKeyIdentifier();
        //        if (this.ContainsKey(JwtHeaderParameterNames.X5t))
        //        {
        //            try
        //            {
        //                ski.Add(new X509ThumbprintKeyIdentifierClause(Base64UrlEncoder.DecodeBytes(GetStandardClaim(JwtHeaderParameterNames.X5t))));
        //            }
        //            catch (Exception ex)
        //            {
        //                if (DiagnosticUtility.IsFatal(ex))
        //                {
        //                    throw;
        //                }

        //                throw new FormatException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10705, JwtHeaderParameterNames.X5t), ex);
        //            }
        //        }

        //        if (this.ContainsKey(JwtHeaderParameterNames.Jku))
        //        {
        //            ski.Add(new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.Jku, GetStandardClaim(JwtHeaderParameterNames.Jku)));
        //        }

        //        if (this.ContainsKey(JwtHeaderParameterNames.Jwk))
        //        {
        //            ski.Add(new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.Jwk, GetStandardClaim(JwtHeaderParameterNames.Jwk)));
        //        }

        //        if (this.ContainsKey(JwtHeaderParameterNames.X5u))
        //        {
        //            ski.Add(new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.X5u, GetStandardClaim(JwtHeaderParameterNames.X5u)));
        //        }

        //        if (this.ContainsKey(JwtHeaderParameterNames.X5c))
        //        {
        //            ski.Add(new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.X5c, GetStandardClaim(JwtHeaderParameterNames.X5c)));
        //        }

        //        if (this.ContainsKey(JwtHeaderParameterNames.Kid))
        //        {
        //            ski.Add(new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.Kid, GetStandardClaim(JwtHeaderParameterNames.Kid)));
        //        }

        //        return ski;
        //    }
        //}

        public string Kid
        {
            get
            {
                string kid = GetStandardClaim(JwtHeaderParameterNames.Kid);
                if (string.IsNullOrWhiteSpace(kid))
                {
                    kid = GetStandardClaim(JwtHeaderParameterNames.X5t);
                }

                return kid;
            }
            set
            {
            }
        }

        public string X5t
        {
            get
            {
                return GetStandardClaim(JwtHeaderParameterNames.X5t);
            }
            set
            {
                Kid = GetStandardClaim(JwtHeaderParameterNames.X5t);
            }

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
        /// Deserializes Base64UrlEncoded JSON into a <see cref="JwtHeader"/> instance.
        /// </summary>
        /// <param name="base64UrlEncodedJsonString">base64url encoded JSON to deserialize.</param>
        /// <returns>an instance of <see cref="JwtHeader"/>.</returns>
        /// <remarks>use <see cref="JsonExtensions.Deserializer"/> to customize JSON serialization.</remarks>
        public static JwtHeader Base64UrlDeserialize(string base64UrlEncodedJsonString)
        {
            return JsonExtensions.DeserializeJwtHeader(Base64UrlEncoder.Decode(base64UrlEncodedJsonString));
        }

        /// <summary>
        /// Deserialzes JSON into a <see cref="JwtHeader"/> instance.
        /// </summary>
        /// <param name="jsonString"> the JSON to deserialize.</param>
        /// <returns>an instance of <see cref="JwtHeader"/>.</returns>
        /// <remarks>use <see cref="JsonExtensions.Deserializer"/> to customize JSON serialization.</remarks>
        public static JwtHeader Deserialize(string jsonString)
        {
            return JsonExtensions.DeserializeJwtHeader(jsonString);
        }
    }
}
