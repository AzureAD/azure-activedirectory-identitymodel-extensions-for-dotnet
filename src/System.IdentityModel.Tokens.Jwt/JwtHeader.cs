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

namespace System.IdentityModel.Tokens.Jwt
{
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

        /// <summary>
        /// Gets the key identifier for the security key used to sign the token
        /// </summary>
        public string Kid
        {
            get
            {
                return GetStandardClaim(JwtHeaderParameterNames.Kid);
            }
        }

        /// <summary>
        /// Gets the thhumbprint of the certificate used to sign the token
        /// </summary>
        public string X5t
        {
            get
            {
                return GetStandardClaim(JwtHeaderParameterNames.X5t);
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
