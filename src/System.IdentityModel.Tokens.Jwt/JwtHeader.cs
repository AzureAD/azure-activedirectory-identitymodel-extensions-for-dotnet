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
    using System.Diagnostics.CodeAnalysis;
    using System.Globalization;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Initializes a new instance of <see cref="JwtHeader"/> which contains JSON objects representing the cryptographic operations applied to the JWT and optionally any additional properties of the JWT. 
    /// The member names within the JWT Header are referred to as Header Parameter Names. 
    /// <para>These names MUST be unique and the values must be <see cref="string"/>(s). The corresponding values are referred to as Header Parameter Values.</para>
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2237:MarkISerializableTypesWithSerializable"), SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Suppressed for private fields.")]
    public class JwtHeader : Dictionary<string, string>
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
        /// <para>if the clause  is a <see cref="NamedKeySecurityKeyIdentifierClause"/> Header Parameter { clause.Name, clause.KeyIdentifier } will be added.</para>
        /// <para>For example, if clause.Name == 'kid' and clause.KeyIdentifier == 'SecretKey99'. The JSON object { kid, SecretKey99 } would be added.</para>
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
        public JwtHeader(SigningCredentials signingCredentials = null)
            : base(StringComparer.Ordinal)
        {
            this.Add(JwtHeaderParameterNames.Typ, JwtConstants.HeaderType);

            if (signingCredentials != null)
            {
                this.signingCredentials = signingCredentials;

                string algorithm = signingCredentials.SignatureAlgorithm;
                if (JwtSecurityTokenHandler.OutboundAlgorithmMap.ContainsKey(signingCredentials.SignatureAlgorithm))
                {
                    algorithm = JwtSecurityTokenHandler.OutboundAlgorithmMap[algorithm];
                }

                this.Add(JwtHeaderParameterNames.Alg, algorithm);
                if (signingCredentials.SigningKeyIdentifier != null)
                {
                    foreach (SecurityKeyIdentifierClause clause in signingCredentials.SigningKeyIdentifier)
                    {
                        NamedKeySecurityKeyIdentifierClause namedKeyClause = clause as NamedKeySecurityKeyIdentifierClause;
                        if (namedKeyClause != null)
                        {
                            this.Add(namedKeyClause.Name, namedKeyClause.KeyIdentifier);
                        }
                    }
                }

                X509SigningCredentials x509SigningCredentials = signingCredentials as X509SigningCredentials;
                if (x509SigningCredentials != null && x509SigningCredentials.Certificate != null)
                {
                    this.Add(JwtHeaderParameterNames.X5t, Base64UrlEncoder.Encode(x509SigningCredentials.Certificate.GetCertHash()));
                }
            }
            else
            {
                this.Add(JwtHeaderParameterNames.Alg, JwtAlgorithms.NONE);
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
                string algorithm = null;
                this.TryGetValue(JwtHeaderParameterNames.Alg, out algorithm);
                return algorithm;
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
        /// Gets a <see cref="SecurityKeyIdentifier"/> that contains a <see cref="SecurityKeyIdentifierClause"/> for each key found.
        /// </summary>
        /// <remarks>
        /// Keys are identified by matching a 'Reserved Header Parameter Name' found in the in JSON Web Signature specification.
        /// <para>Names recognized are: jku, jkw, kid, x5c, x5t, x5u</para>
        /// <para>'x5t' adds a <see cref="X509ThumbprintKeyIdentifierClause"/> passing a the Base64UrlDecoded( Value ) to the constructor.</para>
        /// <para>'jku', 'jkw', 'kid', 'x5u', 'x5c' each add a <see cref="NamedKeySecurityKeyIdentifierClause"/> with the { Name, Value } passed to the <see cref=" NamedKeySecurityKeyIdentifierClause( string, string )"/>.</para>
        /// <para>   </para>
        /// <para>If no keys are found, an empty <see cref="SecurityKeyIdentifier"/> will be returned.</para>
        /// </remarks>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations", Justification="Back compat")]
        public virtual SecurityKeyIdentifier SigningKeyIdentifier
        {
            get
            {
                SecurityKeyIdentifier ski = new SecurityKeyIdentifier();
                string keyIdentifier = null;

                if (this.TryGetValue(JwtHeaderParameterNames.X5t, out keyIdentifier))
                {
                    try
                    {
                        ski.Add(new X509ThumbprintKeyIdentifierClause(Base64UrlEncoder.DecodeBytes(keyIdentifier)));
                    }
                    catch (Exception ex)
                    {
                        if (DiagnosticUtility.IsFatal(ex))
                        {
                            throw;
                        }

                        throw new FormatException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10118, JwtHeaderParameterNames.X5t), ex);
                    }
                }

                if (this.TryGetValue(JwtHeaderParameterNames.Jku, out keyIdentifier))
                {
                    ski.Add(new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.Jku, keyIdentifier));
                }

                if (this.TryGetValue(JwtHeaderParameterNames.Jwk, out keyIdentifier))
                {
                    ski.Add(new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.Jwk, keyIdentifier));
                }

                if (this.TryGetValue(JwtHeaderParameterNames.X5u, out keyIdentifier))
                {
                    ski.Add(new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.X5u, keyIdentifier));
                }

                if (this.TryGetValue(JwtHeaderParameterNames.X5c, out keyIdentifier))
                {
                    ski.Add(new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.X5c, keyIdentifier));
                }

                if (this.TryGetValue(JwtHeaderParameterNames.Kid, out keyIdentifier))
                {
                    ski.Add(new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.Kid, keyIdentifier));
                }

                return ski;
            }
        }

        /// <summary>
        /// Encodes this instance as a Base64UrlEncoded string.
        /// </summary>
        /// <remarks>Returns the current state. If this instance has changed since the last call, the value will be different.</remarks>
        /// <returns>a string BaseUrlEncoded representing the contents of this header.</returns>
        public string Encode()
        {
            return Base64UrlEncoder.Encode(this.SerializeToJson());
        }
    }
}
