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
using System.Security.Cryptography.X509Certificates;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// The <see cref="JwtHeader"/> contains JSON objects representing the cryptographic operations applied to the JWT and optionally any additional properties of the JWT. 
    /// The member names within the JWT Header are referred to as Header Parameter Names. 
    /// <para>These names MUST be unique and the values must be <see cref="string"/>(s). The corresponding values are referred to as Header Parameter Values.</para>
    /// </summary>
    public class JwtHeader : Dictionary<string, string>
    {
        private SigningCredentials _signingCredentials;

        /// <summary>
        /// Creates an empty <see cref="JwtHeader"/>
        /// </summary>
        public JwtHeader()
            : base( StringComparer.Ordinal )
        {
        }

        /// <summary>
        /// Creates a new <see cref="JwtHeader"/> with the Header Parameters as follows: 
        /// <para>{ { typ, JWT }, { alg, Mapped( <see cref="System.IdentityModel.Tokens.SigningCredentials.SignatureAlgorithm"/> } }
        /// See: Algorithm Mapping below.</para>
        /// </summary>
        /// <param name="signingCredentials">The <see cref="SigningCredentials"/> that will be or were used to sign the <see cref="JwtSecurityToken"/>.</param>
        /// <remarks>
        /// <para>For each <see cref="SecurityKeyIdentifierClause"/> in signingCredentials.SigningKeyIdentifier</para>
        /// <para>if the clause  is a <see cref="NamedKeySecurityKeyIdentifierClause"/> Header Parameter { clause.Name, clause.KeyIdentifier } will be added.</para>
        /// <para>For example, if clause.Name == 'kid' and clause.Keyidentifier == 'SecretKey99'. The JSON object { kid, SecretKey99 } would be added.</para>
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
        public JwtHeader( SigningCredentials signingCredentials = null )
            : base( StringComparer.Ordinal )
        {
            Add( JwtConstants.ReservedHeaderParameters.Type, JwtConstants.HeaderType );

            if ( signingCredentials != null )
            {
                _signingCredentials = signingCredentials;

                string algorithm = signingCredentials.SignatureAlgorithm;
                if ( JwtSecurityTokenHandler.OutboundAlgorithmMap.ContainsKey( signingCredentials.SignatureAlgorithm ) )
                {
                    algorithm = JwtSecurityTokenHandler.OutboundAlgorithmMap[algorithm];
                }

                Add( JwtConstants.ReservedHeaderParameters.Algorithm, algorithm );
                if ( signingCredentials.SigningKeyIdentifier != null )
                {
                    foreach ( SecurityKeyIdentifierClause clause in signingCredentials.SigningKeyIdentifier )
                    {
                        NamedKeySecurityKeyIdentifierClause namedKeyClause = clause as NamedKeySecurityKeyIdentifierClause;
                        if ( namedKeyClause != null )
                        {
                            Add( namedKeyClause.Name, namedKeyClause.KeyIdentifier );
                        }
                    }
                }
                
                X509SigningCredentials x509SigningCredentials = signingCredentials as X509SigningCredentials;
                if ( x509SigningCredentials != null  && x509SigningCredentials.Certificate != null )
                {
                    Add( JwtConstants.ReservedHeaderParameters.X509CertificateThumbprint, Base64UrlEncoder.Encode( x509SigningCredentials.Certificate.GetCertHash() ) );
                }
            }
            else
            {
                Add( JwtConstants.ReservedHeaderParameters.Algorithm, JwtConstants.Algorithms.NONE );
            }
        }

        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        /// <remarks>If the signature algorithm is not found, null is returned.</remarks>
        public string SignatureAlgorithm
        {
            get
            {
                string algorithm = null;
                TryGetValue( JwtConstants.ReservedHeaderParameters.Algorithm, out algorithm );
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
                return _signingCredentials;
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
        public virtual SecurityKeyIdentifier SigningKeyIdentifier
        {
            get
            {
                SecurityKeyIdentifier ski = new SecurityKeyIdentifier();
                string keyIdentifier = null;

                if ( this.TryGetValue( JwtConstants.ReservedHeaderParameters.X509CertificateThumbprint, out keyIdentifier ) )
                {
                    try
                    {
                        ski.Add( new X509ThumbprintKeyIdentifierClause( Base64UrlEncoder.DecodeBytes( keyIdentifier ) ) );
                    }
                    catch ( Exception ex )
                    {
                        if ( DiagnosticUtility.IsFatal( ex ) )
                        {
                            throw;
                        }

                        throw new FormatException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10118, JwtConstants.ReservedHeaderParameters.X509CertificateThumbprint ), ex );
                    }
                }

                if ( this.TryGetValue( JwtConstants.ReservedHeaderParameters.JsonSetUrl, out keyIdentifier ) )
                {
                    ski.Add( new NamedKeySecurityKeyIdentifierClause( JwtConstants.ReservedHeaderParameters.JsonSetUrl, keyIdentifier ) );
                }

                if ( this.TryGetValue( JwtConstants.ReservedHeaderParameters.JsonWebKey, out keyIdentifier ) )
                {
                    ski.Add( new NamedKeySecurityKeyIdentifierClause( JwtConstants.ReservedHeaderParameters.JsonWebKey, keyIdentifier ) );
                }

                if ( this.TryGetValue( JwtConstants.ReservedHeaderParameters.X509Url, out keyIdentifier ) )
                {
                    ski.Add( new NamedKeySecurityKeyIdentifierClause( JwtConstants.ReservedHeaderParameters.X509Url, keyIdentifier ) );
                }

                if ( this.TryGetValue( JwtConstants.ReservedHeaderParameters.X509CertificateChain, out keyIdentifier ) )
                {
                    ski.Add( new NamedKeySecurityKeyIdentifierClause( JwtConstants.ReservedHeaderParameters.X509CertificateChain, keyIdentifier ) );
                }

                if ( this.TryGetValue( JwtConstants.ReservedHeaderParameters.KeyId, out keyIdentifier ) )
                {
                    ski.Add( new NamedKeySecurityKeyIdentifierClause( JwtConstants.ReservedHeaderParameters.KeyId, keyIdentifier ) );
                }

                return ski;
            }
        }

        /// <summary>
        /// Encodes this instance as a Base64UrlEncoded string.
        /// </summary>
        /// <remarks>Returns the current state. If this instance has changed since the last call, the value will be different.</remarks>
        public string Encode()
        {
            return Base64UrlEncoder.Encode( this.SerializeToJson() );
        }
    }
}
