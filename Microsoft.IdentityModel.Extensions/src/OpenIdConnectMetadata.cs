// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Runtime.Serialization;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Signing metadata parsed from a WSFed endpoint.
    /// </summary>
    [DataContract]
    public class OpenIdConnectMetadata
    {
        Collection<X509SecurityToken> _signingTokens = new Collection<X509SecurityToken>();

        public OpenIdConnectMetadata()
        {
        }

        /// <summary>
        /// Gets or sets the authorization endpoint.
        /// </summary>       
        [DataMember(Name = OpenIdConnectMetadataNames.Authorization_Endpoint)]
        public string Authorization_Endpoint { get; set; }

        /// <summary>
        /// Gets or sets the end session endpoint.
        /// </summary>
        [DataMember(Name = OpenIdConnectMetadataNames.End_Session_Endpoint)]
        public string End_Session_Endpoint { get; set; }

        /// <summary>
        /// Gets or sets the token issuer.
        /// </summary>
        [DataMember(Name = OpenIdConnectMetadataNames.Issuer)]
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the token issuer.
        /// </summary>
        [DataMember(Name = OpenIdConnectMetadataNames.Jwks_Uri)]
        public string Jwks_Uri{ get; set; }

        /// <summary>
        /// Gets or sets the Signing tokens.
        /// </summary>

        public ICollection<X509SecurityToken> SigningTokens 
        { 
            get 
            { 
                if ( _signingTokens == null)
                {
                    _signingTokens = new Collection<X509SecurityToken>();
                }

                return _signingTokens; 
            } 
        }

        /// <summary>
        /// Gets or sets the token endpoint.
        /// </summary>
        [DataMember(Name = OpenIdConnectMetadataNames.Token_Endpoint)]
        public string Token_Endpoint { get; set; }

    }
}
