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
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Selectors;
using System.Xml;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// <see cref="NamedKeyIssuerTokenResolver"/> represents a collection of named sets of <see cref="SecurityKey"/>(s) that can be matched by a
    /// <see cref="NamedKeySecurityKeyIdentifierClause"/> and return a <see cref="NamedKeySecurityToken"/> that contains <see cref="SecurityKey"/>(s).
    /// </summary>
    public class NamedKeyIssuerTokenResolver : IssuerTokenResolver
    {
        private IDictionary<string, IList<SecurityKey>> _keys;
        private List<XmlNode> _unprocessedNodes = new List<XmlNode>();
        IssuerTokenResolver _issuerTokenResolver;

        /// <summary>
        /// Default constructor
        /// </summary>
        public NamedKeyIssuerTokenResolver()
            : this( null, null )
        {
        }

        /// <summary>
        /// Populates this instance with a named collection of <see cref="SecurityKey"/>(s) and an optional <see cref="SecurityTokenResolver"/> that will be called when a 
        /// <see cref="SecurityKeyIdentifier"/> or <see cref="SecurityKeyIdentifierClause"/> cannot be resolved.
        /// </summary>
        /// <param name="keys">A named collection of <see cref="SecurityKey"/>(s).</param>
        /// <param name="innerTokenResolver">A <see cref="IssuerTokenResolver"/> to call when resolving fails, before calling base.</param>
        /// <remarks>if 'keys' is null an empty collection will be created. A named collection of <see cref="SecurityKey"/>(s) can be added by accessing the property <see cref="SecurityKeys"/>.</remarks>
        public NamedKeyIssuerTokenResolver( IDictionary<string, IList<SecurityKey>> keys = null, IssuerTokenResolver innerTokenResolver = null )
        {

            if ( keys == null )
            {
                _keys = new Dictionary<string, IList<SecurityKey>>();
            }
            else
            {
                _keys = keys;
            }

            _issuerTokenResolver = innerTokenResolver;
        }

        /// <summary>
        /// Gets the named collection of <see cref="SecurityKey"/>(s).
        /// </summary>
        public IDictionary<string, IList<SecurityKey>> SecurityKeys
        {
            get { return _keys; }
        }

        /// <summary>
        /// Gets or sets the <see cref="SecurityTokenResolver"/> to call when <see cref="SecurityKeyIdentifier"/> or <see cref="SecurityKeyIdentifierClause"/> fails to resolve, before calling base.
        /// </summary>
        /// <exception cref="ArgumentNullException">'value' is null.</exception>
        /// <exception cref="ArgumentException">'object.ReferenceEquals( this, value)' is true.</exception>
        public IssuerTokenResolver IssuerTokenResolver
        {
            get 
            {
                return _issuerTokenResolver;
            }

            set 
            {
                if ( value == null )
                {
                    throw new ArgumentNullException( "value" );
                }

                if ( object.ReferenceEquals( this, value ) )
                {
                    throw new ArgumentException( JwtErrors.Jwt10117 );
                }

                _issuerTokenResolver = value;
            }
        }

        /// <summary>
        /// Populates the <see cref="SecurityKeys"/> from xml.
        /// </summary>
        /// <param name="nodeList">xml for processing.</param>
        /// <exception cref="ArgumentNullException">'nodeList' is null.</exception>
        /// <remarks>Only <see cref="XmlNode"/>(s) with <see cref="XmlElement.LocalName"/> == 'securityKey' will be processed. Unprocessed nodes will added to a list and can be accessed using the <see cref="UnprocessedXmlNodes"/> property.</remarks>
        public override void LoadCustomConfiguration( XmlNodeList nodeList )
        {
            if ( nodeList == null )
            {
                throw new ArgumentNullException( "nodeList" );
            }

            for ( int i=0; i < nodeList.Count; i++ )
            {
                XmlElement element = nodeList[i] as XmlElement;

                if ( element != null )
                {
                    if ( string.Equals( element.LocalName, JwtConfigurationStrings.Elements.SecurityKey, StringComparison.Ordinal ) )
                    {
                        ReadSecurityKey( element );
                    }
                    else
                    {
                        _unprocessedNodes.Add( nodeList[i] );
                    }
                }
                else
                {
                    _unprocessedNodes.Add( nodeList[i] );
                }
            }
        }

        /// <summary>
        /// Gets the unprocessed <see cref="XmlNode"/>(s) from <see cref="LoadCustomConfiguration"/>.
        /// </summary>
        /// <remarks><see cref="LoadCustomConfiguration"/> processes only <see cref="XmlElement"/>(s) that have the <see cref="XmlElement.LocalName"/> == 'securityKey'. Unprocessed <see cref="XmlNode"/>(s) are accessible here.</remarks>
        public IList<XmlNode> UnprocessedXmlNodes
        {
            get { return _unprocessedNodes; }
        }

        /// <summary>
        /// When processing xml in <see cref="LoadCustomConfiguration"/> each <see cref="XmlElement"/> that has <see cref="XmlElement.LocalName"/> = "securityKey' is passed here for processing.
        /// </summary>
        /// <param name="element">contains xml to map to a named <see cref="SecurityKey"/>.</param>
        /// <remarks>
        ///<para>A single <see cref="XmlElement"/> is expected with up to three attributes: {'expected values'}.</para>
        ///<para>&lt;securityKey</para>
        ///<para>&#160;&#160;&#160;&#160;symmetricKey {required}</para>
        ///<para>&#160;&#160;&#160;&#160;name         {required}</para>
        ///<para>&#160;&#160;&#160;&#160;EncodingType or encodingType {optional}</para>
        ///<para>></para>
        ///<para>&lt;/securityKey></para>
        ///<para>If "EncodingType' type is specified only:</para>
        ///<para>&#160;&#160;&#160;&#160;'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'</para>
        ///<para>&#160;&#160;&#160;&#160;'Base64Binary'</para>
        ///<para>&#160;&#160;&#160;&#160;'base64Binary'</para>
        ///are allowed and have the same meaning.
        ///<para>When a symmetricKey is found, Convert.FromBase64String( value ) is applied to create the key.</para>
        ///</remarks>
        ///<exception cref="ArgumentNullException">'element' is null.</exception>
        ///<exception cref="ConfigurationErrorsException">attribute 'symmetricKey' is not found.</exception>
        ///<exception cref="ConfigurationErrorsException">value of 'symmetricKey' is empty or whitespace.</exception>
        ///<exception cref="ConfigurationErrorsException">attribute 'name' is not found.</exception>
        ///<exception cref="ConfigurationErrorsException">value of 'name' is empty or whitespace.</exception>
        ///<exception cref="ConfigurationErrorsException">value of 'encodingType' is not valid.</exception>
        protected virtual void ReadSecurityKey( XmlElement element )
        {
            if ( element == null )
            {
                throw new ArgumentNullException( "node" );
            }

            string key = null;
            string name = null;

            XmlNode attributeNode;
            attributeNode = element.Attributes.GetNamedItem( JwtConfigurationStrings.Attributes.SymmetricKey );
            if ( attributeNode == null )
            {
                throw new ConfigurationErrorsException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10106, element.OuterXml ) );
            }

            key = attributeNode.Value;
            if ( string.IsNullOrWhiteSpace( key ) )
            {
                throw new ConfigurationErrorsException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10600, JwtConfigurationStrings.Attributes.SymmetricKey, element.OuterXml ) );
            }

            attributeNode = element.Attributes.GetNamedItem( JwtConfigurationStrings.Attributes.Name );
            if ( attributeNode == null )
            {
                throw new ConfigurationErrorsException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10107, element.OuterXml ) );
            }

            name = attributeNode.Value;
            if ( string.IsNullOrWhiteSpace( name ) )
            {
                throw new ConfigurationErrorsException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10600, JwtConfigurationStrings.Attributes.Name, element.OuterXml ) );
            }

            attributeNode = element.Attributes.GetNamedItem( WSSecurity10Constants.Attributes.EncodingType );
            if ( attributeNode == null )
            {
                attributeNode = element.Attributes.GetNamedItem( WSSecurity10Constants.Attributes.EncodingTypeLower );
            }

            if ( attributeNode != null )
            {                
                if ( !StringComparer.Ordinal.Equals( attributeNode.Value, WSSecurity10Constants.Base64BinaryLower )
                &&   !StringComparer.Ordinal.Equals( attributeNode.Value, WSSecurity10Constants.Base64EncodingType )
                &&   !StringComparer.Ordinal.Equals( attributeNode.Value, WSSecurity10Constants.Base64Binary ) )
                {
                    throw new ConfigurationErrorsException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10105, WSSecurity10Constants.Base64BinaryLower, WSSecurity10Constants.Base64Binary, WSSecurity10Constants.Base64EncodingType, attributeNode.Value, element.OuterXml ) );
                }
            }

            byte[] keybytes = Convert.FromBase64String( key );
            IList<SecurityKey> keys = null;
            if ( !_keys.TryGetValue( name, out keys ) )
            {
                keys = new List<SecurityKey>();
                _keys.Add( name, keys );
            }

            keys.Add( new InMemorySymmetricSecurityKey( keybytes ) );
        }

        /// <summary>
        /// Finds the first <see cref="SecurityKey"/> in a named collection that match the <see cref="SecurityKeyIdentifierClause"/>.
        /// </summary>
        /// <remarks>If there is no match, then <see cref="IssuerTokenResolver"/> and 'base' are called in order.</remarks>
        protected override bool TryResolveSecurityKeyCore( SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key )
        {
            if ( keyIdentifierClause == null )
            {
                throw new ArgumentNullException( "keyIdentifierClause" );
            }

            key = null;
            NamedKeySecurityKeyIdentifierClause namedKeyIdentifierClause = keyIdentifierClause as NamedKeySecurityKeyIdentifierClause;
            if ( namedKeyIdentifierClause != null )
            {
                IList<SecurityKey> keys = null;
                if ( _keys.TryGetValue( namedKeyIdentifierClause.Name, out keys ) )
                {
                    key = keys[0];
                    return true;
                }
            }

            if ( IssuerTokenResolver != null && IssuerTokenResolver.TryResolveSecurityKey( keyIdentifierClause, out key ) )
            {
                return true;
            }

            return base.TryResolveSecurityKeyCore( keyIdentifierClause, out key );
        }

        /// <summary>
        /// Finds a named collection of <see cref="SecurityKey"/>(s) that match the <see cref="SecurityKeyIdentifier"/> and returns a <see cref="NamedKeySecurityToken"/> that contains the <see cref="SecurityKey"/>(s).
        /// </summary>
        /// <remarks><para>A <see cref="SecurityKeyIdentifier"/> can contain multiple <see cref="SecurityKeyIdentifierClause"/>(s). This method will return the named collection that matches the first <see cref="SecurityKeyIdentifierClause"/></para><para>If there is no match, then <see cref="IssuerTokenResolver"/> and 'base' are called in order.</para></remarks>
        protected override bool TryResolveTokenCore( SecurityKeyIdentifier keyIdentifier, out SecurityToken token )
        {
            if ( keyIdentifier == null )
            {
                throw new ArgumentNullException( "keyIdentifier" );
            }
            
            token = null;
            foreach ( SecurityKeyIdentifierClause clause in keyIdentifier )
            {
                if ( null == clause )
                {
                    continue;
                }

                NamedKeySecurityKeyIdentifierClause namedKeyIdentifierClause = clause as NamedKeySecurityKeyIdentifierClause;
                if ( namedKeyIdentifierClause != null )
                {
                    IList<SecurityKey> keys = null;
                    if ( _keys.TryGetValue( namedKeyIdentifierClause.Name, out keys ) )
                    {
                        token = new NamedKeySecurityToken( namedKeyIdentifierClause.Name, keys );
                        return true;
                    }
                }
            }

            if ( IssuerTokenResolver != null && IssuerTokenResolver.TryResolveToken( keyIdentifier, out token ) )
            {
                return true;
            }

            return base.TryResolveTokenCore( keyIdentifier, out token );
        }

        /// <summary>
        /// Finds a named collection of <see cref="SecurityKey"/>(s) that match the <see cref="SecurityKeyIdentifierClause"/> and returns a <see cref="NamedKeySecurityToken"/> that contains the <see cref="SecurityKey"/>(s).
        /// </summary>
        /// <remarks>If there is no match, then <see cref="IssuerTokenResolver"/> and 'base' are called in order.</remarks>
        protected override bool TryResolveTokenCore( SecurityKeyIdentifierClause keyIdentifierClause, out SecurityToken token )
        {
            if ( keyIdentifierClause == null )
            {
                throw new ArgumentNullException( "keyIdentifierClause" );
            }

            token = null;
            NamedKeySecurityKeyIdentifierClause namedKeyIdentifierClause = keyIdentifierClause as NamedKeySecurityKeyIdentifierClause;
            if ( namedKeyIdentifierClause != null )
            {
                IList<SecurityKey> keys = null;
                if ( _keys.TryGetValue( namedKeyIdentifierClause.Name, out keys ) )
                {
                    token = new NamedKeySecurityToken( namedKeyIdentifierClause.Name, keys );
                    return true;
                }
            }

            if ( IssuerTokenResolver != null && IssuerTokenResolver.TryResolveToken( keyIdentifierClause, out token ) )
            {
                return true;
            }

            return base.TryResolveTokenCore( keyIdentifierClause, out token );
        }
    }
}
