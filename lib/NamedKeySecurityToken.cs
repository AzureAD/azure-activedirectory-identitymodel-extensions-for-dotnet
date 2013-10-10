//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// A <see cref="SecurityToken"/> that contains multiple <see cref="SecurityKey"/> that have a name.
    /// </summary>
    public class NamedKeySecurityToken : SecurityToken
    {
        private string _name;
        private DateTime _validFrom;
        private List<SecurityKey> _securityKeys;
        
        /// <summary>
        /// A <see cref="SecurityToken"/> that contains a <see cref="IEnumerable{SecurityKey}"/>(System.IdentityModel.Tokens.SecurityKey) that can be matched by name.
        /// </summary>
        /// <param name="name">A name for the <see cref="IEnumerable{SecurityKey}"/>(System.IdentityModel.Tokens.SecurityKey).</param>
        /// <param name="keys">A collection of <see cref="SecurityKey"/></param>
        /// <exception cref="ArgumentNullException">'name' is null.</exception>
        /// <exception cref="ArgumentNullException">'keys' is null.</exception>
        /// <exception cref="ArgumentException">string.IsNullOrWhiteSpace( 'name' ) is true.</exception>
        public NamedKeySecurityToken( string name, IEnumerable<SecurityKey> keys )
        {
            if ( null == name )
            {
                throw new ArgumentNullException( name );
            }

            if ( keys == null )
            {
                throw new ArgumentNullException( "keys" );
            }

            if ( string.IsNullOrWhiteSpace( name ) )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, WifExtensionsErrors.WIF10000, name ) );
            }

            _securityKeys = new List<SecurityKey>( keys );
            _name = name;
            _validFrom = DateTime.UtcNow;
        }

        /// <summary>
        /// Gets the id
        /// </summary>
        /// <remarks>The default this is the 'name' passed to <see cref="NamedKeySecurityToken( string, IEnumerable{SecurityKey} )"/></remarks>
        public override string Id
        {
            get { return _name; }
        }

        /// <summary>
        /// Gets the creation time as a <see cref="DateTime"/>.
        /// </summary>
        /// <remarks>The default is: <see cref="DateTime.UtcNow"/> set in <see cref="NamedKeySecurityToken( string, IEnumerable{SecurityKey} )"/>.</remarks>
        public override DateTime ValidFrom
        {
            get { return _validFrom; }
        }

        /// <summary>
        /// Gets the expiration time as a <see cref="DateTime"/>
        /// </summary>
        /// <remarks>The default is: <see cref="DateTime.MaxValue"/>.</remarks>
        public override DateTime ValidTo
        {
            // Never expire
            get { return DateTime.MaxValue; }
        }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/>(s).
        /// </summary>
        public override ReadOnlyCollection<SecurityKey> SecurityKeys
        {
            get { return _securityKeys.AsReadOnly(); }
        }

        /// <summary>
        /// Gets the first<see cref="SecurityKey"/> that matches a <see cref="SecurityKeyIdentifierClause"/>
        /// </summary>
        /// <param name="keyIdentifierClause">the <see cref="SecurityKeyIdentifierClause"/> to match.</param>
        /// <returns>The first <see cref="SecurityKey"/> that matches the <see cref="SecurityKeyIdentifierClause"/>.
        /// <para>null if there is no match.</para></returns>
        /// <para>Only <see cref="NamedKeySecurityKeyIdentifierClause"/> are matched.</para>
        /// <exception cref="ArgumentNullException">'keyIdentifierClause' is null.</exception>
        public override SecurityKey ResolveKeyIdentifierClause( SecurityKeyIdentifierClause keyIdentifierClause )
        {
            if ( keyIdentifierClause == null )
            {
                throw new ArgumentNullException( "keyIdentifierClause" );
            }

            // if name matches, return first non null
            NamedKeySecurityKeyIdentifierClause namedKeyIdentifierClause = keyIdentifierClause as NamedKeySecurityKeyIdentifierClause;
            if ( namedKeyIdentifierClause != null )
            {
                if ( string.Equals( namedKeyIdentifierClause.Name, _name, StringComparison.Ordinal ) )
                {
                    foreach ( SecurityKey securityKey in _securityKeys )
                    {
                        if ( securityKey == null )
                        {
                            continue;
                        }

                        return securityKey;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Answers if the <see cref="SecurityKeyIdentifierClause"/> is a match.
        /// </summary>
        /// <param name="keyIdentifierClause">The <see cref="SecurityKeyIdentifierClause"/></param>
        /// <returns>true if matched.</returns>
        /// <remarks><para>A successful match occurs when <see cref="NamedKeySecurityKeyIdentifierClause.Name"/> == <see cref="Id"/>.</para>
        /// <para>Only <see cref="NamedKeySecurityKeyIdentifierClause"/> are matched.</para></remarks>
        /// <exception cref="ArgumentNullException">'keyIdentifierClause' is null.</exception>
        public override bool MatchesKeyIdentifierClause( SecurityKeyIdentifierClause keyIdentifierClause )
        {
            if ( keyIdentifierClause == null )
            {
                throw new ArgumentNullException( "keyIdentifierClause" );
            }

            NamedKeySecurityKeyIdentifierClause namedKeyIdentifierClause = keyIdentifierClause as NamedKeySecurityKeyIdentifierClause;
            if ( namedKeyIdentifierClause != null )
            {
                if ( string.Equals( namedKeyIdentifierClause.Name, _name, StringComparison.Ordinal ) )
                {
                    return true;
                }
            }
            return false;
        }
    }
}