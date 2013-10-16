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

namespace System.IdentityModel.Tokens
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Globalization;

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
        public NamedKeySecurityToken(string name, IEnumerable<SecurityKey> keys)
        {
            if (null == name)
            {
                throw new ArgumentNullException("name");
            }

            if (keys == null)
            {
                throw new ArgumentNullException("keys");
            }

            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, WifExtensionsErrors.WIF10000, name));
            }

            this._securityKeys = new List<SecurityKey>(keys);
            this._name = name;
            this._validFrom = DateTime.UtcNow;
        }

        /// <summary>
        /// Gets the id
        /// </summary>
        /// <remarks>The default this is the 'name' passed to <see cref="NamedKeySecurityToken( string, IEnumerable{SecurityKey} )"/></remarks>
        public override string Id
        {
            get { return this._name; }
        }

        /// <summary>
        /// Gets the creation time as a <see cref="DateTime"/>.
        /// </summary>
        /// <remarks>The default is: <see cref="DateTime.UtcNow"/> set in <see cref="NamedKeySecurityToken( string, IEnumerable{SecurityKey} )"/>.</remarks>
        public override DateTime ValidFrom
        {
            get { return this._validFrom; }
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
            get { return this._securityKeys.AsReadOnly(); }
        }

        /// <summary>
        /// Gets the first<see cref="SecurityKey"/> that matches a <see cref="SecurityKeyIdentifierClause"/>
        /// </summary>
        /// <param name="keyIdentifierClause">the <see cref="SecurityKeyIdentifierClause"/> to match.</param>
        /// <returns>The first <see cref="SecurityKey"/> that matches the <see cref="SecurityKeyIdentifierClause"/>.
        /// <para>null if there is no match.</para></returns>
        /// <para>Only <see cref="NamedKeySecurityKeyIdentifierClause"/> are matched.</para>
        /// <exception cref="ArgumentNullException">'keyIdentifierClause' is null.</exception>
        public override SecurityKey ResolveKeyIdentifierClause(SecurityKeyIdentifierClause keyIdentifierClause)
        {
            if (keyIdentifierClause == null)
            {
                throw new ArgumentNullException("keyIdentifierClause");
            }

            // if name matches, return first non null
            NamedKeySecurityKeyIdentifierClause namedKeyIdentifierClause = keyIdentifierClause as NamedKeySecurityKeyIdentifierClause;
            if (namedKeyIdentifierClause != null)
            {
                if (string.Equals(namedKeyIdentifierClause.Name, this._name, StringComparison.Ordinal))
                {
                    foreach (SecurityKey securityKey in this._securityKeys)
                    {
                        if (securityKey == null)
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
        public override bool MatchesKeyIdentifierClause(SecurityKeyIdentifierClause keyIdentifierClause)
        {
            if (keyIdentifierClause == null)
            {
                throw new ArgumentNullException("keyIdentifierClause");
            }

            NamedKeySecurityKeyIdentifierClause namedKeyIdentifierClause = keyIdentifierClause as NamedKeySecurityKeyIdentifierClause;
            if (namedKeyIdentifierClause != null)
            {
                if (string.Equals(namedKeyIdentifierClause.Name, this._name, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }
}