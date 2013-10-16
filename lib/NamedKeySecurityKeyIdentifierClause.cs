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
    using System.Globalization;

    /// <summary>
    /// A <see cref="SecurityKeyIdentifierClause"/> that can be used to match <see cref="NamedKeySecurityToken"/>.
    /// </summary>
    public class NamedKeySecurityKeyIdentifierClause : SecurityKeyIdentifierClause
    {
        private const string NameKeySecurityKeyIdentifierClauseType = "NamedKeySecurityKeyIdentifierClause";
        private string _keyIdentifier;
        private string _name;

        /// <summary>
        /// A <see cref="NamedKeySecurityToken"> will use the 'name' for matching.</see>
        /// </summary>
        /// <param name="name">Used to identify a named collection of keys.</param>
        /// <param name="keyIdentifier">Additional information for matching.</param>
        /// <exception cref="ArgumentNullException">'name' is null.</exception>
        /// <exception cref="ArgumentNullException">'keyIdentifier' is null.</exception>
        /// <exception cref="ArgumentException">string.IsNullOrWhiteSpace( 'name' ) is true.</exception>
        /// <exception cref="ArgumentException">string.IsNullOrWhiteSpace( 'keyIdentifier' ) is true.</exception>
        public NamedKeySecurityKeyIdentifierClause(string name, string keyIdentifier)
            : base(NameKeySecurityKeyIdentifierClauseType)
        {
            if (name == null)
            {
                throw new ArgumentNullException("name");
            }

            if (keyIdentifier == null)
            {
                throw new ArgumentNullException("keyIdentifier");
            }

            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, WifExtensionsErrors.WIF10000, name));
            }

            if (string.IsNullOrWhiteSpace(keyIdentifier))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, WifExtensionsErrors.WIF10000, keyIdentifier));
            }

            this._name = name;
            this._keyIdentifier = keyIdentifier;
        }

        /// <summary>
        /// Gets the name of the <see cref="SecurityKey"/>(s) this <see cref="NamedKeySecurityKeyIdentifierClause"/> represents.
        /// </summary>
        public string Name
        {
            get { return this._name; }
        }

        /// <summary>
        /// Gets the keyidentifier can be used for additional matching.
        /// </summary>
        public string KeyIdentifier
        {
            get { return this._keyIdentifier; }
        }

        /// <summary>
        /// Determines if a <see cref="SecurityKeyIdentifierClause"/> matches this instance.
        /// </summary>
        /// <param name="keyIdentifierClause">The <see cref="SecurityKeyIdentifierClause"/> to match.</param>
        /// <returns>true if:
        /// <para>&#160;&#160;&#160;&#160;1. keyIdentifierClause is a <see cref="NamedKeySecurityKeyIdentifierClause"/>.</para>
        /// <para>&#160;&#160;&#160;&#160;2. string.Equals( keyIdentifierClause.Name, this.Name, StringComparison.Ordinal).</para>
        /// <para>&#160;&#160;&#160;&#160;2. string.Equals( keyIdentifierClause.KeyIdentifier, this.KeyIdentifier, StringComparison.Ordinal).</para>
        /// <para>Otherwise calls base.Matches( keyIdentifierClause ).</para>
        /// </returns>
        /// <exception cref="ArgumentNullException">'keyIdentifierClause' is null.</exception>
        public override bool Matches(SecurityKeyIdentifierClause keyIdentifierClause)
        {
            if (keyIdentifierClause == null)
            {
                throw new ArgumentNullException("keyIdentifierClause");
            }

            NamedKeySecurityKeyIdentifierClause namedKeyIdentifierClause = keyIdentifierClause as NamedKeySecurityKeyIdentifierClause;
            if (namedKeyIdentifierClause != null)
            {
                if (string.Equals(namedKeyIdentifierClause.Name, Name, StringComparison.Ordinal)
                && string.Equals(namedKeyIdentifierClause.KeyIdentifier, this.KeyIdentifier, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return base.Matches(keyIdentifierClause);
        }
    }
}