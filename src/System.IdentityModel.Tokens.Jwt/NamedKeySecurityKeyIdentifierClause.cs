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
    using System.Diagnostics.CodeAnalysis;

    /// <summary>
    /// A <see cref="SecurityKeyIdentifierClause"/> that can be used to match <see cref="NamedKeySecurityToken"/>.
    /// </summary>
    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Suppressed for private or internal fields.")]
    public class NamedKeySecurityKeyIdentifierClause : SecurityKeyIdentifierClause
    {
        private const string NameKeySecurityKeyIdentifierClauseType = "NamedKeySecurityKeyIdentifierClause";
        private string name;

        /// <summary>
        /// Initializes a new instance of the <see cref="NamedKeySecurityKeyIdentifierClause"/> class. The 'name' for matching key identifiers found in the securityToken.
        /// </summary>
        /// <param name="name">Used to identify a named collection of keys.</param>
        /// <param name="id">Additional information for matching.</param>
        /// <exception cref="ArgumentNullException">if 'name' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">if 'id' is null or whitespace</exception>
        public NamedKeySecurityKeyIdentifierClause(string name, string id)
            : base(NameKeySecurityKeyIdentifierClauseType)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException("name");

            if (string.IsNullOrWhiteSpace(id))
                throw new ArgumentNullException("id");

            this.name = name;
            this.Id = id;
        }

        /// <summary>
        /// Gets the name of the <see cref="SecurityKey"/>(s) this <see cref="NamedKeySecurityKeyIdentifierClause"/> represents.
        /// </summary>
        public string Name
        {
            get { return this.name; }
        }

        /// <summary>
        /// Determines if a <see cref="SecurityKeyIdentifierClause"/> matches this instance.
        /// </summary>
        /// <param name="keyIdentifierClause">The <see cref="SecurityKeyIdentifierClause"/> to match.</param>
        /// <returns>true if:
        /// <para>&#160;&#160;&#160;&#160;1. keyIdentifierClause is a <see cref="NamedKeySecurityKeyIdentifierClause"/>.</para>
        /// <para>&#160;&#160;&#160;&#160;2. string.Equals( keyIdentifierClause.Name, this.Name, StringComparison.Ordinal).</para>
        /// <para>&#160;&#160;&#160;&#160;2. string.Equals( keyIdentifierClause.Id, this.Id, StringComparison.Ordinal).</para>
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
                if (string.Equals(namedKeyIdentifierClause.Name, this.Name, StringComparison.Ordinal)
                && string.Equals(namedKeyIdentifierClause.Id, this.Id, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return base.Matches(keyIdentifierClause);
        }
    }
}