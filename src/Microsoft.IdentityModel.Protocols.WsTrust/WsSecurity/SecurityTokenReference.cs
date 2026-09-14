// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Represents the contents of SecurityTokenReference element.
    /// This type is used to identity a reference to a specific SecurityToken.
    /// <para>see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf </para>
    /// </summary>
    public class SecurityTokenReference
    {
        private string _id;
        private string _tokenType;
        private string _usage;
        private KeyIdentifier _keyIdentifier;

        internal SecurityTokenReference()
        {
        }

        /// <summary>
        /// Instantiates a <see cref="SecurityTokenReference"/> specifying the <see cref="KeyIdentifier"/>.
        /// </summary>
        /// <param name="keyIdentifier">the value of this <see cref="KeyIdentifier"/>.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="keyIdentifier"/> is null.</exception>
        public SecurityTokenReference(KeyIdentifier keyIdentifier)
        {
            KeyIdentifier = keyIdentifier;
        }

        /// <summary>
        /// Gets or sets the Id.
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if value is null or empty.</exception>
        public string Id
        {
            get => _id;
            set => _id = !string.IsNullOrEmpty(value) ? value : throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the <see cref="KeyIdentifier"/>
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if value is null.</exception>
        public KeyIdentifier KeyIdentifier
        {
            get => _keyIdentifier;
            set => _keyIdentifier = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the TokenType.
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if value is null or empty.</exception>
        public string TokenType
        {
            get => _tokenType;
            set => _tokenType = !string.IsNullOrEmpty(value) ? value : throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the Usage.
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if value is null or empty.</exception>
        public string Usage
        {
            get => _usage;
            set => _usage = !string.IsNullOrEmpty(value) ? value : throw LogHelper.LogArgumentNullException(nameof(value));
        }
    }
}
