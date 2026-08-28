// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Represents the contents of KeyIdentifier element.
    /// This type is used with WsTrust requests when specifying a SecurityTokenReference.
    /// <para>Composes with <see cref="SecurityTokenReference"/>.</para>
    /// <para>see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf </para>
    /// </summary>
    public class KeyIdentifier
    {
        private string _encodingType;
        private string _id;
        private string _valueType;

        /// <summary>
        /// Instantiates an empty <see cref="KeyIdentifier"/>.
        /// </summary>
        internal KeyIdentifier()
        { }

        /// <summary>
        /// Instantiates a <see cref="KeyIdentifier"/> specifying the value.
        /// </summary>
        /// <param name="value">the value of this <see cref="KeyIdentifier"/>.</param>
        /// <exception cref="ArgumentNullException">thrown if value is null or empty string.</exception>
        public KeyIdentifier(string value)
        {
            Value = (!string.IsNullOrEmpty(value)) ? value : throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the EncodingType
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if value is null or empty.</exception>
        public string EncodingType
        {
            get => _encodingType;
            set => _encodingType = !string.IsNullOrEmpty(value) ? value : throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the EncodingType
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if value is null or empty.</exception>
        public string Id
        {
            get => _id;
            set => _id = !string.IsNullOrEmpty(value) ? value : throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets the value passed in the constructor.
        /// </summary>
        public string Value { get; internal set; }

        /// <summary>
        /// Gets or sets the ValueType
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if value is null or empty.</exception>
        public string ValueType
        {
            get => _valueType;
            set => _valueType = !string.IsNullOrEmpty(value) ? value : throw LogHelper.LogArgumentNullException(nameof(value));
        }
    }
}
