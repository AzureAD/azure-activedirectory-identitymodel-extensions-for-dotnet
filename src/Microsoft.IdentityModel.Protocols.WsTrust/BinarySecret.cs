// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of a BinarySecret element.
    /// A binary secret represents key material that will be serialized with a request.
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    public class BinarySecret
    {
        private byte[] _data;
        private string _encodingType;

        /// <summary>
        /// Creates an instance of <see cref="BinarySecret"/>.
        /// This constructor is useful when deserializing from xml.
        /// </summary>
        internal BinarySecret()
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="BinarySecret"/>.
        /// </summary>
        /// <param name="data">the bytes of the key material.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="data"/> is null.</exception>
        public BinarySecret(byte[] data)
        {
            Data = data;
        }

        /// <summary>
        /// Creates an instance of <see cref="BinarySecret"/>.
        /// </summary>
        /// <param name="data">the bytes of the key material.</param>
        /// <param name="encodingType">the encoding type to use when writing data.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="data"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="encodingType"/> is null or an empty string.</exception>
        public BinarySecret(byte[] data, string encodingType)
        {
            Data = data;
            EncodingType = encodingType;
        }

        /// <summary>
        /// Gets or sets the binary data.
        /// </summary>
        /// <exception cref="ArgumentNullException">if Data is null.</exception>
        public byte[] Data
        {
            get
            {
                byte[] binaryCopy = new byte[_data.Length];
                Array.Copy(_data, binaryCopy, _data.Length);
                return binaryCopy;
            }

            internal set
            {
                _data = value ?? throw LogHelper.LogArgumentNullException(nameof(Data));
            }
        }

        /// <summary>
        /// Gets or sets the encoding type.
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if value is null or empty.</exception>
        public string EncodingType
        {
            get => _encodingType;
            set => _encodingType = string.IsNullOrEmpty(value) ? throw LogHelper.LogArgumentNullException(nameof(EncodingType)) : value;
        }

        /// <summary>
        /// A collection of additional attributes.
        /// </summary>
        public ICollection<string> AdditionalAttributes { get; } = new Collection<string>();
    }
}
