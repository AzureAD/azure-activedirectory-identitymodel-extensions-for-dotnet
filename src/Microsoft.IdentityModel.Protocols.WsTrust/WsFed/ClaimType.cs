// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsFed
{
    /// <summary>
    /// This class is used to represent a ClaimType found in the WsFed specification: http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html .
    /// </summary>
    /// <remarks>Only 'Value' is read.</remarks>
    public class ClaimType
    {
        private string _uri;
        private string _value;

        /// <summary>
        /// Instantiates a <see cref="ClaimType"/> instance.
        /// </summary>
        public ClaimType() { }

        /// <summary>
        /// Gets ClaimType optional attribute.
        /// </summary>
        /// <remarks>This is an optional attribute.</remarks>
        public bool? IsOptional { get; set; }

        /// <summary>
        /// Gets ClaimType value element.
        /// </summary>
        /// <remarks>this is an optional value.</remarks>
        /// <exception cref="ArgumentNullException"> thrown if value is null.or empty.</exception>
        public string Value
        {
            get => _value;
            set => _value = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(Value)) : value;
        }

        /// <summary>
        /// Gets ClaimType uri attribute.
        /// </summary>
        /// <remarks>this is a required value.</remarks>
        /// <exception cref="ArgumentNullException"> thrown if value is null.or empty.</exception>
        public string Uri
        {
            get => _uri;
            set => _uri = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(Uri)) : value;
        }
    }
}
