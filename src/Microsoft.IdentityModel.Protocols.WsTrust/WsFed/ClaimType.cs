//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using Microsoft.IdentityModel.Logging;

#pragma warning disable 1591

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
        public ClaimType() {}

        /// <summary>
        /// Gets ClaimType optional attribute.
        /// </summary>
        /// <remarks>This is an optional attribute.</remarks>
        public bool? IsOptional { get; set; }

        /// <summary>
        /// Gets ClaimType value element.
        /// </summary>
        /// <remarks>this is an optional value.</remarks>
        public string Value
        {
            get => _value;
            set => _value = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(Value)) : value;
        }

        /// <summary>
        /// Gets ClaimType uri attribute.
        /// </summary>
        /// <remarks>this is a required value.</remarks>
        public string Uri
        {
            get => _uri;
            set => _uri = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(Uri)) : value;
        }
    }
}
