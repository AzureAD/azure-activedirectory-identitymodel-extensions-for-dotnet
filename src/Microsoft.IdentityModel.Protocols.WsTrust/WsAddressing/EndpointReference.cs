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

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsPolicy;

namespace Microsoft.IdentityModel.Protocols.WsAddressing
{
    /// <summary>
    /// Represents the contents of EndpointReference element.
    /// This type is used when creating a WsTrust request to specify the relying party for the token.
    ///<para>Composes with <see cref="AppliesTo"/>.</para>
    /// <para>see: https://www.w3.org/Submission/2004/SUBM-ws-addressing-20040810/ </para>
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public class EndpointReference
    {
        /// <summary>
        /// Instantiates a <see cref="EndpointReference"/> specifying the relying party.
        /// </summary>
        /// <param name="uri">the uri representing the relying party.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="uri"/> is null.</exception>
        /// <exception cref="ArgumentException">thrown if <paramref name="uri"/> is not a an absolute uri.</exception>
        public EndpointReference(string uri)
        {
            if (uri == null)
                throw LogHelper.LogArgumentNullException(nameof(uri));

            if (!System.Uri.IsWellFormedUriString(uri, UriKind.Absolute))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant($"uri is not absolute: {uri}")));

            Uri = uri;
        }

        /// <summary>
        /// Extensibility for adding additional elements.
        /// </summary>
        public ICollection<XmlElement> AdditionalXmlElements { get; } = new Collection<XmlElement>();

        /// <summary>
        /// Gets the uri passed to the constructor.
        /// </summary>
        public string Uri { get; }
    }
}
