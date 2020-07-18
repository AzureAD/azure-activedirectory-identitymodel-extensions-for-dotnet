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
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Utilities for working with WS-* 
    /// </summary>
    internal static class WsUtils
    {
        /// <summary>
        /// Checks standard items on a write call.
        /// </summary>
        internal static void ValidateParamsForWritting(XmlWriter writer, WsSerializationContext serializationContext, object obj, string objName)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (serializationContext == null)
                throw LogHelper.LogArgumentNullException(nameof(serializationContext));

            if (obj == null)
                throw LogHelper.LogArgumentNullException(objName);
        }

        /// <summary>
        /// Checks if the <see cref="XmlReader"/> is pointing to an expected element.
        /// </summary>
        /// <param name="reader">the <see cref="XmlReader"/>to check.</param>
        /// <param name="element">the expected element.</param>
        /// <param name="serializationContext">the expected namespace.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="element"/> is null or empty.</exception>
        /// <exception cref="XmlReadException">if <paramref name="reader"/> if not at a StartElement.</exception>
        /// <exception cref="XmlReadException">if <paramref name="reader"/> if not at expected element.</exception>
        internal static void CheckReaderOnEntry(XmlReader reader, string element, WsSerializationContext serializationContext)
        {
            if (serializationContext == null)
                throw LogHelper.LogArgumentNullException(nameof(serializationContext));

            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // IsStartElement calls reader.MoveToContent().
            if (!reader.IsStartElement())
                throw XmlUtil.LogReadException(LogMessages.IDX30022, reader.NodeType);

            if (!reader.IsStartElement(element, serializationContext.TrustConstants.Namespace))
                throw XmlUtil.LogReadException(LogMessages.IDX30011, serializationContext.TrustConstants.Namespace, element, reader.NamespaceURI, reader.LocalName);
        }
    }
}
