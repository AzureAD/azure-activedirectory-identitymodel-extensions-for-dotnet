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

using System.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Basic implementation of DataReference element used in XML encryption. This class cannot be inherited.
    /// </summary>
    /// <remarks> http://www.w3.org/TR/xmlenc-core/#sec-ReferenceList </remarks>
    public sealed class DataReference : EncryptedReference
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DataReference"/> class.
        /// </summary>
        public DataReference() : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DataReference"/> class using the specified Uniform Resource Identifier (URI).
        /// </summary>
        /// <param name="uri"></param>
        public DataReference(string uri) : base(uri)
        {
        }

        internal override void WriteXml(XmlWriter writer)
        {
            if (writer == null)
                throw LogArgumentNullException(nameof(writer));

            // nothing to write - return
            if (string.IsNullOrEmpty(Uri))
                return;

            writer.WriteStartElement(XmlEncryptionConstants.Prefix, XmlEncryptionConstants.Elements.DataReference, null);
            writer.WriteAttributeString(XmlEncryptionConstants.Attributes.Uri, Uri);
            writer.WriteEndElement();
        }
    }
}
