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
    /// Represents the abstract base class used in XML encryption from which the <see cref="KeyReference"/> and <see cref="DataReference"/> classes derive. 
    /// </summary>
    /// <remarks> http://www.w3.org/TR/xmlenc-core1/#sec-ReferenceList </remarks>
    public abstract class EncryptedReference
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptedReference"/> class.
        /// </summary>
        protected EncryptedReference()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptedReference"/> class using the specified Uniform Resource Identifier(URI).
        /// </summary>
        /// <param name="uri"></param>
        protected EncryptedReference(string uri)
        {
            Uri = uri;
        }

        /// <summary>
        /// Gets or sets the Uniform Resource Identifier(URI) of an <see cref= "EncryptedReference" /> object.
        /// </summary>
        public string Uri { get; set; }

        abstract internal void WriteXml(XmlWriter writer);

        internal virtual void ReadXml(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            if (reader.IsStartElement(XmlEncryptionConstants.Elements.KeyReference, XmlEncryptionConstants.Namespace) || reader.IsStartElement(XmlEncryptionConstants.Elements.DataReference, XmlEncryptionConstants.Namespace))
            {
                Uri = reader.GetAttribute(XmlEncryptionConstants.Attributes.Uri, null);
                reader.Skip();
            }
        }
    }
}
