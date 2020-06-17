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
using System.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents the <see cref="EncryptedKey"/> element in XML encryption. This class cannot be inherited.
    /// </summary>
    /// <remarks> http://www.w3.org/TR/xmlenc-core/#sec-EncryptedKey </remarks>
    public sealed class EncryptedKey : EncryptedType
    {
        private IList<EncryptedReference> _referenceList;

        /// <summary>
        /// Initializes an instance of <see cref="EncryptedKey"/>.
        /// </summary>
        public EncryptedKey()
        {
            Type = XmlEncryptionConstants.EncryptedDataTypes.EncryptedKey;
        }

        /// <summary>
        /// Gets the ReferenceList of <see cref="EncryptedReference"/> elements.
        /// </summary>
        public IList<EncryptedReference> ReferenceList
        {
            get
            {
                if (_referenceList == null)
                    _referenceList = new List<EncryptedReference>();
                return _referenceList;
            }
        }

        /// <summary>
        /// Adds new <see cref="EncryptedReference"/> to the ReferenceList of <see cref="EncryptedReference"/> elements.
        /// </summary>
        /// <param name="reference"></param>
        public void AddReference(EncryptedReference reference)
        {
            ReferenceList.Add(reference);
        }

        internal override void WriteXml(XmlWriter writer)
        {
            writer.WriteStartElement(XmlEncryptionConstants.Prefix, XmlEncryptionConstants.Elements.EncryptedKey, XmlEncryptionConstants.Namespace);

            base.WriteXml(writer);

            if (ReferenceList.Count != 0)
            {
                writer.WriteStartElement(XmlEncryptionConstants.Prefix, XmlEncryptionConstants.Elements.ReferenceList, null);

                foreach (var reference in ReferenceList)
                {
                    reference.WriteXml(writer);
                }

                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }

        internal override void ReadXml(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            if (reader.IsStartElement(XmlEncryptionConstants.Elements.EncryptedKey, XmlEncryptionConstants.Namespace))
            {
                // <EncryptedType> 1
                base.ReadXml(reader);

                // <ReferenceList>? 0 - 1
                if (reader.IsStartElement(XmlEncryptionConstants.Elements.ReferenceList, XmlEncryptionConstants.Namespace))
                {
                    reader.ReadStartElement(XmlEncryptionConstants.Elements.ReferenceList, XmlEncryptionConstants.Namespace);

                    while (reader.IsStartElement())
                    {
                        if (reader.IsStartElement(XmlEncryptionConstants.Elements.DataReference, XmlEncryptionConstants.Namespace))
                        {
                            var dataReferece = new DataReference();
                            dataReferece.ReadXml(reader);
                            ReferenceList.Add(dataReferece);
                        }
                        else if (reader.IsStartElement(XmlEncryptionConstants.Elements.KeyReference, XmlEncryptionConstants.Namespace))
                        {
                            var keyReferece = new KeyReference();
                            keyReferece.ReadXml(reader);
                            ReferenceList.Add(keyReferece);
                        }
                        else
                        {
                            LogInformation(LogMessages.IDX30303, reader.LocalName);
                            reader.Skip();
                        }
                    }
                }

                // <CarriedKeyName>? 0 - 1
                // Skip - not supported
                if (reader.IsStartElement(XmlEncryptionConstants.Elements.CarriedKeyName, XmlEncryptionConstants.Namespace))
                {
                    LogInformation(LogMessages.IDX30302, XmlEncryptionConstants.Elements.CarriedKeyName, XmlEncryptionConstants.Elements.EncryptedKey);
                    reader.Skip();
                }

                // should be on EndElement for the EncryptedKey
                reader.ReadEndElement();
            }
        }
    }
}
