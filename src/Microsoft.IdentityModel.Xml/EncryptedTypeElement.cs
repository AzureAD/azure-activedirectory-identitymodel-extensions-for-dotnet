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

#if EncryptedTokens

using System.Collections.Generic;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{

    /// <summary>
    /// This class implements a deserialization for: EncryptedType as defined in section 3.1 of http://www.w3.org/TR/2002/REC-xmlenc-core-2002120
    /// </summary>
    internal abstract class EncryptedTypeElement
    {
        private CipherDataElement _cipherData;
        private EncryptionMethodElement _encryptionMethod;
        private string _encoding;
        private string _id;
        private string _mimeType;
        private List<string> _properties;
        private string _type;

        public EncryptedTypeElement()
        {
            _cipherData = new CipherDataElement();
            _encryptionMethod = new EncryptionMethodElement();
            _properties = new List<string>();
            Algorithm = EncryptionMethod.Algorithm;
        }

        public string Algorithm
        {
            get { return (EncryptionMethod != null) ? EncryptionMethod.Algorithm : null; }
            set
            {
                if (value == null)
                    LogArgumentNullException(nameof(value));

                EncryptionMethod.Algorithm = value;
            }
        }

        public string Id
        {
            get { return _id; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    LogArgumentNullException(nameof(value));

                _id = value;
            }
        }

        public EncryptionMethodElement EncryptionMethod
        {
            get { return _encryptionMethod; }
            set
            {
                if (value == null)
                    LogArgumentNullException(nameof(value));

                _encryptionMethod = value;
            }
        }

        public CipherDataElement CipherData
        {
            get { return _cipherData; }
            set
            {
                if (value == null)
                    LogArgumentNullException(nameof(value));

                _cipherData = value;
            }
        }

        // TODO - use KeyInfo class
        public SecurityKey SecurityKey { get; set; }
        //public SecurityKeyIdentifier KeyIdentifier
        //{
        //    get { return _keyInfo.KeyIdentifier; }
        //    set
        //    {
        //        if (value == null)
        //            LogArgumentNullException(nameof(value));

        //        _keyInfo.KeyIdentifier = value;
        //    }
        //}

        public abstract void ReadExtensions(XmlDictionaryReader reader);

        //public SecurityTokenSerializer TokenSerializer
        //{
        //    get { return _keyInfoSerializer; }
        //}

        public string Type
        {
            get { return _type; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    LogArgumentNullException(nameof(value));

                _type = value;
            }
        }

        /// <summary>
        /// Reads an "EncryptedType" xmlfragment
        /// </summary>
        /// <remarks>Assumes that the reader is positioned on an "EncryptedData" or "EncryptedKey" element.
        /// Both of these elements extend EncryptedType</remarks>
        public virtual void ReadXml(XmlDictionaryReader reader)
        {
            if (reader == null)
                LogArgumentNullException(nameof(reader));

            reader.MoveToContent();

            _id = reader.GetAttribute(XmlEncryptionConstants.Attributes.Id, null);
            _type = reader.GetAttribute(XmlEncryptionConstants.Attributes.Type, null);
            _mimeType = reader.GetAttribute(XmlEncryptionConstants.Attributes.MimeType, null);
            _encoding = reader.GetAttribute(XmlEncryptionConstants.Attributes.Encoding, null);

            reader.ReadStartElement();
            reader.MoveToContent();

            // <EncryptedMethod>? 0 - 1
            if (reader.IsStartElement(XmlEncryptionConstants.Elements.EncryptionMethod, XmlEncryptionConstants.Namespace))
            {
                _encryptionMethod.ReadXml(reader);
            }

            // <KeyInfo>? 0 - 1
            reader.MoveToContent();
            if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace))
            {
                // TODO - key reader?
                //_keyInfo = new KeyInfo(_keyInfoSerializer);
                reader.Skip();

                // if there is a keyInfo, we need to reset the default which is 
                // contains a single EmptyKeyInfoClause
                //if (_keyInfoSerializer.CanReadKeyIdentifier(reader))
                //{
                //    _keyInfo.KeyIdentifier = _keyInfoSerializer.ReadKeyIdentifier(reader);
                //}
                //else
                //{
                //    _keyInfo.ReadXml(reader);
                //}
            }

            // <CipherData> 1
            reader.MoveToContent();
            _cipherData.ReadXml(reader);

            ReadExtensions(reader);

            // should be on EndElement for the extended type.
            reader.MoveToContent();
            reader.ReadEndElement();
        }
    }
}
#endif