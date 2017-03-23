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

namespace Microsoft.IdentityModel.Xml
{
    public class CipherDataElement
    {
        byte[] _iv;
        byte[] _cipherText;

        public byte[] CipherValue
        {
            get
            {
                if (_iv != null)
                {
                    byte[] buffer = new byte[_iv.Length + _cipherText.Length];
                    Buffer.BlockCopy(_iv, 0, buffer, 0, _iv.Length);
                    Buffer.BlockCopy(_cipherText, 0, buffer, _iv.Length, _cipherText.Length);
                    _iv = null;
                }

                return _cipherText;
            }
            set
            {
                _cipherText = value;
            }
        }

        public void ReadXml(XmlDictionaryReader reader)
        {
            if (reader == null)
                LogHelper.LogArgumentNullException(nameof(reader));

            reader.MoveToContent();
            if (!reader.IsStartElement(XmlEncryptionStrings.CipherData, XmlEncryptionStrings.Namespace))
                throw LogHelper.LogExceptionMessage(new XmlEncryptionException($"Expection start element {XmlEncryptionStrings.CipherData}"));

            reader.ReadStartElement(XmlEncryptionStrings.CipherData, XmlEncryptionStrings.Namespace);
            reader.ReadStartElement(XmlEncryptionStrings.CipherValue, XmlEncryptionStrings.Namespace);

            _cipherText = reader.ReadContentAsBase64();
            _iv         = null;

            // <CipherValue>
            reader.MoveToContent();
            reader.ReadEndElement();


            // <CipherData>
            reader.MoveToContent();
            reader.ReadEndElement();
        }

        public void SetCipherValueFragments(byte[] iv, byte[] cipherText)
        {
            _iv         = iv;
            _cipherText = cipherText;
        }

        public void WriteXml(XmlWriter writer)
        {
            writer.WriteStartElement(XmlEncryptionStrings.Prefix, XmlEncryptionStrings.CipherData, XmlEncryptionStrings.Namespace);
            writer.WriteStartElement(XmlEncryptionStrings.Prefix, XmlEncryptionStrings.CipherValue, XmlEncryptionStrings.Namespace);

            if (_iv != null)
                writer.WriteBase64(_iv, 0, _iv.Length);

            writer.WriteBase64(_cipherText, 0, _cipherText.Length);

            writer.WriteEndElement(); // CipherValue
            writer.WriteEndElement(); // CipherData
        }
    }
}
