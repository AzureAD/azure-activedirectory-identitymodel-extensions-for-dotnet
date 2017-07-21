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

using System;
using System.Xml;
using static Microsoft.IdentityModel.Xml.XmlEncryptionConstants;

namespace Microsoft.IdentityModel.Xml
{
    internal class CipherDataElement
    {
        private byte[] _cipherText;
        private byte[] _iv;

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
            XmlUtil.CheckReaderOnEntry(reader, Elements.CipherData, Namespace);
            reader.ReadStartElement(Elements.CipherData, Namespace);
            reader.ReadStartElement(Elements.CipherValue, Namespace);

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
            // TODO - allow null?
            _iv         = iv;
            _cipherText = cipherText;
        }

        public void WriteXml(XmlWriter writer)
        {
            writer.WriteStartElement(Prefix, Elements.CipherData, Namespace);
            writer.WriteStartElement(Prefix, Elements.CipherValue, Namespace);

            if (_iv != null)
                writer.WriteBase64(_iv, 0, _iv.Length);

            writer.WriteBase64(_cipherText, 0, _cipherText.Length);

            // </CipherValue>
            writer.WriteEndElement();

            // </CipherData>
            writer.WriteEndElement();
        }
    }
}

#endif