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
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    public class Signature
    {
        private KeyInfo _keyInfo;
        private string _prefix = SignedXml.DefaultPrefix;
        readonly SignatureValueElement _signatureValueElement = new SignatureValueElement();

        public Signature(SignedXml signedXml, SignedInfo signedInfo)
        {
            if (signedXml == null)
                throw LogHelper.LogArgumentNullException(nameof(signedXml));

            if (signedInfo == null)
                throw LogHelper.LogArgumentNullException(nameof(signedInfo));

            SignedXml = signedXml;
            SignedInfo = signedInfo;
        }

        public SecurityKey Key { get; set; }

        public string Id { get; set; }

        public SignedInfo SignedInfo
        {
            get; private set;
        }

        public SignedXml SignedXml
        {
            get; private set;
        }

        public ISignatureValueSecurityElement SignatureValue
        {
            get { return _signatureValueElement; }
        }

        public byte[] GetSignatureBytes()
        {
            return _signatureValueElement.Signature;
        }

        public void ReadFrom(XmlDictionaryReader reader)
        {
            reader.MoveToStartElement(XmlSignatureStrings.Signature, XmlSignatureStrings.Namespace);
            _prefix = reader.Prefix;
            Id = reader.GetAttribute(UtilityStrings.Id, null);
            reader.Read();

            SignedInfo.ReadFrom(reader, SignedXml.TransformFactory);
            _signatureValueElement.ReadFrom(reader);
            _keyInfo = new KeyInfo();
            _keyInfo.ReadFrom(reader);

            reader.ReadEndElement(); // Signature
        }

        public void SetSignatureValue(byte[] signatureValue)
        {
            _signatureValueElement.Signature = signatureValue;
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(_prefix, XmlSignatureStrings.Signature, XmlSignatureStrings.Namespace);
            if (Id != null)
                writer.WriteAttributeString(UtilityStrings.Id, null, Id);

            SignedInfo.WriteTo(writer);
            _signatureValueElement.WriteTo(writer);

            writer.WriteEndElement(); // Signature
        }

        sealed class SignatureValueElement : ISignatureValueSecurityElement
        {
            string _prefix = SignedXml.DefaultPrefix;
            byte[] _signatureValue;
            string _signatureText;

            public bool HasId
            {
                get { return true; }
            }

            public string Id { get; set; }

            public byte[] Signature
            {
                get { return _signatureValue; }
                set
                {
                    _signatureValue = value;
                    _signatureText = null;
                }
            }

            public void ReadFrom(XmlDictionaryReader reader)
            {
                reader.MoveToStartElement(XmlSignatureStrings.SignatureValue, XmlSignatureStrings.Namespace);
                _prefix = reader.Prefix;
                Id = reader.GetAttribute(UtilityStrings.Id, null);
                reader.Read();

                _signatureText = reader.ReadString();
                _signatureValue = System.Convert.FromBase64String(_signatureText.Trim());

                reader.ReadEndElement(); // SignatureValue
            }

            public void WriteTo(XmlDictionaryWriter writer)
            {
                writer.WriteStartElement(_prefix, XmlSignatureStrings.SignatureValue, XmlSignatureStrings.Namespace);
                if (Id != null)
                    writer.WriteAttributeString(UtilityStrings.Id, null, Id);

                if (_signatureText != null)
                    writer.WriteString(_signatureText);
                else
                    writer.WriteBase64(_signatureValue, 0, _signatureValue.Length);

                writer.WriteEndElement(); // SignatureValue
            }

            byte[] ISignatureValueSecurityElement.GetSignatureValue()
            {
                return Signature;
            }
        }
    }
}