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

using System.IO;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    public class Signature
    {
        private string _prefix = XmlSignatureConstants.Prefix;
        private byte[] _signature;
        readonly SignatureValueElement _signatureValueElement = new SignatureValueElement();

        public Signature(SignedInfo signedInfo)
        {
            if (signedInfo == null)
                throw LogHelper.LogArgumentNullException(nameof(signedInfo));

            SignedInfo = signedInfo;
        }

        public string Id { get; set; }

        public KeyInfo KeyInfo { get; protected set; }

        public SignedInfo SignedInfo
        {
            get; private set;
        }

        public void ComputeSignature(SigningCredentials credentials)
        {
            var hash = credentials.Key.CryptoProviderFactory.CreateHashAlgorithm(credentials.Digest);
            SignedInfo.ComputeReferenceDigests();
            SignedInfo.ComputeHash(hash);
            _signatureValueElement.Signature = hash.Hash;
            _signature = _signatureValueElement.Signature;
        }

        public byte[] GetSignatureBytes()
        {
            return _signatureValueElement.Signature;
        }

        public void ReadFrom(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Namespace);

            reader.MoveToStartElement(XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Namespace);
            _prefix = reader.Prefix;
            Id = reader.GetAttribute(UtilityStrings.Id, null);
            reader.Read();

            SignedInfo.ReadFrom(reader, TransformFactory);
            _signatureValueElement.ReadFrom(reader);
            KeyInfo = new KeyInfo();
            KeyInfo.ReadFrom(reader);

            reader.ReadEndElement(); // Signature
        }

        public TokenStreamingReader TokenSource { get; set; }

        public TransformFactory TransformFactory { get; set; } = TransformFactory.Instance;

        public void Verify(SecurityKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            var signatureProvider = key.CryptoProviderFactory.CreateForVerifying(key, SignedInfo.SignatureAlgorithm);
            var memoryStream = new MemoryStream();
            SignedInfo.GetCanonicalBytes(memoryStream);
            if (!signatureProvider.Verify(memoryStream.ToArray(), GetSignatureBytes()))
                throw LogHelper.LogExceptionMessage(new CryptographicException(LogMessages.IDX21200));

            var reference = SignedInfo[0];
            if (!reference.Verify(key.CryptoProviderFactory, TokenSource))
                throw LogHelper.LogExceptionMessage(new CryptographicException(LogHelper.FormatInvariant(LogMessages.IDX21201, reference.Uri)));
        }


        public void WriteTo(XmlDictionaryWriter writer)
        {
            if (writer == null)
                LogHelper.LogArgumentNullException(nameof(writer));

            // <Signature>
            writer.WriteStartElement(_prefix, XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Namespace);
            if (Id != null)
                writer.WriteAttributeString(UtilityStrings.Id, null, Id);

            SignedInfo.WriteTo(writer);
            _signatureValueElement.WriteTo(writer);

            // <SignatureValue>
            writer.WriteStartElement(_prefix, XmlSignatureConstants.Elements.SignatureValue, XmlSignatureConstants.Namespace);

            // TODO - need different id for SignatureValue
            // @Id
            //if (Id != null)
            //    writer.WriteAttributeString(UtilityStrings.Id, null, Id);

            writer.WriteBase64(_signature, 0, _signature.Length);

             // </ SignatureValue >
            writer.WriteEndElement();

            // </ Signature>
            writer.WriteEndElement(); // Signature
        }

        internal sealed class SignatureValueElement : ISignatureValueSecurityElement
        {
            string _prefix = XmlSignatureConstants.Prefix;
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
                reader.MoveToStartElement(XmlSignatureConstants.Elements.SignatureValue, XmlSignatureConstants.Namespace);
                _prefix = reader.Prefix;
                Id = reader.GetAttribute(UtilityStrings.Id, null);
                reader.Read();

                _signatureText = reader.ReadString();
                _signatureValue = System.Convert.FromBase64String(_signatureText.Trim());

                // </SignatureValue>
                reader.ReadEndElement(); 
            }


            public void WriteTo(XmlDictionaryWriter writer)
            {
                writer.WriteStartElement(_prefix, XmlSignatureConstants.Elements.SignatureValue, XmlSignatureConstants.Namespace);
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