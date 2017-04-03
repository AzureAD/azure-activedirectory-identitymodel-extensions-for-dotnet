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
    public class SignedXml : ISignatureValueSecurityElement
    {
        internal const string DefaultPrefix = XmlSignatureConstants.Prefix;

        public SignedXml(SignedInfo signedInfo)
        {
            if (signedInfo == null)
                throw LogHelper.LogArgumentNullException(nameof(signedInfo));

            TransformFactory = TransformFactory.Instance;
            Signature = new Signature(this, signedInfo);
        }

        public bool HasId
        {
            get { return true; }
        }

        public string Id
        {
            get { return Signature.Id; }
            set { Signature.Id = value; }
        }

        public object TokenSource { get; set; }

        public Signature Signature { get; private set; }

        public TransformFactory TransformFactory { get; set; }

        public void ComputeSignature(SigningCredentials credentials)
        {
            // TODO - do not create hash algorithm here OR assume SHA256
            //var hash = credentials.CryptoProviderFactory.CreateHashAlgorithm(credentials.Algorithm);
            var hash = credentials.Key.CryptoProviderFactory.CreateHashAlgorithm(SecurityAlgorithms.Sha256);
            Signature.SignedInfo.ComputeReferenceDigests();
            Signature.SignedInfo.ComputeHash(hash);
            byte[] signature = hash.Hash;
            Signature.SetSignatureValue(signature);
        }

        public void CompleteSignatureVerification()
        {
            Signature.SignedInfo.EnsureAllReferencesVerified();
        }

        public void EnsureDigestValidity(string id, object resolvedXmlSource)
        {
            Signature.SignedInfo.EnsureDigestValidity(id, resolvedXmlSource);
        }

        public bool EnsureDigestValidityIfIdMatches(string id, object resolvedXmlSource)
        {
            return Signature.SignedInfo.EnsureDigestValidityIfIdMatches(id, resolvedXmlSource);
        }

        public byte[] GetSignatureValue()
        {
            return Signature.GetSignatureBytes();
        }

        public void ReadFrom(XmlReader reader)
        {
            ReadFrom(XmlDictionaryReader.CreateDictionaryReader(reader));
        }

        public void ReadFrom(XmlDictionaryReader reader)
        {
            Signature.ReadFrom(reader);
        }

        public void VerifySignature(SecurityKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            var signatureProvider = key.CryptoProviderFactory.CreateForVerifying(key, Signature.SignedInfo.SignatureMethod);
            var memoryStream = new MemoryStream();
            Signature.SignedInfo.GetCanonicalBytes(memoryStream);
            if (!signatureProvider.Verify(memoryStream.ToArray(), Signature.GetSignatureBytes()))
                throw LogHelper.LogExceptionMessage(new CryptographicException("Signature Failure"));
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            Signature.WriteTo(writer);
        }
    }
}