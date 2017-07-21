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
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tests
{
    public static class XmlUtilities
    {
        public static XmlDictionaryReader CreateDictionaryReader(string xml)
        {
            if (string.IsNullOrEmpty(xml))
                return null;

            return XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(new StringReader(xml)));
        }

        public static EnvelopedSignatureReader CreateEnvelopedSignatureReader(string xml)
        {
            return new EnvelopedSignatureReader(XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(new StringReader(xml))));
        }

        public static XmlTokenStream CreateXmlTokenStream(string xml)
        {
            var envelopedSignatureReader = CreateEnvelopedSignatureReader(xml);
            while (envelopedSignatureReader.Read());
            return envelopedSignatureReader.TokenStream;
        }

        public static byte[] CreateDigestBytes(string xml, bool includeComments)
        {
            using (var stream = new MemoryStream())
            {
                ExclusiveCanonicalizationTransform.WriteCanonicalStream(stream, CreateXmlTokenStream(xml), includeComments);
                stream.Flush();
                stream.Position = 0;
                return Default.HashAlgorithm.ComputeHash(stream);
            }
        }

        public static byte[] GenerateSignatureBytes(SignedInfo signedInfo, SecurityKey key)
        {
            using (var stream = new MemoryStream())
            {
                var serailizer = new DSigSerializer();
                var writer = XmlDictionaryWriter.CreateTextWriter(Stream.Null);
                var includeComments = signedInfo.CanonicalizationMethod == SecurityAlgorithms.ExclusiveC14nWithComments;
                writer.StartCanonicalization(stream, includeComments, null);
                serailizer.WriteSignedInfo(writer, signedInfo);
                writer.EndCanonicalization();
                writer.Flush();
                stream.Position = 0;
                var provider = key.CryptoProviderFactory.CreateForSigning(key, signedInfo.SignatureMethod);
                return provider.Sign(stream.ToArray());
            }
        }
    }
}
