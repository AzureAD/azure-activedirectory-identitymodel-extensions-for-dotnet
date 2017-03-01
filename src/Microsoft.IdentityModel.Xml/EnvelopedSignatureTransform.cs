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
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    sealed class EnvelopedSignatureTransform : Transform
    {
        string prefix = XmlSignatureStrings.Prefix;

        public EnvelopedSignatureTransform() {}

        public override string Algorithm
        {
            get { return XmlSignatureStrings.EnvelopedSignature; }
        }

        public override object Process(object input, SignatureResourcePool resourcePool)
        {
            XmlTokenStream tokenStream = input as XmlTokenStream;
            if (tokenStream != null)
            {
                tokenStream.SetElementExclusion(XmlSignatureStrings.Signature, XmlSignatureStrings.Namespace);
                return tokenStream;
            }

            WrappedReader reader = input as WrappedReader;
            if ( reader != null )
            {
                // The Enveloped Signature Transform is supposed to remove the
                // Signature which encloses the transform element. Previous versions
                // of this code stripped out all Signature elements at any depth, 
                // which did not allow nested signed structures. By specifying '1' 
                // as the depth, we narrow our range of support so that we require
                // that the enveloped signature be a direct child of the element
                // being signed.
                reader.XmlTokens.SetElementExclusion(XmlSignatureStrings.Signature, XmlSignatureStrings.Namespace, 1 );
                return reader;
            }

            throw LogHelper.LogExceptionMessage(new NotSupportedException("UnsupportedInputTypeForTransform, input.GetType()"));
        }

        // this transform is not allowed as the last one in a chain
        public override byte[] ProcessAndDigest(object input, SignatureResourcePool resourcePool, string digestAlgorithm)
        {
            throw LogHelper.LogExceptionMessage(new NotSupportedException("UnsupportedLastTransform"));
        }

        public override void ReadFrom(XmlDictionaryReader reader, bool preserveComments)
        {
            reader.MoveToContent();
            string algorithm = XmlUtil.ReadEmptyElementAndRequiredAttribute(reader,
                XmlSignatureStrings.Transform, XmlSignatureStrings.Namespace, XmlSignatureStrings.Algorithm, out this.prefix);
            if (algorithm != this.Algorithm)
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("AlgorithmMismatchForTransform"));
            }
        }

        public override void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(this.prefix, XmlSignatureStrings.Transform, XmlSignatureStrings.Namespace);
            writer.WriteAttributeString(XmlSignatureStrings.Algorithm, null, Algorithm);
            writer.WriteEndElement();
        }
    }
}
