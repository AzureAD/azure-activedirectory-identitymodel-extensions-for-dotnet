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
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    internal class StrTransform : Transform
    {
        private string _inclusiveNamespacesPrefixList;
        private string[] _inclusivePrefixes;
        private string _prefix = XmlSignatureConstants.Prefix;
        private TranformationParameters _transformationParameters = new TranformationParameters();

        public StrTransform()
        {
            Algorithm = SecurityAlgorithms.StrTransform;
        }

        public bool IncludeComments { get; } = false;

        public string InclusiveNamespacesPrefixList
        {
            get { return _inclusiveNamespacesPrefixList; }
            set
            {
                _inclusiveNamespacesPrefixList = value;
                _inclusivePrefixes = TokenizeInclusivePrefixList(value);
            }
        }

        public override bool NeedsInclusiveContext
        {
            get { return GetInclusivePrefixes() != null; }
        }

        public string[] GetInclusivePrefixes()
        {
            return _inclusivePrefixes;
        }

        internal override object Process(TokenStreamingReader reader, SignatureResourcePool resourcePool)
        {
            if (reader == null)
                LogHelper.LogArgumentNullException(nameof(reader));

            var driver = resourcePool.TakeCanonicalizationDriver(reader, IncludeComments, _inclusivePrefixes);
            return driver.GetMemoryStream();
        }

        public override byte[] ProcessAndDigest(TokenStreamingReader reader, SignatureResourcePool resourcePool, string digestAlgorithm)
        {
            HashAlgorithm hash = resourcePool.TakeHashAlgorithm(digestAlgorithm);
            ProcessAndDigest(reader, resourcePool, hash);
            return hash.Hash;
        }

        public void ProcessAndDigest(TokenStreamingReader reader, SignatureResourcePool resourcePool, HashAlgorithm hash)
        {
            if (reader == null)
                LogHelper.LogArgumentNullException(nameof(reader));

            var hashStream = resourcePool.TakeHashStream(hash);
            var driver = resourcePool.TakeCanonicalizationDriver(reader, IncludeComments, _inclusivePrefixes);
            driver.WriteTo(hashStream);

            hashStream.FlushHash();
        }

        public override void ReadFrom(XmlDictionaryReader reader, bool preserveComments)
        {
            reader.MoveToStartElement(XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace);
            _prefix = reader.Prefix;
            bool isEmptyElement = reader.IsEmptyElement;
            string algorithm = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
            if (algorithm != Algorithm)
                throw LogHelper.LogExceptionMessage(new NotSupportedException("AlgorithmMismatchForTransform"));

            reader.MoveToContent();
            reader.Read();

            if (!isEmptyElement)
            {
                if (reader.IsStartElement(XmlSignatureConstants.Elements.TransformationParameters, XmlSignatureConstants.SecurityJan2004Namespace))
                    _transformationParameters.ReadFrom(reader);

                reader.MoveToContent();
                reader.ReadEndElement();
            }
        }

        public override void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(_prefix, XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace);
            writer.WriteStartAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
            writer.WriteString(Algorithm);
            writer.WriteEndAttribute();
            _transformationParameters.WriteTo(writer);
            writer.WriteEndElement();
        }

        static string[] TokenizeInclusivePrefixList(string prefixList)
        {
            if (prefixList == null)
                return null;

            string[] prefixes = prefixList.Split(null);
            int count = 0;
            for (int i = 0; i < prefixes.Length; i++)
            {
                string prefix = prefixes[i];
                if (prefix == "#default")
                {
                    prefixes[count++] = string.Empty;
                }
                else if (prefix.Length > 0)
                {
                    prefixes[count++] = prefix;
                }
            }
            if (count == 0)
            {
                return null;
            }
            else if (count == prefixes.Length)
            {
                return prefixes;
            }
            else
            {
                string[] result = new string[count];
                Array.Copy(prefixes, result, count);
                return result;
            }
        }
    }

    class TranformationParameters
    {
        public TranformationParameters() { }

        public string CanonicalizationAlgorithm
        {
            get { return XmlSignatureConstants.ExclusiveC14n; }
        }

        public void ReadFrom(XmlDictionaryReader reader)
        {
            reader.MoveToContent();
            reader.MoveToStartElement(XmlSignatureConstants.Elements.TransformationParameters, XmlSignatureConstants.SecurityJan2004Namespace);
            string prefix = reader.Prefix;

            bool skipReadingTransformEnd = reader.IsEmptyElement;
            reader.ReadStartElement();

            if (reader.IsStartElement(XmlSignatureConstants.Elements.CanonicalizationMethod, XmlSignatureConstants.Namespace))
            {

                string algorithm = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                // Canonicalization Method can be empty.
                // <elementNOTempty></elementNOTempty>
                // <elementEmpty/>
                bool skipReadingC14End = reader.IsEmptyElement;

                reader.ReadStartElement();

                if (algorithm == null)
                    throw LogHelper.LogExceptionMessage(new CryptographicException("dictionaryManager.XmlSignatureDictionary.CanonicalizationMethod"));

                if (algorithm != CanonicalizationAlgorithm)
                    throw LogHelper.LogExceptionMessage(new CryptographicException("AlgorithmMismatchForTransform"));


                // ReadEndElement() called only if element was not empty
                if (!skipReadingC14End)
                {
                    reader.MoveToContent();
                    reader.ReadEndElement();
                }
            }

            // If it was empty, don't read endElement as it was read in ReadStartElement
            if (!skipReadingTransformEnd)
            {
                reader.MoveToContent();
                reader.ReadEndElement();
            }
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(XmlSignatureConstants.SecurityJan2004Prefix, XmlSignatureConstants.Elements.TransformationParameters, XmlSignatureConstants.SecurityJan2004Namespace);  //<wsse:TransformationParameters>
            writer.WriteStartElement(XmlSignatureConstants.Prefix, XmlSignatureConstants.Elements.CanonicalizationMethod, XmlSignatureConstants.Namespace);
            writer.WriteStartAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
            writer.WriteString(XmlSignatureConstants.ExclusiveC14n);
            writer.WriteEndAttribute();
            writer.WriteEndElement(); // CanonicalizationMethod 
            writer.WriteEndElement(); // TransformationParameters
        }
    }
}
