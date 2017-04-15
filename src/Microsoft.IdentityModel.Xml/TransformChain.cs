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

using System.Collections.Generic;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    public class TransformChain
    {
        private string _prefix = XmlSignatureConstants.Prefix;
        private List<Transform> _transforms = new List<Transform>();

        public TransformChain() { }

        public int TransformCount
        {
            get { return _transforms.Count; }
        }

        public Transform this[int index]
        {
            get { return _transforms[index]; }
        }

        public bool NeedsInclusiveContext
        {
            get
            {
                for (int i = 0; i < TransformCount; i++)
                {
                    if (this[i].NeedsInclusiveContext)
                        return true;
                }
                return false;
            }
        }

        public void Add(Transform transform)
        {
            _transforms.Add(transform);
        }

        public void ReadFrom(XmlDictionaryReader reader, bool preserveComments)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace, false);

            reader.MoveToStartElement(XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace);
            _prefix = reader.Prefix;
            reader.Read();

            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace, true);
            while (reader.IsStartElement(XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace))
            {
                string transformAlgorithmUri = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                var transform = CreateTransform(transformAlgorithmUri);
                transform.ReadFrom(reader, preserveComments);
                Add(transform);
            }

            // </ Transforms>
            reader.MoveToContent();
            reader.ReadEndElement();

            if (TransformCount == 0)
                throw XmlUtil.LogReadException(LogMessages.IDX21014);
        }

        public virtual Transform CreateTransform(string transform)
        {
            if (string.IsNullOrEmpty(transform))
                LogHelper.LogArgumentNullException(nameof(transform));

            if (transform == SecurityAlgorithms.ExclusiveC14n)
                return new ExclusiveCanonicalizationTransform();
            else if (transform == SecurityAlgorithms.ExclusiveC14nWithComments)
                return new ExclusiveCanonicalizationTransform(false, true);
            else if (transform == SecurityAlgorithms.EnvelopedSignature)
                return new EnvelopedSignatureTransform();

            throw LogHelper.LogExceptionMessage(new XmlException(LogHelper.FormatInvariant(LogMessages.IDX21018, transform)));
        }

        //public byte[] TransformToDigest(TokenStreamingReader data, SignatureResourcePool resourcePool, string digestMethod)
        //{
        //    for (int i = 0; i < TransformCount - 1; i++)
        //        data = this[i].Process(data, resourcePool);

        //    return this[TransformCount - 1].ProcessAndDigest(data, resourcePool, digestMethod);
        //}

        internal byte[] TransformToDigest(TokenStreamingReader tokenStream, SignatureResourcePool resourcePool, string digestMethod)
        {
            for (int i = 0; i < TransformCount - 1; i++)
                tokenStream = this[i].Process(tokenStream, resourcePool) as TokenStreamingReader;

            return this[TransformCount - 1].ProcessAndDigest(tokenStream, resourcePool, digestMethod);
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(_prefix, XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace);
            for (int i = 0; i < TransformCount; i++)
                this[i].WriteTo(writer);

            writer.WriteEndElement(); // Transforms
        }
    }
}