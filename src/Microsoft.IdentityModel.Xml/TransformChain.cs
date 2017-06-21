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
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    public class TransformChain
    {
        private string _prefix = XmlSignatureConstants.Prefix;

        public TransformChain()
        {
            Transforms = new List<Transform>();
        }

        public TransformChain(IEnumerable<Transform> transforms)
        {
            if (transforms == null)
                LogArgumentNullException(nameof(transforms));

            Transforms = new List<Transform>(transforms);
        }

        public int Count
        {
            get { return Transforms.Count; }
        }

        public IList<Transform> Transforms { get; }

        public Transform this[int index]
        {
            get { return Transforms[index]; }
        }

        public bool NeedsInclusiveContext
        {
            get
            {
                for (int i = 0; i < Count; i++)
                    if (this[i].NeedsInclusiveContext)
                        return true;

                return false;
            }
        }

        public virtual void ReadFrom(XmlDictionaryReader reader, bool preserveComments)
        {
            // <Transforms>
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace);
            reader.MoveToStartElement(XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace);
            _prefix = reader.Prefix;
            reader.Read();

            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace);
            while (reader.IsStartElement(XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace))
            {
                string transformAlgorithmUri = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                var transform = CreateTransform(transformAlgorithmUri);
                transform.ReadFrom(reader, preserveComments);
                Transforms.Add(transform);
            }

            // </ Transforms>
            reader.MoveToContent();
            reader.ReadEndElement();

            if (Count == 0)
                throw XmlUtil.LogReadException(LogMessages.IDX21014);
        }

        internal Transform CreateTransform(string transform)
        {
            if (string.IsNullOrEmpty(transform))
                LogArgumentNullException(nameof(transform));

            if (transform == SecurityAlgorithms.ExclusiveC14n)
                return new ExclusiveCanonicalizationTransform();
            else if (transform == SecurityAlgorithms.ExclusiveC14nWithComments)
                return new ExclusiveCanonicalizationTransform(false, true);
            else if (transform == SecurityAlgorithms.EnvelopedSignature)
                return new EnvelopedSignatureTransform();

            throw LogExceptionMessage(new XmlException(FormatInvariant(LogMessages.IDX21018, transform)));
        }

        internal byte[] TransformToDigest(XmlTokenStreamReader tokenStreamReader, HashAlgorithm hash)
        {
            for (int i = 0; i < Count - 1; i++)
                tokenStreamReader = this[i].Process(tokenStreamReader) as XmlTokenStreamReader;

            return this[Count - 1].ProcessAndDigest(tokenStreamReader, hash);
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            if (writer == null)
                LogArgumentNullException(nameof(writer));

            writer.WriteStartElement(_prefix, XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace);
            for (int i = 0; i < Count; i++)
                this[i].WriteTo(writer);

            writer.WriteEndElement();
        }
    }
}