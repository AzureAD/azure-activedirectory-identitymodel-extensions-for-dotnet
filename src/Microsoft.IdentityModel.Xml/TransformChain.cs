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
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    public class TransformChain
    {
        string _prefix = SignedXml.DefaultPrefix;
        List<Transform> _transforms = new List<Transform>();

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

        public void ReadFrom(XmlDictionaryReader reader, TransformFactory transformFactory, bool preserveComments)
        {
            reader.MoveToStartElement(XmlSignatureStrings.Transforms, XmlSignatureStrings.Namespace);
            _prefix = reader.Prefix;
            reader.Read();

            while (reader.IsStartElement(XmlSignatureStrings.Transform, XmlSignatureStrings.Namespace))
            {
                string transformAlgorithmUri = reader.GetAttribute(XmlSignatureStrings.Algorithm, null);
                Transform transform = transformFactory.CreateTransform(transformAlgorithmUri);
                transform.ReadFrom(reader, preserveComments);
                Add(transform);
            }
            reader.MoveToContent();
            reader.ReadEndElement(); // Transforms
            if (TransformCount == 0)
                throw LogHelper.LogExceptionMessage(new CryptographicException("AtLeastOneTransformRequired"));
        }

        public byte[] TransformToDigest(object data, SignatureResourcePool resourcePool, string digestMethod)
        {
            for (int i = 0; i < TransformCount - 1; i++)
            {
                data = this[i].Process(data, resourcePool);
            }
            return this[TransformCount - 1].ProcessAndDigest(data, resourcePool, digestMethod);
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(_prefix, XmlSignatureStrings.Transforms, XmlSignatureStrings.Namespace);
            for (int i = 0; i < TransformCount; i++)
            {
                this[i].WriteTo(writer);
            }
            writer.WriteEndElement(); // Transforms
        }
    }
}