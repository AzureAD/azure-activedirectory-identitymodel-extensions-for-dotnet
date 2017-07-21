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
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// </summary>
    public class TransformFactory
    {
        /// <summary>
        /// Static constructor that initializes the default <see cref="TransformFactory"/>.
        /// </summary>
        static TransformFactory()
        {
            Default = new TransformFactory();
        }

        /// <summary>
        /// Gets the default instance of <see cref="TransformFactory"/>
        /// </summary>
        public static TransformFactory Default
        {
            get;
        }

        /// <summary>
        /// Gets a XML transform.
        /// </summary>
        /// <param name="transform">the name of the transform.</param>
        /// <returns><see cref="Transform"/></returns>
        public virtual Transform GetTransform(string transform)
        {
            if (transform == SecurityAlgorithms.EnvelopedSignature)
                return new EnvelopedSignatureTransform();

            throw LogExceptionMessage(new NotSupportedException($"transform not supported: '{transform}'."));
        }

        /// <summary>
        /// Gets a XML that is capable of Canonicalizing XML and returning the bytes.
        /// </summary>
        /// <param name="transform">the name of the transform.</param>
        /// <returns><see cref="CanonicalizingTransfrom"/></returns>
        public virtual CanonicalizingTransfrom GetCanonicalizingTransform(string transform)
        {
            if (transform == SecurityAlgorithms.ExclusiveC14nWithComments)
                return new ExclusiveCanonicalizationTransform(true);

            if (transform == SecurityAlgorithms.ExclusiveC14n)
                return new ExclusiveCanonicalizationTransform(false);

            throw LogExceptionMessage(new NotSupportedException($"transform not supported: '{transform}'."));
        }
    }
}
