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

using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    public class ECDsaSecurityKey : AsymmetricSecurityKey
    {
        public ECDsaSecurityKey(byte[] blob, CngKeyBlobFormat blobFormat)
        {
            if (blob == null)
                throw LogHelper.LogArgumentNullException("blob");

            if (blobFormat == null)
                throw LogHelper.LogArgumentNullException("blobFormat");

            CngKey = CngKey.Import(blob, blobFormat);
            BlobFormat = blobFormat;
        }

        public override bool HasPrivateKey
        {
            get
            {
                return (BlobFormat.Format == CngKeyBlobFormat.EccPrivateBlob.Format || BlobFormat.Format == CngKeyBlobFormat.GenericPrivateBlob.Format);
            }
        }

        public override bool HasPublicKey
        {
            get
            {
                return (HasPrivateKey || BlobFormat.Format == CngKeyBlobFormat.EccPublicBlob.Format || BlobFormat.Format == CngKeyBlobFormat.GenericPublicBlob.Format);
            }
        }

        public override SignatureProvider GetSignatureProvider(string algorithm, bool verifyOnly)
        {
            if (verifyOnly)
                return SignatureProviderFactory.CreateForVerifying(this, algorithm);
            else
                return SignatureProviderFactory.CreateForSigning(this, algorithm);
        }

        /// <summary>
        /// <see cref="CngKeyBlobFormat"/> used to initialize the <see cref="CngKey"/>
        /// </summary>
        public CngKeyBlobFormat BlobFormat { get; private set; }

        /// <summary>
        /// <see cref="CngKey"/> that will be used for signing/verifying operations.
        /// </summary>
        public CngKey CngKey { get; private set; }

        public override int KeySize
        {
            get
            {
                return CngKey.KeySize;
            }
        }
    }
}
