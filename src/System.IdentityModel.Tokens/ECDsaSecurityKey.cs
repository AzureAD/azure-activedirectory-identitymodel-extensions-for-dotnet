//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System.Diagnostics.Tracing;
using System.Globalization;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace System.IdentityModel.Tokens
{
    public class ECDsaSecurityKey : AsymmetricSecurityKey
    {
        public ECDsaSecurityKey(byte[] blob, CngKeyBlobFormat blobFormat)
        {
            if (blob == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "ECDsaSecurityKey.blob"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (blobFormat == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "ECDsaSecurityKey.blobFormat"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

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
