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

using System;
using System.Diagnostics.Tracing;
using System.Globalization;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace System.IdentityModel.Tokens
{
    public class ECDsaSecurityKey : AsymmetricSecurityKey
    {
        private byte[] _blob;
        private CngKeyBlobFormat _blobFormat;
        private CngKey _cngKey;

        public ECDsaSecurityKey(byte[] blob, CngKeyBlobFormat blobFormat)
        {
            if (blob == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "ECDsaSecurityKey.blob"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (string.IsNullOrEmpty(blobFormat.Format))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "ECDsaSecurityKey.blobFormat.Format"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            _cngKey = CngKey.Import(blob, blobFormat);
            _blob = blob;
            _blobFormat = blobFormat;
        }

        public override bool HasPrivateKey
        {
            get
            {
                return (_blobFormat.Format == "ECCPRIVATEBLOB" || _blobFormat.Format == "PRIVATEBLOB");
            }
        }

        public override bool HasPublicKey
        {
            get
            {
                return (_blobFormat.Format == "ECCPUBLICBLOB" || _blobFormat.Format == "PUBLICBLOB");
            }
        }

        public override SignatureProvider GetSignatureProvider(string algorithm, bool verifyOnly)
        {
            if (verifyOnly)
                return SignatureProviderFactory.CreateForVerifying(this, algorithm);
            else
                return SignatureProviderFactory.CreateForSigning(this, algorithm);
        }

        public byte[] Blob
        {
            get
            {
                return _blob;
            }
        }

        public CngKeyBlobFormat BlobFormat
        {
            get
            {
                return _blobFormat;
            }
        }

        public CngKey CngKey
        {
            get
            {
                return _cngKey;
            }
        }

        public override int KeySize
        {
            get
            {
                return _cngKey.KeySize;
            }
        }
    }
}
