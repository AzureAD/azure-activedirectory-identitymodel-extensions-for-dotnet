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

namespace System.IdentityModel.Tokens
{
    public abstract class SecurityKey
    {
        private SignatureProviderFactory _signatureProviderFactory = SignatureProviderFactory.Default;

        public abstract int KeySize { get; }

        public string KeyId { get; set; }

        public abstract SignatureProvider GetSignatureProvider(string algorithm, bool verifyOnly);

        public SignatureProviderFactory SignatureProviderFactory
        {
            get
            {
                return _signatureProviderFactory;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                };

                _signatureProviderFactory = value;
            }
        }
    }
}