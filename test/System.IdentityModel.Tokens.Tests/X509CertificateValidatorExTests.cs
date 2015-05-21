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

using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace System.IdentityModel.Test
{
    public class X509CertificateValidatorExTests
    {
        [Fact(DisplayName = "X509CertificateValidatorExTests: Constructor")]
        public void Constructor()
        {
            X509CertificateValidatorEx validator = new X509CertificateValidatorEx(X509CertificateValidationMode.None, X509RevocationMode.NoCheck, StoreLocation.CurrentUser);
            validator = new X509CertificateValidatorEx(X509CertificateValidationMode.PeerTrust, X509RevocationMode.NoCheck, StoreLocation.CurrentUser);
            validator = new X509CertificateValidatorEx(X509CertificateValidationMode.ChainTrust, X509RevocationMode.NoCheck, StoreLocation.CurrentUser);
            validator = new X509CertificateValidatorEx(X509CertificateValidationMode.PeerOrChainTrust, X509RevocationMode.NoCheck, StoreLocation.CurrentUser);
        }

        [Fact(DisplayName = "X509CertificateValidatorExTests: Defaults")]
        public void Defaults()
        {
        }
    }
}
