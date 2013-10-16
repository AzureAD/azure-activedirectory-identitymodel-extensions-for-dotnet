// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using System.Globalization;
using System.IdentityModel.Selectors;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// This class also resets the _chainPolicy.VerificationTime = DateTime.Now each time a certificate is validated otherwise certificates created after the validator is created will not chain.
    /// </summary>
    internal class X509CertificateValidatorEx : X509CertificateValidator
    {
        internal X509CertificateValidationMode _certificateValidationMode;
        internal X509ChainPolicy _chainPolicy;
        internal X509CertificateValidator _validator;

        public X509CertificateValidatorEx(X509CertificateValidationMode certificateValidationMode, X509RevocationMode revocationMode, StoreLocation trustedStoreLocation)
        {
            _certificateValidationMode = certificateValidationMode;
            switch (_certificateValidationMode)
            {
                case X509CertificateValidationMode.None:
                    {
                        _validator = X509CertificateValidator.None;
                        break;
                    }

                case X509CertificateValidationMode.PeerTrust:
                    {
                        _validator = X509CertificateValidator.PeerTrust;
                        break;
                    }

                case X509CertificateValidationMode.ChainTrust:
                    {
                        bool useMachineContext = trustedStoreLocation == StoreLocation.LocalMachine;
                        _chainPolicy = new X509ChainPolicy();
                        _chainPolicy.RevocationMode = revocationMode;

                        _validator = X509CertificateValidator.CreateChainTrustValidator(useMachineContext, _chainPolicy);
                        break;
                    }

                case X509CertificateValidationMode.PeerOrChainTrust:
                    {
                        bool useMachineContext = trustedStoreLocation == StoreLocation.LocalMachine;
                        _chainPolicy = new X509ChainPolicy();
                        _chainPolicy.RevocationMode = revocationMode;

                        _validator = X509CertificateValidator.CreatePeerOrChainTrustValidator(useMachineContext, _chainPolicy);
                        break;
                    }

                case X509CertificateValidationMode.Custom:
                default:
                    throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10614, _certificateValidationMode));
            }
        }

        public override void Validate(X509Certificate2 certificate)
        {
            if (_certificateValidationMode == X509CertificateValidationMode.ChainTrust || _certificateValidationMode == X509CertificateValidationMode.PeerOrChainTrust)
            {
                // This is needed otherwise certificates created after the creation of the validator to fail chain trust.
                _chainPolicy.VerificationTime = DateTime.Now;
            }

            _validator.Validate(certificate);
        }
    }
}
