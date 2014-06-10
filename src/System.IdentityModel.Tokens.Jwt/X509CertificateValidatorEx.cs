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
    using Microsoft.IdentityModel;
    using System.Diagnostics.CodeAnalysis;
    using System.Globalization;
    using System.IdentityModel.Selectors;
    using System.Security.Cryptography.X509Certificates;
    using System.ServiceModel.Security;

    /// <summary>
    /// This class also resets the chainPolicy.VerificationTime = DateTime.Now each time a certificate is validated otherwise certificates created after the validator is created will not chain.
    /// </summary>
    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Suppressed for private or internal fields.")]
    internal class X509CertificateValidatorEx : X509CertificateValidator
    {
        private X509CertificateValidationMode certificateValidationMode;
        private X509ChainPolicy chainPolicy;
        private X509CertificateValidator validator;

        /// <summary>
        /// Initializes a new instance of the <see cref="X509CertificateValidatorEx"/> class.
        /// </summary>
        /// <param name="certificateValidationMode">
        /// The certificate validation mode.
        /// </param>
        /// <param name="revocationMode">
        /// The revocation mode.
        /// </param>
        /// <param name="trustedStoreLocation">
        /// The trusted store location.
        /// </param>
        /// <exception cref="InvalidOperationException"> thrown if the certificationValidationMode is custom or unknown.
        /// </exception>
        [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Suppressed for private or internal fields.")]
        public X509CertificateValidatorEx(X509CertificateValidationMode certificateValidationMode, X509RevocationMode revocationMode, StoreLocation trustedStoreLocation)
        {
            this.certificateValidationMode = certificateValidationMode;
            switch (this.certificateValidationMode)
            {
                case X509CertificateValidationMode.None:
                    {
                        this.validator = X509CertificateValidator.None;
                        break;
                    }

                case X509CertificateValidationMode.PeerTrust:
                    {
                        this.validator = X509CertificateValidator.PeerTrust;
                        break;
                    }

                case X509CertificateValidationMode.ChainTrust:
                    {
                        bool useMachineContext = trustedStoreLocation == StoreLocation.LocalMachine;
                        this.chainPolicy = new X509ChainPolicy();
                        this.chainPolicy.RevocationMode = revocationMode;

                        this.validator = X509CertificateValidator.CreateChainTrustValidator(useMachineContext, this.chainPolicy);
                        break;
                    }

                case X509CertificateValidationMode.PeerOrChainTrust:
                    {
                        bool useMachineContext = trustedStoreLocation == StoreLocation.LocalMachine;
                        this.chainPolicy = new X509ChainPolicy();
                        this.chainPolicy.RevocationMode = revocationMode;

                        this.validator = X509CertificateValidator.CreatePeerOrChainTrustValidator(useMachineContext, this.chainPolicy);
                        break;
                    }

                default:
                    throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10637, this.certificateValidationMode));
            }
        }

        /// <summary>
        /// Validates a <see cref="X509Certificate2"/>.
        /// </summary>
        /// <param name="certificate">
        /// The <see cref="X509Certificate2"/> to validate.
        /// </param>
        public override void Validate(X509Certificate2 certificate)
        {
            if (this.certificateValidationMode == X509CertificateValidationMode.ChainTrust || this.certificateValidationMode == X509CertificateValidationMode.PeerOrChainTrust)
            {
                // This is needed otherwise certificates created after the creation of the validator to fail chain trust.
                this.chainPolicy.VerificationTime = DateTime.Now;
            }

            this.validator.Validate(certificate);
        }
    }
}
