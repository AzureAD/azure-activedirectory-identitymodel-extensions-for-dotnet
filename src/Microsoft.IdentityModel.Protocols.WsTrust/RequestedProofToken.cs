// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.XmlEnc;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of a Participants element.
    /// <see cref="RequestedProofToken"/> is to represent the proof-of-possession artifact associated with a security token.
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    public class RequestedProofToken
    {
        private BinarySecret _binarySecret;
        private string _computedKeyAlgorithm;
        private EncryptedKey _encryptedKey;

        /// <summary>
        /// Creates an instance of <see cref="RequestedProofToken"/>.
        /// This constructor is useful when deserializing from a stream such as xml.
        /// <see cref="RequestedProofToken"/> is to represent the proof-of-possession artifact associated with a security token.
        /// </summary>
        internal RequestedProofToken()
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="RequestedProofToken"/>.
        /// <see cref="RequestedProofToken"/> is to represent the proof-of-possession artifact associated with a security token.
        /// </summary>
        ///<param name="binarySecret"> a <see cref="BinarySecret"/> that can be used when creating a <see cref= "SecurityKey" /> for cryptographic operations.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="binarySecret"/> is null.</exception>
        public RequestedProofToken(BinarySecret binarySecret)
        {
            BinarySecret = binarySecret;
        }

        /// <summary>
        /// Creates an instance of <see cref="RequestedProofToken"/>.
        /// <see cref="RequestedProofToken"/> is to represent the proof-of-possession artifact associated with a security token.
        /// </summary>
        /// <param name="computedKeyAlgorithm">the algorithm to apply when creating the security key.
        /// a typical value is: http://docs.oasis-open.org/ws-sx/ws-trust/200512/CK/PSHA1 </param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="computedKeyAlgorithm"/> is null or empty string.</exception>
        internal RequestedProofToken(string computedKeyAlgorithm)
        {
            ComputedKeyAlgorithm = computedKeyAlgorithm;
        }

        /// <summary>
        /// Creates an instance of <see cref="RequestedProofToken"/>.
        /// <see cref="RequestedProofToken"/> is to represent the proof-of-possession artifact associated with a security token.
        /// </summary>
        ///<param name="encryptedKey"> an <see cref="EncryptedKey"/> that can be used when creating a <see cref= "SecurityKey" /> for cryptographic operations.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="encryptedKey"/> is null.</exception>
        public RequestedProofToken(EncryptedKey encryptedKey)
        {
            EncryptedKey = encryptedKey ?? throw LogHelper.LogArgumentNullException(nameof(encryptedKey));
        }

        /// <summary>
        /// Gets or sets the <see cref="BinarySecret"/> to use when creating a <see cref="SecurityKey"/> for cryptographic operations.
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if BinarySecret is null.</exception>
        public BinarySecret BinarySecret
        {
            get => _binarySecret;
            set => _binarySecret = value ?? throw LogHelper.LogArgumentNullException(nameof(BinarySecret));
        }

        /// <summary>
        /// Gets or set the computed key algorithm to use when creating a <see cref="SecurityKey"/> for cryptographic operations.
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if ComputedKeyAlgorithm is null or empty.</exception>
        public string ComputedKeyAlgorithm
        {
            get => _computedKeyAlgorithm;
            set => _computedKeyAlgorithm = string.IsNullOrEmpty(value) ? throw LogHelper.LogArgumentNullException(nameof(ComputedKeyAlgorithm)) : value;
        }

        /// <summary>
        /// Gets or sets the <see cref="EncryptedKey"/> to use when creating a <see cref="SecurityKey"/> for cryptographic operations.
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if EncryptedKey is null.(</exception>
        public EncryptedKey EncryptedKey
        {
            get => _encryptedKey;
            set => _encryptedKey = value ?? throw LogHelper.LogArgumentNullException(nameof(EncryptedKey));
        }
    }
}
