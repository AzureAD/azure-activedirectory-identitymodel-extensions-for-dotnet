// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// This type is used when creating a WsTrust request to specify entropy used to create a security key used to secure the request.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public class Entropy
    {
        /// <summary>
        /// 
        /// </summary>
        internal Entropy()
        {
        }

        /// <summary>
        /// Instantiates an <see cref="Entropy"/> with a <see cref="BinarySecret"/>.
        /// </summary>
        /// <param name="binarySecret">the entropy to use on the WsTrust request.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="binarySecret"/> is null.</exception>
        public Entropy(BinarySecret binarySecret)
        {
            BinarySecret = binarySecret;
        }

        /// <summary>
        /// Gets the <see cref="BinarySecret"/> passed to the constructor.
        /// </summary>
        public BinarySecret BinarySecret { get; internal set; }

        /// <summary>
        /// Constructs an entropy instance with the protected key.
        /// </summary>
        /// <param name="protectedKey">The protected key which can be either binary secret or encrypted key.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="protectedKey"/> is null.</exception>
        public Entropy(ProtectedKey protectedKey)
        {
            ProtectedKey = protectedKey ?? throw LogHelper.LogArgumentNullException(nameof(protectedKey));
        }

        /// <summary>
        /// Get the <see cref="ProtectedKey"/> passed to the constructor.
        /// </summary>
        public ProtectedKey ProtectedKey { get; }

        static byte[] GetKeyBytesFromProtectedKey(ProtectedKey protectedKey)
        {
            if (protectedKey == null)
                throw LogHelper.LogArgumentNullException(nameof(protectedKey));

            return protectedKey.Secret;
        }

        static EncryptingCredentials GetWrappingCredentialsFromProtectedKey(ProtectedKey protectedKey)
        {
            if (protectedKey == null)
                throw LogHelper.LogArgumentNullException(nameof(protectedKey));

            return protectedKey.WrappingCredentials;
        }
    }
}
