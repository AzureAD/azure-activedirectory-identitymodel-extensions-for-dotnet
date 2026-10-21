// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// This class are used in defining Entropy and RequestProofToken element inside the 
    /// RequestSecurityToken and RequestSecurityTokenResponse.
    /// </summary>
    public class ProtectedKey
    {
        /// <summary>
        /// Use this constructor if we want to send the key material encrypted.
        /// </summary>
        /// <param name="secret">The key material that needs to be protected.</param>
        /// <param name="wrappingCredentials">The encrypting credentials used to encrypt the key material.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="secret"/> is null.</exception>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="wrappingCredentials"/> is null.</exception>
        public ProtectedKey(byte[] secret, EncryptingCredentials wrappingCredentials)
        {
            Secret = secret ?? throw LogHelper.LogArgumentNullException(nameof(secret));
            WrappingCredentials = wrappingCredentials ?? throw LogHelper.LogArgumentNullException(nameof(wrappingCredentials));
        }

        /// <summary>
        /// Gets the secret passed to the constructor.
        /// </summary>
        public byte[] Secret { get; }

        /// <summary>
        /// Gets the encrypting credentials passed to the constructor.
        /// </summary>
        public EncryptingCredentials WrappingCredentials { get; }
    }
}
