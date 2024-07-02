// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Base class for a <see cref="SecurityKey"/> that contains Asymmetric key material.
    /// </summary>
    public abstract class AsymmetricSecurityKey : SecurityKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricSecurityKey"/> class.
        /// </summary>
        public AsymmetricSecurityKey()
        {
        }

        internal AsymmetricSecurityKey(SecurityKey key)
            : base(key)
        {
        }

        /// <summary>
        /// This must be overridden to get a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
        [System.Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus instead.")]
        public abstract bool HasPrivateKey { get; }

        /// <summary>
        /// Gets the status of the private key.
        /// </summary>
        /// <return><see cref="PrivateKeyStatus.Exists"/> if private key exists for sure; <see cref="PrivateKeyStatus.DoesNotExist"/> if private key doesn't exist for sure; <see cref="PrivateKeyStatus.Unknown"/> if we cannot determine.</return>
        public abstract PrivateKeyStatus PrivateKeyStatus { get; }
    }

    /// <summary>
    /// Enum for the existence of private key
    /// </summary>
    public enum PrivateKeyStatus
    {
        /// <summary>
        /// private key exists for sure
        /// </summary>
        Exists,

        /// <summary>
        /// private key doesn't exist for sure
        /// </summary>
        DoesNotExist,

        /// <summary>
        /// unable to determine the existence of private key
        /// </summary>
        Unknown
    };
}
