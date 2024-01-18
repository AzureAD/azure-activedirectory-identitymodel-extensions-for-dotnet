// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.KeyVaultExtensions
{
    /// <summary>
    /// Provides signing and verifying operations using Azure Key Vault.
    /// </summary>
    public class KeyVaultSecurityKey : SecurityKey
    {
        private int? _keySize;
        private string? _keyId;

        /// <summary>
        /// The authentication callback delegate which is to be implemented by the client code.
        /// </summary>
        /// <param name="authority">Identifier of the authority, a URL.</param>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token, a URL.</param>
        /// <param name="scope">The scope of the authentication request.</param>
        /// <returns>An access token for Azure Key Vault.</returns>
        public delegate Task<string> AuthenticationCallback(string authority, string resource, string scope);

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecurityKey"/> class.
        /// </summary>
        protected KeyVaultSecurityKey()
        {

        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecurityKey"/> class.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier that is recognized by KeyVault.</param>
        /// <param name="callback">The authentication callback that will obtain the access_token for KeyVault.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="keyIdentifier"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="callback"/>is null.</exception>
        public KeyVaultSecurityKey(string keyIdentifier, AuthenticationCallback callback)
        {
            Callback = callback ?? throw LogHelper.LogArgumentNullException(nameof(callback));
            KeyId = keyIdentifier;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecurityKey"/> class.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier that is recognized by KeyVault.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="keyIdentifier"/> is null or empty.</exception>
        public KeyVaultSecurityKey(string keyIdentifier)
            : this(keyIdentifier, new DefaultAzureCredential())
        {
            KeyId = keyIdentifier;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecurityKey"/> class.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier that is recognized by KeyVault.</param>
        /// <param name="credential">The token credential that will obtain the access_token for KeyVault.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="keyIdentifier"/> is null or empty.</exception>
        /// /// <exception cref="ArgumentNullException">if <paramref name="credential"/>is null.</exception>
#pragma warning disable CS3001 // Argument type is not CLS-compliant
        public KeyVaultSecurityKey(string keyIdentifier, TokenCredential credential)
#pragma warning restore CS3001 // Argument type is not CLS-compliant
        {
            TokenCredential = credential ?? throw LogHelper.LogArgumentNullException(nameof(credential));
            KeyId = keyIdentifier;
        }

        internal KeyVaultSecurityKey(string keyIdentifier, int keySize)
        {
            _keyId = keyIdentifier;
            _keySize = keySize;
        }

        /// <summary>
        /// The authentication callback delegate that retrieves an access token for the KeyVault.
        /// </summary>
        public AuthenticationCallback? Callback { get; protected set; }

        /// <summary>
        /// The token credential that retrieves an access token for the KeyVault.
        /// </summary>
#pragma warning disable CS3003 // Type is not CLS-compliant
        public TokenCredential? TokenCredential { get; set; }
#pragma warning restore CS3003 // Type is not CLS-compliant

        /// <summary>
        /// The uniform resource identifier of the security key.
        /// </summary>
        public override string KeyId
        {
            get => _keyId!;
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));
                else if (StringComparer.Ordinal.Equals(_keyId, value))
                    return;

                _keyId = value;

                // Reset the properties so they can be retrieved from Azure KeyVault the next time they are accessed.
                _keySize = null;
            }
        }

        /// <summary>
        /// The size of the security key.
        /// </summary>
        public override int KeySize
        {
            get
            {
                if (!_keySize.HasValue)
                    _ = InitializeAsync();

                return _keySize!.Value;
            }
        }

        /// <summary>
        /// Retrieve the properties from Azure Key Vault.
        /// </summary>
        private async Task InitializeAsync()
        {
            var client = new KeyClient(new Uri(_keyId ?? ""), new DefaultAzureCredential());

            await foreach (KeyProperties item in client.GetPropertiesOfKeysAsync(CancellationToken.None))
            {
                KeyVaultKey key = client.GetKeyAsync(item.Name).ConfigureAwait(false).GetAwaiter().GetResult();
                _keySize = new BitArray(key.Key.N).Length;

            }
        }
    }
}
