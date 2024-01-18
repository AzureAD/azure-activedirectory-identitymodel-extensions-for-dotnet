// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Text;
using Azure.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.KeyVaultExtensions.Tests
{
    public class KeyVaultSecurityKeyE2ETests
    {
        [Fact]
        public void KeyVaultExtensionsE2ETests()
        {
            TestUtilities.WriteHeader($"{this}.KeyVaultExtensionsE2ETests");
            var context = new CompareContext($"{this}.KeyVaultExtensionsE2ETests");

            string keyIdentifier = "https://mykeyvault.vault.azure.net/keys/mykey/01234567890123456789012345678901";
            var key = new KeyVaultSecurityKey(keyIdentifier, new DefaultAzureCredential());

            // Create a KeyVaultSignatureProvider with the key, the algorithm, and the flag
            var provider = new KeyVaultSignatureProvider(key, SecurityAlgorithms.RsaSha256, true);

            // Sign some data using the provider
            var data = Encoding.UTF8.GetBytes("Hello, world!");
            var signature = provider.Sign(data);

            // Verify the signature using the provider
            var result = provider.Verify(data, signature);

            Assert.True(result, "Cannot verify the signatureis over the input of Azure Key Vault." );
            
            TestUtilities.AssertFailIfErrors(context);
        }
    }
}
