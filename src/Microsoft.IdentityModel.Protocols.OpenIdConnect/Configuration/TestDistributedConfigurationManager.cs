using Microsoft.IdentityModel.Tokens;
using System.Threading;
using System.Threading.Tasks;
using System;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Protocols.Configuration;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Configuration
{
    // wrapper in S2S
    internal class TestDistributedConfigurationManager : IDistributedConfigurationManager<OpenIdConnectConfiguration>
    {
        readonly IDistributedCache _l2Cache;

        // encryption / compression / etc to be injected here

        public TestDistributedConfigurationManager(IDistributedCache cache)
        {
            _l2Cache = cache;
        }
        /// <inheritdoc/>
        public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(string metadataAddress, DistributedConfigurationOptions distributedConfigurationOptions, CancellationToken cancellationToken = default)
        {
            string cacheResultAsString = await _l2Cache.GetStringAsync(metadataAddress, cancellationToken).ConfigureAwait(false);
            var config = OpenIdConnectConfigurationSerializer.Read(cacheResultAsString);

            // validate config
            if (config.JsonWebKeySet == null)
                return null;
            else
            {
                foreach (JsonWebKey webKey in config.JsonWebKeySet.Keys)
                {
                    // Convert to RsaSecurityKey if possible as they contain the X509Data which is about 1k.
                    // Wilson will create an X509SecurityKey from X509Data, see: JsonWebKeySet.GetSigningKeys() in M.IM.Tokens.
                    // For an example see: AadV1JwksUriCommon in IdentityProviderHttpClient.cs
                    if (JsonWebKeyConverter.TryCreateToRsaSecurityKey(webKey, out SecurityKey securityKey))
                    {
                        if (webKey.Use.Equals(JsonWebKeyUseNames.Enc, StringComparison.OrdinalIgnoreCase))
                            config.TokenDecryptionKeys.Add(securityKey);
                        else
                            config.SigningKeys.Add(securityKey);
                    }
                    else
                    {
                        if (webKey.Use.Equals(JsonWebKeyUseNames.Enc, StringComparison.OrdinalIgnoreCase))
                            config.TokenDecryptionKeys.Add(webKey);
                        else
                            config.SigningKeys.Add(webKey);
                    }
                }
            }

            return config;
        }

        /// <inheritdoc/>
        public async Task SetConfigurationAsync(string metadataAddress, OpenIdConnectConfiguration configuration, DistributedConfigurationOptions distributedConfigurationOptions, CancellationToken cancellationToken = default)
        {
            if (configuration.JsonWebKeySet != null)
            {
                configuration.SerializeKeys = true;
                string serializedConfig = OpenIdConnectConfigurationSerializer.Write(configuration);
                await _l2Cache.SetStringAsync(metadataAddress, serializedConfig, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                // log + telemetry
            }
        }
    }
}
