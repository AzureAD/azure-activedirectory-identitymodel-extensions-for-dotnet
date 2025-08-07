// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens.Json;

namespace Microsoft.IdentityModel.Tokens.PQC.Tests
{
    /// <summary>
    /// This class tests serializing JsonWebKeySets with MLDSA keys.
    /// </summary>
    public class PQCTestUtilities
    {
        public static string JsonWebKeySetWithMultipleKeys()
        {
            ECDsa ecdsa = null;
            ECDsa ecdsaPublic = null;
            Mldsa mldsa = null;
            RSA rsa = null;

            try
            {
                ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                mldsa = Mldsa.Create(SecurityAlgorithms.Mldsa44);
                rsa = RSA.Create(2048);

                return JsonWebKeySetWithMultipleKeys(ecdsa, rsa, mldsa);
            }
            finally
            {
                ecdsa?.Dispose();
                ecdsaPublic?.Dispose();
                mldsa?.Dispose();
                rsa?.Dispose();
            }
        }

        public static string JsonWebKeySetWithMultipleKeys(ECDsa ecdsa, RSA rsa, Mldsa mldsa)
        {
            ECDsa ecdsaPublic = null;
            try
            {
                // scope to public keys
                RSAParameters rsaParameters = rsa.ExportParameters(false);
                ECParameters ecdsaPrameters = ecdsa.ExportParameters(false);
                ecdsaPublic = ECDsa.Create(ecdsaPrameters);

                ECDsaSecurityKey ecdsaSecurityKey = new ECDsaSecurityKey(ecdsaPublic);
                MldsaSecurityKey mldsaSecurityKey = new MldsaSecurityKey(mldsa);
                RsaSecurityKey rsaSecurityKey = new RsaSecurityKey(rsaParameters);

                JsonWebKey ecdsaJsonWebKey = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(ecdsaSecurityKey);
                JsonWebKey rsaJsonWebKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaSecurityKey);
                JsonWebKey mldsaJsonWebKey = JsonWebKeyConverter.ConvertFromMldsaSecurityKey(mldsaSecurityKey);

                JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
                jsonWebKeySet.Keys.Add(ecdsaJsonWebKey);
                jsonWebKeySet.Keys.Add(rsaJsonWebKey);
                jsonWebKeySet.Keys.Add(mldsaJsonWebKey);

                return JsonWebKeySetSerializer.Write(jsonWebKeySet);
            }
            finally
            {
                ecdsaPublic?.Dispose();
            }
        }

        /// <summary>
        /// Creates a <see cref="ConfigurationManager{OpenIdConnectConfiguration}"/> with a static configuration and a static JWK set.
        /// </summary>
        /// <param name="ecdsa">the ECDsa algorithm to include.</param>
        /// <param name="rsa">the RSA algorithm to include.</param>
        /// <param name="mldsa">the Mldsa algorithm to include.</param>
        /// <param name="issuer">the issuer in the metadata.</param>
        /// <param name="authority">the address that is used to identify this metadata.</param>
        /// <param name="jwksUri">the address for the 'jwks_uri value in the discovery metadata.</param>
        /// <returns></returns>
        public static ConfigurationManager<OpenIdConnectConfiguration> GetStaticConfiguration(
            ECDsa ecdsa,
            RSA rsa,
            Mldsa mldsa,
            string issuer,
            string authority,
            string jwksUri)
        {
            string jsonWebKeySetString = PQCTestUtilities.JsonWebKeySetWithMultipleKeys(ecdsa, rsa, mldsa);
            OpenIdConnectConfiguration openIdConnectConfiguration = new OpenIdConnectConfiguration();
            openIdConnectConfiguration.Issuer = issuer;
            openIdConnectConfiguration.JwksUri = jwksUri;

            string openIdConnectConfigurationString = OpenIdConnectConfiguration.Write(openIdConnectConfiguration);

            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    authority,
                    new OpenIdConnectConfigurationRetriever(),
                    new StaticDocumentRetriever(openIdConnectConfigurationString, jsonWebKeySetString, authority, jwksUri));

            return configurationManager;
        }
    }

    public class StaticDocumentRetriever : IDocumentRetriever
    {
        private string _openIdConnectConfiguration;
        private string _jsonWebKeySet;
        private string _authority = "MetadataAddress";
        private string _jwksUri = "JsonWebKeySetAddress";

        public StaticDocumentRetriever(string openIdConnectConfiguration, string jsonWebKeySet) :
            this(openIdConnectConfiguration, jsonWebKeySet, "MetadataAddress", "JsonWebKeySetAddress")
        {
        }

        public StaticDocumentRetriever(string openIdConnectConfiguration, string jsonWebKeySet, string authority, string jwksuri)
        {
            _openIdConnectConfiguration = openIdConnectConfiguration;
            _jsonWebKeySet = jsonWebKeySet;
            _authority = authority;
            _jwksUri = jwksuri;
        }

        public Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            if (address == _authority)
            {
                return Task.FromResult(_openIdConnectConfiguration);
            }
            else if (address == _jwksUri)
            {
                return Task.FromResult(_jsonWebKeySet);
            }
            else
            {
                throw new InvalidOperationException($"Unknown address: {address}");
            }
        }
    }
}

