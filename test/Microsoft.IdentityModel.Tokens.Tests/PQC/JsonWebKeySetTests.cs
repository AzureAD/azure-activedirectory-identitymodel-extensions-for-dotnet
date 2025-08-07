// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Json;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.PQC.Tests
{
    /// <summary>
    /// This class tests serializing JsonWebKeySets with MLDSA keys.
    /// </summary>
    public class JsonWebKeySetTests
    {
        /// <summary>
        /// Parses a JsonWebKeySet with MLDSA, RSA, ECD keys and X509Certs.
        /// This is the first step in reading OpenIdConnectConfiguration with ML-DSA keys.
        /// </summary>
        [Fact]
        public void SerializeJsonWebKeySet()
        {
            Mldsa mldsa = Mldsa.Create(SecurityAlgorithms.Mldsa44);
            Mldsa mldsa2 = Mldsa.Create(SecurityAlgorithms.Mldsa44);
            JsonWebKey jsonWebKey1 = JsonWebKeyConverter.ConvertFromMldsaSecurityKey(new MldsaSecurityKey(mldsa));
            JsonWebKey jsonWebKey2 = JsonWebKeyConverter.ConvertFromMldsaSecurityKey(new MldsaSecurityKey(mldsa2));

            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
            jsonWebKeySet.Keys.Add(jsonWebKey1);
            jsonWebKeySet.Keys.Add(jsonWebKey2);

            string JsonWebKeySetString = JsonWebKeySetSerializer.Write(jsonWebKeySet);
            JsonWebKeySet deserializedJsonWebKeySet = JsonWebKeySetSerializer.Read(JsonWebKeySetString, new JsonWebKeySet());

            CompareContext compareContext = new CompareContext();
            IdentityComparer.AreEqual(jsonWebKeySet, deserializedJsonWebKeySet, compareContext);

            TestUtilities.AssertFailIfErrors(compareContext);
        }

        /// <summary>
        /// Serializer and JsonWebKeySet with ECDsa, RSA and MLDSA.
        /// </summary>
        [Fact]

        public void SerializeMultipleKeys()
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

                string jsonWebKeySetString = JsonWebKeySetSerializer.Write(jsonWebKeySet);
                JsonWebKeySet deserializedJsonWebKeySet = JsonWebKeySetSerializer.Read(jsonWebKeySetString, new JsonWebKeySet());

                CompareContext compareContext = new CompareContext();
                IdentityComparer.AreEqual(jsonWebKeySet, deserializedJsonWebKeySet, compareContext);

                TestUtilities.AssertFailIfErrors(compareContext);
            }
            finally
            {
                ecdsa?.Dispose();
                ecdsaPublic?.Dispose();
                mldsa?.Dispose();
                rsa?.Dispose();
            }
        }
    }
}

