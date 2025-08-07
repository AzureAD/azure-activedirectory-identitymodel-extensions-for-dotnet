// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Converts a <see cref="SecurityKey"/> into a <see cref="JsonWebKey"/>
    /// Supports: converting to a <see cref="JsonWebKey"/> from one of: <see cref="RsaSecurityKey"/>, <see cref="X509SecurityKey"/>, and <see cref=" SymmetricSecurityKey"/>.
    /// </summary>
    public partial class JsonWebKeyConverter
    {
#pragma warning disable RS0016 // Add public types and members to the declared API

        /// <summary>
        /// Converts a <see cref="MldsaSecurityKey"/> into a <see cref="JsonWebKey"/>
        /// </summary>
        /// <param name="key">a <see cref="MldsaSecurityKey"/> to convert.</param>
        /// <returns>a <see cref="JsonWebKey"/></returns>
        /// <exception cref="ArgumentNullException">if <paramref name="key"/>is null.</exception>
        public static JsonWebKey ConvertFromMldsaSecurityKey(MldsaSecurityKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            return new JsonWebKey
            {
                Pub = key.PublicKey,
                Kty = JsonWebAlgorithmsKeyTypes.MLDSA,
                Kid = key.Thumbprint,
                Alg = key.Algorithm,
                ConvertedSecurityKey = key
            };
        }

        internal static bool TryConvertToMldsaSecurityKey(JsonWebKey webKey, out SecurityKey key)
        {
            if (webKey.ConvertedSecurityKey is MldsaSecurityKey)
            {
                key = webKey.ConvertedSecurityKey;
                return true;
            }

            key = null;
            if (string.IsNullOrWhiteSpace(webKey.Pub))
                return false;

            try
            {
#pragma warning disable CA2000
                // TODO: need to find a way to not convert key until needed
                Mldsa mldsa = Mldsa.Create(webKey.Pub, webKey.Alg);
#pragma warning restore CA2000
                key = new MldsaSecurityKey(mldsa)
                {
                    KeyId = webKey.KeyId,
                };

                webKey.ConvertedSecurityKey = key;
                return true;
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                string convertKeyInfo = LogHelper.FormatInvariant(LogMessages.IDX10813, LogHelper.MarkAsNonPII(typeof(RsaSecurityKey)), LogHelper.MarkAsNonPII(webKey.KeyId), ex);
                webKey.ConvertKeyInfo = convertKeyInfo;
                if (LogHelper.IsEnabled(EventLogLevel.Error))
                    LogHelper.LogExceptionMessage(new InvalidOperationException(convertKeyInfo, ex));
            }

            return false;
        }

    }
#pragma warning restore RS0016 // Add public types and members to the declared API
}
