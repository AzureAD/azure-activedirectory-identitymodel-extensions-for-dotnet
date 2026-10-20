// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.TestUtils
{
    public static class ReplayIdentityTestUtilities
    {
        public static ECDsa CreateEcdsa(int bits)
        {
#if NET462
            return new ECDsaCng(bits);
#else
            return ECDsa.Create(bits == 256 ? ECCurve.NamedCurves.nistP256 :
                bits == 384 ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP521);
#endif
        }

        // P1363 encodes r || s. (r, n - s) is another valid signature of the same message.
        public static byte[] TwinSignature(byte[] signature)
        {
            string order = signature.Length == 64
                ? "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
                : signature.Length == 96
                    ? "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"
                    : "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409";
            int size = signature.Length / 2;
            var twin = (byte[])signature.Clone();
            int borrow = 0;
            for (int i = size - 1; i >= 0; i--)
            {
                int difference = Convert.ToByte(order.Substring(i * 2, 2), 16) - signature[size + i] - borrow;
                twin[size + i] = (byte)difference;
                borrow = difference < 0 ? 1 : 0;
            }

            return twin;
        }

        public sealed class StatefulReplayCache : ITokenReplayCache
        {
            private readonly HashSet<string> _entries = new HashSet<string>(StringComparer.Ordinal);
            public List<string> Finds { get; } = new List<string>();
            public List<string> Adds { get; } = new List<string>();
            public List<DateTime> Expirations { get; } = new List<DateTime>();
            public bool FailAdds { get; set; }

            public bool TryFind(string securityToken)
            {
                lock (_entries)
                {
                    Finds.Add(securityToken);
                    return _entries.Contains(securityToken);
                }
            }

            public bool TryAdd(string securityToken, DateTime expiresOn)
            {
                lock (_entries)
                {
                    Adds.Add(securityToken);
                    Expirations.Add(expiresOn);
                    return !FailAdds && _entries.Add(securityToken);
                }
            }
        }

        public sealed class RejectSigningKey : ISignatureKeyValidator
        {
            public ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
                SecurityKey signingKey, SecurityToken securityToken, ValidationParameters validationParameters, CallContext callContext)
            {
                return new SignatureKeyValidationError(new MessageDetail("Rejected test signing key"),
                    SignatureKeyValidationFailure.ValidationFailed, null, signingKey);
            }
        }

        public sealed class RecordingReplayValidator : ITokenReplayValidator
        {
            public List<string> Tokens { get; } = new List<string>();
            public bool Accept { get; set; } = true;
            public Action OnValidation { get; set; }

            public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
                DateTime? expirationTime, string securityToken, ValidationParameters validationParameters, CallContext callContext)
            {
                Tokens.Add(securityToken);
                OnValidation?.Invoke();
                if (!Accept)
                    return new TokenReplayValidationError(new MessageDetail("Rejected test replay"),
                        TokenReplayValidationFailure.TokenFoundInCache, null, expirationTime);

                return expirationTime;
            }
        }
    }
}
