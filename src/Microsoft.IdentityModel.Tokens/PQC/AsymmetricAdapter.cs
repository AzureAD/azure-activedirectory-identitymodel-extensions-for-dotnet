// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
#if NET6_0_OR_GREATER
using System.Buffers;
#endif

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Handles MLDsa.
    /// </summary>
    internal partial class AsymmetricAdapter : IDisposable
    {
        private void InitializeUsingMldsaSecurityKey(MldsaSecurityKey mldsaSecurityKey)
        {
            Mldsa = mldsaSecurityKey.Mldsa;
            _signFunction = SignMldsa;
#if NET6_0_OR_GREATER
            _signUsingSpanFunction = SignUsingSpanMldsa;
#endif
            _verifyFunction = VerifyMldsa;
            _verifyUsingOffsetFunction = VerifyUsingOffsetMldsa;
        }

        private Mldsa Mldsa { get; set; }

        private byte[] SignMldsa(byte[] bytes)
        {
            Mldsa.SignData(bytes, out byte[] signature);

            return signature;
        }

#if NET6_0_OR_GREATER
        internal bool SignUsingSpanMldsa(
            ReadOnlySpan<byte> data,
            Span<byte> destination,
            out int bytesWritten)
        {
            if (destination.Length == 0)
            {
                bytesWritten = 0;
                return false;
            }

            Mldsa.SignData(data.ToArray(), out byte[] signature);
            bytesWritten = signature.Length;
            if (destination.Length < bytesWritten)
            {
                return false;
            }

            signature.CopyTo(destination);
            return destination.Length >= bytesWritten;
        }
#endif

        private bool VerifyMldsa(byte[] bytes, byte[] signature)
        {
            return Mldsa.VerifyData(bytes, signature);
        }

        private bool VerifyUsingOffsetMldsa(byte[] bytes, int offset, int count, byte[] signature)
        {
            byte[] data = new byte[count];
            Buffer.BlockCopy(bytes, offset, data, 0, count);
            return Mldsa.VerifyData(data, signature);
        }
    }
}
