// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.PQC.Tests
{
    /// <summary>
    /// This class tests integration with SymCrypt
    /// </summary>
    public class SymCryptWin64Tests
    {
        [Fact]
        public void SignWithRsaSymCrypt()
        {
            byte[] bytesToSign = Guid.NewGuid().ToByteArray();
            long cb = bytesToSign.Length;
            byte[] signature = new byte[2048];
            long sizeofSignature = 2048;
            int result = SymCryptWin64.CreateRsaKeyAndSign(
                bytesToSign,
                cb,
                ref signature,
                ref sizeofSignature);
        }
    }
}
