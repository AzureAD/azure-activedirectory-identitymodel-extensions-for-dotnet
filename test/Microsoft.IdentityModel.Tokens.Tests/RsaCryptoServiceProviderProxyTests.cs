//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Globalization;
using System.Security.Cryptography;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class RsaCryptoServiceProviderProxyTests
    {

        byte[] input = new byte[10];

#if NETCOREAPP1_0
        HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;
#else
        string _hashAlgorithm = SecurityAlgorithms.Sha256;
#endif

        [Fact]
        public void TestCustomRsaCsp()
        {
            RSACryptoServiceProvider rsaCsp = KeyingMaterial.DefaultX509Key_2048.PrivateKey as RSACryptoServiceProvider;
            if (rsaCsp == null)
                return;

            Assert.True(rsaCsp.CspKeyContainerInfo.ProviderType == 1, "Default RsaCSP provider type is not equal to 1. ProviderType: " + rsaCsp.CspKeyContainerInfo.ProviderType);
            SignData(rsaCsp, ExpectedException.CryptographicException("Invalid algorithm specified"));
            SignData(new RSACryptoServiceProviderProxy(rsaCsp), ExpectedException.NoExceptionExpected);

            rsaCsp = CreateProviderWithProviderType(rsaCsp.CspKeyContainerInfo, 1);
            SignData(rsaCsp, ExpectedException.CryptographicException("Invalid algorithm specified"));
            SignData(new RSACryptoServiceProviderProxy(rsaCsp), ExpectedException.NoExceptionExpected);

            rsaCsp = CreateProviderWithProviderType(rsaCsp.CspKeyContainerInfo, 12);
            Assert.True(rsaCsp.CspKeyContainerInfo.ProviderType == 12, "rsa provider type != 12. ProviderType: " + rsaCsp.CspKeyContainerInfo.ProviderType);
            SignData(rsaCsp, ExpectedException.CryptographicException("Invalid algorithm specified"));
            SignData(new RSACryptoServiceProviderProxy(rsaCsp), ExpectedException.NoExceptionExpected);

            rsaCsp = CreateProviderWithProviderType(rsaCsp.CspKeyContainerInfo, 24);
            SignData(rsaCsp, ExpectedException.NoExceptionExpected);
            SignData(new RSACryptoServiceProviderProxy(rsaCsp), ExpectedException.NoExceptionExpected);
        }

        private RSACryptoServiceProvider CreateProviderWithProviderType(CspKeyContainerInfo cspKeyContainerInfo, int providerType)
        {
            CspParameters csp = new CspParameters();
            csp.ProviderType = providerType;
            csp.KeyContainerName = cspKeyContainerInfo.KeyContainerName;
            csp.KeyNumber = (int)cspKeyContainerInfo.KeyNumber;
            if (cspKeyContainerInfo.MachineKeyStore)
                csp.Flags = CspProviderFlags.UseMachineKeyStore;
            csp.Flags |= CspProviderFlags.UseExistingKey;
            return new RSACryptoServiceProvider(csp);
        }

        private void SignData(RSACryptoServiceProvider rsaCsp, ExpectedException ee)
        {
            try
            {
#if NETCOREAPP1_0
                rsaCsp.SignData(input, _hashAlgorithm.Name);
#else
                rsaCsp.SignData(input, _hashAlgorithm);
#endif
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        private void SignData(RSACryptoServiceProviderProxy rsaCspProxy, ExpectedException ee)
        {
            try
            {
#if NETCOREAPP1_0
                rsaCspProxy.SignData(input, _hashAlgorithm.Name);
#else
                rsaCspProxy.SignData(input, _hashAlgorithm);
#endif
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

    }
}
