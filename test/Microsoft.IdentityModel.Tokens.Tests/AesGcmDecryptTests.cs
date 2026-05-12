// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#if NET6_0_OR_GREATER
using System;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests;

public class AesGcmTheoryData : TheoryDataBase
{
    public int KeySize { get; set; }
    public int PlaintextSize { get; set; }
    public TamperTarget TamperTarget { get; set; }
    public bool UseAssociatedData { get; set; }
    public bool ExpectDecryptionFailure { get; set; }
}

public enum TamperTarget
{
    None,
    Tag,
    Ciphertext,
    AssociatedData
}

public class AesGcmDecryptTests
{
    [Theory, MemberData(nameof(DecryptPlaintextBufferTheoryData), DisableDiscoveryEnumeration = true)]
    public void Decrypt_ClearsPlaintextBufferOnFailure(AesGcmTheoryData theoryData)
    {
        var context = TestUtilities.WriteHeader($"{this}.Decrypt_ClearsPlaintextBufferOnFailure", theoryData);

        try
        {
            // Arrange: Create valid encryption
            byte[] key = new byte[theoryData.KeySize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            byte[] nonce = new byte[AesGcm.NonceSize];
            byte[] plaintext = new byte[theoryData.PlaintextSize];
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[AesGcm.TagSize];
            byte[] associatedData = theoryData.UseAssociatedData ? new byte[16] : null;

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonce);
                rng.GetBytes(plaintext);
                if (associatedData != null)
                    rng.GetBytes(associatedData);
            }

            // Perform valid encryption
            using (var aesGcm = new AesGcm(key))
            {
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            }

            // Apply tampering based on test scenario
            byte[] decryptTag = tag;
            byte[] decryptCiphertext = ciphertext;
            byte[] decryptAssociatedData = associatedData;

            switch (theoryData.TamperTarget)
            {
                case TamperTarget.Tag:
                    decryptTag = (byte[])tag.Clone();
                    decryptTag[0] ^= 0xFF;
                    break;
                case TamperTarget.Ciphertext:
                    decryptCiphertext = (byte[])ciphertext.Clone();
                    decryptCiphertext[0] ^= 0xFF;
                    break;
                case TamperTarget.AssociatedData:
                    if (associatedData != null)
                    {
                        decryptAssociatedData = (byte[])associatedData.Clone();
                        decryptAssociatedData[0] ^= 0xFF;
                    }
                    break;
            }

            // Prepare plaintext buffer with recognizable data
            byte[] plaintextBuffer = Enumerable.Repeat((byte)0xAA, plaintext.Length).ToArray();

            // Act & Assert
            using (var aesGcm = new AesGcm(key))
            {
                if (theoryData.ExpectDecryptionFailure)
                {
#if NET8_0_OR_GREATER
                    var exception = Assert.Throws<AuthenticationTagMismatchException>(() =>
                        aesGcm.Decrypt(nonce, decryptCiphertext, decryptTag, plaintextBuffer, decryptAssociatedData));
#elif NET6_0
                    var exception = Assert.Throws<CryptographicException>(() =>
                        aesGcm.Decrypt(nonce, decryptCiphertext, decryptTag, plaintextBuffer, decryptAssociatedData));
#endif
                    Assert.NotNull(exception);

                    // Verify that the plaintext buffer was zeroed out
                    bool isZeroed = plaintextBuffer.All(b => b == 0);
                    if (!isZeroed)
                    {
                        context.AddDiff($"Plaintext buffer was not zeroed after decryption failure. " +
                            $"Tamper target: {theoryData.TamperTarget}, Key size: {theoryData.KeySize * 8} bits. " +
                            $"Buffer contains non-zero bytes: {string.Join(", ", plaintextBuffer.Take(10))}");
                    }

                    Assert.True(isZeroed, "Plaintext buffer should be completely zeroed after decryption failure to prevent secret leakage.");
                }
                else
                {
                    // Valid decryption case
                    aesGcm.Decrypt(nonce, decryptCiphertext, decryptTag, plaintextBuffer, decryptAssociatedData);

                    // Verify that decryption succeeded and plaintext matches
                    bool matches = plaintext.SequenceEqual(plaintextBuffer);
                    if (!matches)
                    {
                        context.AddDiff("Decrypted plaintext does not match original plaintext.");
                    }

                    Assert.True(matches, "Decrypted plaintext should match original plaintext for valid inputs.");
                }
            }

            theoryData.ExpectedException.ProcessNoException(context);
        }
        catch (Exception ex)
        {
            theoryData.ExpectedException.ProcessException(ex, context);
        }

        TestUtilities.AssertFailIfErrors(context);
    }

    public static TheoryData<AesGcmTheoryData> DecryptPlaintextBufferTheoryData()
    {
        var theoryData = new TheoryData<AesGcmTheoryData>();

        // Test tampering with authentication tag for various key sizes
        theoryData.Add(new AesGcmTheoryData
        {
            TestId = "TamperedTag_128bit_WithAAD",
            KeySize = 16,
            PlaintextSize = 32,
            TamperTarget = TamperTarget.Tag,
            UseAssociatedData = true,
            ExpectDecryptionFailure = true,
            ExpectedException = ExpectedException.NoExceptionExpected
        });

        theoryData.Add(new AesGcmTheoryData
        {
            TestId = "TamperedTag_192bit_WithAAD",
            KeySize = 24,
            PlaintextSize = 32,
            TamperTarget = TamperTarget.Tag,
            UseAssociatedData = true,
            ExpectDecryptionFailure = true,
            ExpectedException = ExpectedException.NoExceptionExpected
        });

        theoryData.Add(new AesGcmTheoryData
        {
            TestId = "TamperedTag_256bit_WithAAD",
            KeySize = 32,
            PlaintextSize = 32,
            TamperTarget = TamperTarget.Tag,
            UseAssociatedData = true,
            ExpectDecryptionFailure = true,
            ExpectedException = ExpectedException.NoExceptionExpected
        });

        // Test tampering with ciphertext
        theoryData.Add(new AesGcmTheoryData
        {
            TestId = "TamperedCiphertext_256bit_WithAAD",
            KeySize = 32,
            PlaintextSize = 32,
            TamperTarget = TamperTarget.Ciphertext,
            UseAssociatedData = true,
            ExpectDecryptionFailure = true,
            ExpectedException = ExpectedException.NoExceptionExpected
        });

        // Test tampering with associated data
        theoryData.Add(new AesGcmTheoryData
        {
            TestId = "TamperedAssociatedData_256bit",
            KeySize = 32,
            PlaintextSize = 32,
            TamperTarget = TamperTarget.AssociatedData,
            UseAssociatedData = true,
            ExpectDecryptionFailure = true,
            ExpectedException = ExpectedException.NoExceptionExpected
        });

        // Test without associated data
        theoryData.Add(new AesGcmTheoryData
        {
            TestId = "TamperedTag_256bit_NoAAD",
            KeySize = 32,
            PlaintextSize = 64,
            TamperTarget = TamperTarget.Tag,
            UseAssociatedData = false,
            ExpectDecryptionFailure = true,
            ExpectedException = ExpectedException.NoExceptionExpected
        });

        // Test valid decryption (positive case)
        theoryData.Add(new AesGcmTheoryData
        {
            TestId = "ValidDecryption_256bit_WithAAD",
            KeySize = 32,
            PlaintextSize = 32,
            TamperTarget = TamperTarget.None,
            UseAssociatedData = true,
            ExpectDecryptionFailure = false,
            ExpectedException = ExpectedException.NoExceptionExpected
        });

        theoryData.Add(new AesGcmTheoryData
        {
            TestId = "ValidDecryption_256bit_NoAAD",
            KeySize = 32,
            PlaintextSize = 32,
            TamperTarget = TamperTarget.None,
            UseAssociatedData = false,
            ExpectDecryptionFailure = false,
            ExpectedException = ExpectedException.NoExceptionExpected
        });

        return theoryData;
    }
}
#endif
