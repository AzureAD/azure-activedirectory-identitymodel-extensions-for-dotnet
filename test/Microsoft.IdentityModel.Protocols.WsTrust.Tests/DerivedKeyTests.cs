using System;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class DerivedKeyTests
    {
        [Theory, MemberData(nameof(ComputedKeyTheoryData))]
        public void ComputedKey(DerivedKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ComputedKey", theoryData);

            try
            {
                byte[] computedKey = KeyGenerator.ComputeCombinedKey(theoryData.ComputedKeyMaterial.IssuerEntropyBytes, theoryData.ComputedKeyMaterial.RequestorEntropyBytes, theoryData.ComputedKeyMaterial.KeySizeInBits);
                // derived key with label == null, position == 0, nonce == IssuerEntropy should equal computed key.
                byte[] derivedKey = (new PshaDerivedKeyGenerator(theoryData.ComputedKeyMaterial.RequestorEntropyBytes).ComputeCombinedKey(SecurityAlgorithms.HmacSha1, new byte[] { }, theoryData.ComputedKeyMaterial.IssuerEntropyBytes, theoryData.ComputedKeyMaterial.KeySizeInBits, 0));
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(computedKey, theoryData.ComputedKeyMaterial.DerivedKeyBytes, context);
                if (!IdentityComparer.AreEqual(computedKey, derivedKey))
                    context.AddDiff("IdentityComparer.AreEqual(computedKey, derivedKey) returned false.");

                if (computedKey.Length * 8 != theoryData.ComputedKeyMaterial.KeySizeInBits)
                    context.Diffs.Add($"computedKey.Length: '{computedKey.Length}' != theoryData.ComputedKeyMaterial.KeySizeInBits: '{theoryData.ComputedKeyMaterial.KeySizeInBits}'.");
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<DerivedKeyTheoryData> ComputedKeyTheoryData
        {
            get
            {
                var theoryData = new TheoryData<DerivedKeyTheoryData>
                {
                    new DerivedKeyTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("issuerEntropy"),
                        First = true,
                        ComputedKeyMaterial = new ComputedKeyMaterial(null, ComputedKeyMaterial.Entropy128, ComputedKeyMaterial.DerivedKey128, 256 * 8),
                        TestId = "IssuerEntropyNull"
                    },
                    new DerivedKeyTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentException("issuerEntropy"),
                        First = true,
                        ComputedKeyMaterial = new ComputedKeyMaterial(ComputedKeyMaterial.EntropyTooLarge, ComputedKeyMaterial.Entropy128, ComputedKeyMaterial.DerivedKey128, 256 * 8),
                        TestId = "IssuerEntropyTooLarge"
                    },
                    new DerivedKeyTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentException("issuerEntropy"),
                        First = true,
                        ComputedKeyMaterial = new ComputedKeyMaterial(ComputedKeyMaterial.EntropyTooSmall, ComputedKeyMaterial.Entropy128, ComputedKeyMaterial.DerivedKey128, 256 * 8),
                        TestId = "IssuerEntropyTooSmall"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = new ComputedKeyMaterial(ComputedKeyMaterial.Entropy128, ComputedKeyMaterial.Entropy128, ComputedKeyMaterial.DerivedKey128, 8 * 8),
                        ExpectedException = ExpectedException.ArgumentException("keySizeInBits"),
                        TestId = "KeySizeTooSmall"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = new ComputedKeyMaterial(ComputedKeyMaterial.Entropy128, ComputedKeyMaterial.Entropy128, ComputedKeyMaterial.DerivedKey128, 32 * 1024 * 8),
                        ExpectedException = ExpectedException.ArgumentException("keySizeInBits"),
                        TestId = "KeySizeTooLarge"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = new ComputedKeyMaterial(ComputedKeyMaterial.Entropy128, null, ComputedKeyMaterial.DerivedKey128, 256),
                        ExpectedException = ExpectedException.ArgumentNullException("requestorEntropy"),
                        TestId = "RequestorEntropyNull"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = new ComputedKeyMaterial(ComputedKeyMaterial.Entropy128, ComputedKeyMaterial.EntropyTooSmall, ComputedKeyMaterial.DerivedKey128, 256),
                        ExpectedException = ExpectedException.ArgumentException("requestorEntropy"),
                        TestId = "RequestorEntropyTooSmall"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = new ComputedKeyMaterial(ComputedKeyMaterial.Entropy128, ComputedKeyMaterial.EntropyTooLarge, ComputedKeyMaterial.DerivedKey128, 256),
                        ExpectedException = ExpectedException.ArgumentException("requestorEntropy"),
                        TestId = "RequestorEntropyTooLarge"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = PSHA1.Reference128_1,
                        TestId = "PSHA1_Reference128_1"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = PSHA1.Reference128_2,
                        TestId = "PSHA1_Reference128_2"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = PSHA1.Reference128_3,
                        TestId = "PSHA1_Reference128_3"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = PSHA1.Reference128_4,
                        TestId = "PSHA1_Reference128_4"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = PSHA1.Reference256_1,
                        TestId = "PSHA1_Reference256_1"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = PSHA1.Reference256_2,
                        TestId = "PSHA1_Reference256_2"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = PSHA1.Reference512_1,
                        TestId = "PSHA1_Reference512_1"
                    },
                    new DerivedKeyTheoryData
                    {
                        ComputedKeyMaterial = PSHA1.Reference512_2,
                        TestId = "PSHA1_Reference512_2"
                    }
                };

                return theoryData;
            }
        }
    }

    public class DerivedKeyTheoryData : TheoryDataBase
    {
        public ComputedKeyMaterial ComputedKeyMaterial { get; set; }
    }
}
