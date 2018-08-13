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
using System.Collections.Generic;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class EncryptedKeyTests
    {
        [Fact]
        public void GetSets()
        {
            var type = typeof(EncryptedKey);
            var properties = type.GetProperties();
            Assert.True(properties.Length == 8, $"Number of properties has changed from 8 to: {properties.Length}, adjust tests");

            var encryptedKey = new EncryptedKey();

            var getSetContext = new GetSetContext
            {
                PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                {
                    new KeyValuePair<string, List<object>>("Id", new List<object>{null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Type", new List<object>{XmlEncryptionConstants.EncryptedDataTypes.EncryptedKey, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("MimeType", new List<object>{null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Encoding", new List<object>{XmlSignatureConstants.Base64Encoding, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("KeyInfo", new List<object>{new KeyInfo()}),
                },
                Object = encryptedKey
            };

            TestUtilities.GetSet(getSetContext);
            TestUtilities.AssertFailIfErrors($"{this}.GetSets", getSetContext.Errors);
        }
        
        [Theory, MemberData(nameof(ConstructorTheoryData))]
        public void Constructor(EncryptedKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.Constructor", theoryData);
            try
            {
                var encryptedKey = new EncryptedKey();
                IdentityComparer.AreEqual(encryptedKey.Type, XmlEncryptionConstants.EncryptedDataTypes.EncryptedKey, context);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception exception)
            {
                theoryData.ExpectedException.ProcessException(exception, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<EncryptedKeyTheoryData> ConstructorTheoryData()
        {
            return new TheoryData<EncryptedKeyTheoryData>
            {
                new EncryptedKeyTheoryData
                {
                    First = true,
                    TestId = "valid"
                },
            };
        }

        [Theory, MemberData(nameof(AddReferenceTheoryData))]
        public void AddReference(EncryptedKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.AddReference", theoryData);

            try
            {
                var encryptedKey = new EncryptedKey();
                foreach (var reference in theoryData.KeyReferenceList)
                {
                    encryptedKey.AddReference(reference);
                }

                foreach (var reference in theoryData.DataReferenceList)
                {
                    encryptedKey.AddReference(reference);
                }

                IdentityComparer.AreEqual(encryptedKey.ReferenceList.Count, theoryData.KeyReferenceList.Count + theoryData.DataReferenceList.Count, context);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<EncryptedKeyTheoryData> AddReferenceTheoryData()
        {
            return new TheoryData<EncryptedKeyTheoryData>
            {
                new EncryptedKeyTheoryData
                {
                    KeyReferenceList = new List<KeyReference>() { new KeyReference(), new KeyReference(Guid.NewGuid().ToString()) },
                    DataReferenceList = new List<DataReference>(),
                    TestId = "valid"
                },
                new EncryptedKeyTheoryData
                {
                    KeyReferenceList = new List<KeyReference>() { new KeyReference(), new KeyReference(Guid.NewGuid().ToString()) },
                    DataReferenceList = new List<DataReference>() { new DataReference(), new DataReference(Guid.NewGuid().ToString()) },
                    TestId = "valid_both"
                },
            };
        }
    }

    public class EncryptedKeyTheoryData : TheoryDataBase
    {
        public IList<EncryptedReference> ReferenceList { get; set; }

        public string Id { get; set; }

        public string Type { get; set; }

        public string MimeType { get; set; }

        public string Encoding { get; set; }

        public KeyInfo KeyInfo { get; set; }

        public EncryptionMethod EncryptionMethod { get; set; }

        public CipherData CipherData { get; set; }

        public IList<KeyReference> KeyReferenceList { get; set; }

        public IList<DataReference> DataReferenceList { get; set; }
    }
}

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant


