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
using System.IO;
using Microsoft.IdentityModel.Tests;
using Newtonsoft.Json;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class JsonWebKeySetTests
    {
        private static readonly JsonSerializerSettings _jsonSerializerSettingsForRegressionTest = new JsonSerializerSettings
        {
            ObjectCreationHandling = ObjectCreationHandling.Replace,
        };

        [Theory, MemberData(nameof(JsonWekKeySetDataSet))]
        public void Constructors(
            string json,
            JsonWebKeySet compareTo,
            JsonSerializerSettings settings,
            ExpectedException ee)
        {
            var context = new CompareContext();
            try
            {
#pragma warning disable CS0618 // Type or member is obsolete
                var jsonWebKeys = new JsonWebKeySet(json, settings);
#pragma warning restore CS0618 // Type or member is obsolete
                var keys = jsonWebKeys.GetSigningKeys();
                ee.ProcessNoException(context);
                if (compareTo != null)
                    IdentityComparer.AreEqual(jsonWebKeys, compareTo, context);

            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<string, JsonWebKeySet, JsonSerializerSettings, ExpectedException> JsonWekKeySetDataSet
        {
            get
            {
                var dataset = new TheoryData<string, JsonWebKeySet, JsonSerializerSettings, ExpectedException>();

                foreach (var setting in new[] { _jsonSerializerSettingsForRegressionTest, null })
                {
                    dataset.Add(DataSets.JsonWebKeySetAdditionalDataString1, DataSets.JsonWebKeySetAdditionalData1, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(null, null, setting, ExpectedException.ArgumentNullException());
                    dataset.Add(DataSets.JsonWebKeySetString1, DataSets.JsonWebKeySet1, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetBadFormatingString, null, setting, ExpectedException.ArgumentException(substringExpected: "IDX10805:", inner: typeof(JsonReaderException)));
                    dataset.Add(File.ReadAllText(DataSets.GoogleCertsFile), DataSets.GoogleCertsExpected, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetBadRsaExponentString, null, setting, ExpectedException.InvalidOperationException(substringExpected: "IDX10801:", inner: typeof(FormatException)));
                    dataset.Add(DataSets.JsonWebKeySetBadRsaModulusString, null, setting, ExpectedException.InvalidOperationException(substringExpected: "IDX10801:", inner: typeof(FormatException)));
                    dataset.Add(DataSets.JsonWebKeySetKtyNotRsaString, null, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetUseNotSigString, null, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetBadX509String, null, setting, ExpectedException.InvalidOperationException(substringExpected: "IDX10802:", inner: typeof(FormatException)));
                }

                return dataset;
            }
        }

        [Fact]
        public void Defaults()
        {
            var context = new CompareContext();
            JsonWebKeySet jsonWebKeys = new JsonWebKeySet();

            if (jsonWebKeys.Keys == null)
                context.Diffs.Add("jsonWebKeys.Keys == null");
            else if (jsonWebKeys.Keys.Count != 0)
                context.Diffs.Add("jsonWebKeys.Keys.Count != 0");

            if (jsonWebKeys.AdditionalData == null)
                context.Diffs.Add("jsonWebKeys.AdditionalData == null");
            else if (jsonWebKeys.AdditionalData.Count != 0)
                context.Diffs.Add("jsonWebKeys.AdditionalData.Count != 0");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void GetSets()
        {
        }

        [Fact]
        public void Publics()
        {
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
