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
using System.IO;
using Newtonsoft.Json;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class JsonWebKeySetTests
    {
        [Fact(DisplayName = "JsonWebKeySetTests: Constructors")]
        public void Constructors()
        {
            //System.Diagnostics.Debugger.Launch();
            JsonWebKeySet jsonWebKeys = new JsonWebKeySet();
            Assert.True(IsDefaultJsonWebKeySet(jsonWebKeys));

            // null string, nothing to add
            RunJsonWebKeySetTest((string)null, null, ExpectedException.ArgumentNullException());
            RunJsonWebKeySetTest(DataSets.JsonWebKeySetString1,  DataSets.JsonWebKeySetExpected1, ExpectedException.NoExceptionExpected);
            RunJsonWebKeySetTest(DataSets.JsonWebKeySetBadFormatingString, null, ExpectedException.ArgumentException(substringExpected: "IDX10804:", inner: typeof(JsonReaderException)));
        }

        [Fact]
        public void Interop()
        {
            string certsData = File.ReadAllText(DataSets.GoogleCertsFile);
            RunJsonWebKeySetTest(certsData, DataSets.GoogleCertsExpected, ExpectedException.NoExceptionExpected);

            GetSigningKeys(DataSets.JsonWebKeySetBadRsaExponentString, null, ExpectedException.InvalidOperationException(substringExpected: "IDX10801:", inner: typeof(FormatException)));
            GetSigningKeys(DataSets.JsonWebKeySetBadRsaModulusString, null, ExpectedException.InvalidOperationException(substringExpected: "IDX10801:", inner: typeof(FormatException)));
            GetSigningKeys(DataSets.JsonWebKeySetKtyNotRsaString, null, ExpectedException.NoExceptionExpected);
            GetSigningKeys(DataSets.JsonWebKeySetUseNotSigString, null, ExpectedException.NoExceptionExpected);
            GetSigningKeys(DataSets.JsonWebKeySetBadX509String, null, ExpectedException.InvalidOperationException(substringExpected: "IDX10802:", inner: typeof(FormatException)));
        }

        private void GetSigningKeys(string webKeySetString, List<SecurityKey> expectedKeys, ExpectedException expectedException)
        {

            JsonWebKeySet webKeySet = new JsonWebKeySet(webKeySetString);
            try
            {
                IList<SecurityKey> keys = webKeySet.GetSigningKeys();
                expectedException.ProcessNoException();
                if (expectedKeys != null)
                {
                    Assert.True(IdentityComparer.AreEqual(keys, expectedKeys));
                }
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="compareTo"></param>
        /// <param name="expectedException"></param>
        /// <param name="asString"> this is useful when passing null for parameter 'is' and 'as' don't contain type info.</param>
        /// <returns></returns>
        private JsonWebKeySet RunJsonWebKeySetTest(object obj, JsonWebKeySet compareTo, ExpectedException expectedException, bool asString = true)
        {
            JsonWebKeySet jsonWebKeys = null;
            try
            {
                if (obj is string || asString)
                {
                    jsonWebKeys = new JsonWebKeySet(obj as string);
                }
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            if (compareTo != null)
            {
                Assert.True(IdentityComparer.AreEqual(jsonWebKeys, compareTo, CompareContext.Default), "jsonWebKeys created from: " + (obj == null ? "NULL" : obj.ToString() + " did not match expected."));
            }

            return jsonWebKeys;
        }

        [Fact(DisplayName = "JsonWebKeySetTests: Defaults")]
        public void Defaults()
        {
        }

        [Fact(DisplayName = "JsonWebKeySetTests: GetSets")]
        public void GetSets()
        {
        }

        [Fact(DisplayName = "JsonWebKeySetTests: Publics")]
        public void Publics()
        {
        }

        private bool IsDefaultJsonWebKeySet(JsonWebKeySet jsonWebKeys)
        {
            if (jsonWebKeys.Keys == null)
                return false;

            if (jsonWebKeys.Keys.Count != 0)
                return false;

            return true;
        }
    }
}
