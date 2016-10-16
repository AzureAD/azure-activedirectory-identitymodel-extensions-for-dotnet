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

using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    /// <summary>
    /// Contains theory data shared between different tests
    /// </summary>
    public static class JwtTestData
    {
        public static TheoryData<string, string, ExpectedException> ValidEncodedSegmentsData()
        {
            string[] tokenParts = EncodedJwts.Asymmetric_LocalSts.Split('.');
            var dataSet = new TheoryData<string, string, ExpectedException>();

            dataSet.Add(
                "Test1",
                EncodedJwts.OverClaims,
                ExpectedException.NoExceptionExpected
            );

            dataSet.Add(
                "Test2",
                string.Format("{0}.{1}.", tokenParts[0], tokenParts[1]),
                ExpectedException.NoExceptionExpected
            );

            dataSet.Add(
                "Test3",
                EncodedJwts.Asymmetric_LocalSts,
                ExpectedException.NoExceptionExpected
            );

            return dataSet;
        }

        public static TheoryData<string, string, ExpectedException> InvalidNumberOfSegmentsData(string errorString)
        {
            var dataSet = new TheoryData<string, string, ExpectedException>();

            dataSet.Add(
                "Test1",
                null,
                ExpectedException.ArgumentNullException()
            );

            dataSet.Add(
                "Test2",
                "",
                ExpectedException.ArgumentNullException()
            );

            dataSet.Add(
                "Test3",
                "a",
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test4",
                "a.b",
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test5",
                "a.b.c.d",
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test6",
                "a.b.c.d.e.f",
                ExpectedException.ArgumentException(errorString)
            );

            return dataSet;
        }

        public static TheoryData<string, string, ExpectedException> InvalidRegExSegmentsData(string errorString)
        {
            var validRegEx = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9";
            var invalidRegEx = "eyJpc3MiOiJodHRwOi8vR290Snd0LmNvbSIsImF1Z CI6Imh0";
            var dataSet = new TheoryData<string, string, ExpectedException>();

            dataSet.Add(
                "Test1",
                invalidRegEx + "." + validRegEx + "." + validRegEx + "." + validRegEx + "." + validRegEx,
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test2",
                validRegEx + "." + invalidRegEx + "." + validRegEx + "." + validRegEx + "." + validRegEx,
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test3",
                validRegEx + "." + validRegEx + "." + invalidRegEx + "." + validRegEx + "." + validRegEx,
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test4",
                validRegEx + "." + validRegEx + "." + validRegEx + "." + invalidRegEx + "." + validRegEx,
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test5",
                validRegEx + "." + validRegEx + "." + validRegEx + "." + validRegEx + "." + invalidRegEx,
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test6",
                invalidRegEx + ".." + validRegEx + "." + validRegEx + "." + validRegEx,
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test7",
                validRegEx + ".." + invalidRegEx + "." + validRegEx + "." + validRegEx,
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test8",
                invalidRegEx + ".." + validRegEx + "." + invalidRegEx + "." + validRegEx,
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test9",
                invalidRegEx + ".." + validRegEx + "." + validRegEx + "." + invalidRegEx,
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test10",
                invalidRegEx + "." + validRegEx + "." + validRegEx,
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test11",
                validRegEx + "." + invalidRegEx + "." + validRegEx,
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test12",
                validRegEx + "." + invalidRegEx + ".",
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test13",
                validRegEx + "." + validRegEx + "." + invalidRegEx,
                ExpectedException.ArgumentException(errorString)
            );

            dataSet.Add(
                "Test14",
                "SignedEncodedJwts.Asymmetric_LocalSts",
                ExpectedException.ArgumentException(errorString)
            );

            return dataSet;
        }

        public static TheoryData<string, string, ExpectedException> InvalidEncodedSegmentsData(string errorString)
        {
            var dataSet = new TheoryData<string, string, ExpectedException>();

            dataSet.Add(
                "Test1",
                EncodedJwts.InvalidPayload,
                ExpectedException.ArgumentException(substringExpected: "IDX10723:", inner: typeof(FormatException))
            );

            return dataSet;
        }
    }
}
