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
using System.Threading;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.Tests
{
    /// <summary>
    /// Tests for FileDocumentRetriever.cs
    /// </summary>
    public class FileDocumentRetrieverTests
    {
        private void GetDocument(string address, IDocumentRetriever docRetriever, CancellationToken token, ExpectedException ee)
        {
            try
            {
                string doc = docRetriever.GetDocumentAsync(address, token).Result;
                ee.ProcessNoException();
            }
            catch (AggregateException ex)
            {
                ex.Handle((x) =>
                {
                    ee.ProcessException(x);
                    return true;
                });
            }
        }

        [Fact]
        public void GetDocuments()
        {
            FileDocumentRetriever docRetriever = new FileDocumentRetriever();
            GetDocument(null, docRetriever, CancellationToken.None, ExpectedException.ArgumentNullException());
            GetDocument("OpenIdConnectMetadata.json", docRetriever, CancellationToken.None, ExpectedException.IOException("IDX10804:", typeof(FileNotFoundException), "IDX10814:"));
            GetDocument("ValidJson.json", docRetriever, CancellationToken.None, ExpectedException.NoExceptionExpected);
        }
    }
}
