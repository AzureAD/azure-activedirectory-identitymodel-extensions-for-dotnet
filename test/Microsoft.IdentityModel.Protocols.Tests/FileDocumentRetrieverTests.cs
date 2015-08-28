//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System;
using System.IdentityModel.Tokens.Tests;
using System.Threading;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.Tests
{
    /// <summary>
    /// Tests for FileDocumentRetriever.cs
    /// </summary>
    public class FileDocumentRetrieverTests
    {
        private void GetDocument(string address, IDocumentRetriever docRetriever, ExpectedException ee)
        {
            try
            {
                string doc = docRetriever.GetDocumentAsync(address, CancellationToken.None).Result;
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

        [Fact(DisplayName = "FileDocumentRetrieverTests: Publics")]
        public void Publics()
        {
            FileDocumentRetriever docRetriever = new FileDocumentRetriever();
            GetDocument(null, docRetriever, ExpectedException.ArgumentNullException());
            GetDocument("OpenIdConnectMetadata.json", docRetriever, ExpectedException.IOException("IDX10804:", typeof(ArgumentException), "IDX10814:"));
            GetDocument("project.json", docRetriever, ExpectedException.NoExceptionExpected);
        }
    }
}