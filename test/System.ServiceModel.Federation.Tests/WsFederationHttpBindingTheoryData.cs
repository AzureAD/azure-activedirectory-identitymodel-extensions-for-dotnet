// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.TestUtils;

namespace System.ServiceModel.Federation.Tests
{
    public class WsFederationHttpBindingTheoryData: TheoryDataBase
    {
        public SecurityKeyType KeyType { get; set; }
        public string RequestContext { get; set; }
        public string TokenType { get; set; }
    }
}
