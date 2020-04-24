// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.IdentityModel.TestUtils;

namespace System.ServiceModel.Federation.Tests
{
    public class MessageSecurityVersionTheoryData : TheoryDataBase
    {
        public MessageSecurityVersion IssuerBindingSecurityVersion { get; set; }

        public MessageSecurityVersion OuterBindingSecurityVersion { get; set; }

        public MessageSecurityVersion ExpectedMessageSecurityVersion { get; set; }
    }
}
