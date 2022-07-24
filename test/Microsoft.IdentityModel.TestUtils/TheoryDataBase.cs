// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.TestUtils
{
    /// <summary>
    /// Set defaults for TheoryData
    /// </summary>
    public class TheoryDataBase
    {
        public TheoryDataBase()
        {
            IdentityModelEventSource.ShowPII = true;
        }

        public TheoryDataBase(bool showPII)
        {
            IdentityModelEventSource.ShowPII = showPII;
        }

        public ExpectedException ExpectedException { get; set; } = ExpectedException.NoExceptionExpected;

        public bool First { get; set; } = false;

        public Dictionary<Type, List<string>> PropertiesToIgnoreWhenComparing { get; set; } = new Dictionary<Type, List<string>>();

        public string TestId { get; set; }

        public override string ToString()
        {
            return $"{TestId}, {ExpectedException}";
        }
    }
}
