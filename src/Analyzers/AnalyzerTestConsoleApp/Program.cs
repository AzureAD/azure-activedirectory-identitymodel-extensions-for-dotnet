// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.JsonWebTokens;

namespace AnalyzerTestConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            new Class1().Method(true, 5);

#pragma warning disable IDMODEL103 // Type shouldn't be used.
            var jwt = new JsonWebToken("");
#pragma warning restore IDMODEL103 // Type shouldn't be used.
        }
    }

    public class Class1
    {
        public void Method(bool flag, int value)
        {
            while (flag)
                if (value > 0)
                    Console.WriteLine(value);
        }
    }
}
