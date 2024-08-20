// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Benchmarks;

Console.WriteLine("Hello, World!");

var test = new ValidateTokenAsyncWithVPTests();
test.Setup();

var list = new List<int>();
Console.WriteLine("Size of list: " + list.Capacity);

for (int i = 0; i < 1000; i++)
{
    await test.JsonWebTokenHandler_03_ValidateTokenAsyncWithVP();
}
