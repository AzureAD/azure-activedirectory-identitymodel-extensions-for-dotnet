// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Reflection;

namespace System.ServiceModel.Federation.Tests
{
    public static class ReflectionHelpers
    {
        public static object GetInternalProperty(object obj, string propertyName) =>
            obj.GetType()
            .GetProperty(propertyName, BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)?
            .GetValue(obj);

        public static object CallInternalMethod(object obj, string methodName, params object[] args) =>
            obj.GetType()
            .GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance)?
            .Invoke(obj, args);
    }
}
