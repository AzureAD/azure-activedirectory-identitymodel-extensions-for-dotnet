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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Xml;
using SamlSecurityTokenHandler = Microsoft.IdentityModel.Extensions.SamlSecurityTokenHandler;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// Mixed bag of funtionality:
    ///     Generically calling Properties
    /// </summary>
    public static class TestUtilities
    {
        /// <summary>
        /// Gets and sets a named property on an object. Checks: initial value.
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="property"></param>
        /// <param name="initialPropertyValue"></param>
        /// <param name="setPropertyValue"></param>
        public static void GetSet(object obj, string property, object initialPropertyValue, object[] setPropertyValues)
        {
            Type type = obj.GetType();
            PropertyInfo propertyInfo = type.GetProperty(property);

            Assert.IsNotNull(propertyInfo, "property get is not found: " + property + ", type: " + type.ToString());

            object retval = propertyInfo.GetValue(obj);
            Assert.IsTrue(initialPropertyValue == retval);

            if (propertyInfo.CanWrite)
            {
                foreach (object propertyValue in setPropertyValues)
                {
                    propertyInfo.SetValue(obj, propertyValue);
                    retval = propertyInfo.GetValue(obj);
                    Assert.IsTrue(propertyValue == retval);
                }
            }
        }

        /// <summary>
        /// Gets and sets a named property on an object.
        /// </summary>
        /// <param name="obj">object that has 'get' and 'set'.</param>
        /// <param name="property">the name of the property.</param>
        /// <param name="propertyValue">value to set on the property.</param>
        /// <param name="exceptionProcessor">checks that exception is correct.</param>
        public static void GetSet(object obj, string property, object propertyValue, ExceptionProcessor exceptionProcessor)
        {
            Assert.IsNotNull(obj, "'obj' can not be null");
            Assert.IsFalse(string.IsNullOrWhiteSpace(property), "'property' can not be null or whitespace");

            Type type = obj.GetType();
            PropertyInfo propertyInfo = type.GetProperty(property);

            Assert.IsNotNull(propertyInfo, "'get is not found for property: '" + property + "', type: '" + type.ToString() + "'");
            Assert.IsTrue(propertyInfo.CanWrite, "can not write to property: '" + property + "', type: '" + type.ToString() + "'");

            try
            {
                propertyInfo.SetValue(obj, propertyValue);
                object retval = propertyInfo.GetValue(obj);
                Assert.IsTrue(propertyValue == retval);
                exceptionProcessor.ProcessNoException();
            }
            catch (Exception exception)
            {
                // pass inner exception
                exceptionProcessor.ProcessException(exception.InnerException);
            }
        }
    }
}