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
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using Xunit;

namespace System.IdentityModel.Test
{
    public class GetSetContext
    {
        private List<string> _errors = new List<string>();
        private List<KeyValuePair<string, List<object>>> _propertyNamesAndSetGetValues;

        public List<string> Errors { get { return _errors; } }

        public List<KeyValuePair<string, List<object>>> PropertyNamesAndSetGetValue { get { return _propertyNamesAndSetGetValues; } set { _propertyNamesAndSetGetValues = value; } }

        public object Object { get; set; }
    }

    public class TokenReplayCache : ITokenReplayCache
    {
        public bool OnAddReturnValue { get; set; }
        
        public bool OnFindReturnValue { get; set; }

        public bool TryAdd(string nonce, DateTime expiresAt)
        {
            return OnAddReturnValue;
        }

        public bool TryFind(string nonce)
        {
            return OnFindReturnValue;
        }
    }

    /// <summary>
    /// Mixed bag of funtionality:
    ///     Generically calling Properties
    /// </summary>
    public static class TestUtilities
    {
        /// <summary>
        /// Calls all public instance and static properties on an object
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="testcase">contains info about the current test case</param>
        public static void CallAllPublicInstanceAndStaticPropertyGets(object obj, string testcase)
        {
            if (obj == null)
            {
                Console.WriteLine(string.Format("Entering: '{0}', obj is null, have to return.  Is the Testcase: '{1}' right?", "CallAllPublicInstanceAndStaticPropertyGets", testcase ?? "testcase is null"));
                return;
            }

            Type type = obj.GetType();

            // call get all public static properties of MyClass type
            PropertyInfo[] propertyInfos = type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static);

            // Touch each public property
            foreach (PropertyInfo propertyInfo in propertyInfos)
            {
                try
                {
                    if (propertyInfo.GetMethod != null)
                    {
                        object retval = propertyInfo.GetValue(obj, null);
                    }
                }
                catch (Exception ex)
                {
                    Assert.True(false, string.Format("Testcase: '{0}', type: '{1}', property: '{2}', exception: '{3}'", type, testcase ?? "testcase is null", propertyInfo.Name, ex));
                }
            }
        }

        /// <summary>
        /// Gets a named field on an object
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="field"></param>
        public static object GetField(object obj, string field)
        {
            Type type = obj.GetType();
            FieldInfo fieldInfo = type.GetField(field, BindingFlags.NonPublic | BindingFlags.Instance);
            return  fieldInfo.GetValue(obj);
        }

        /// <summary>
        /// Sets a named field on an object
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="field"></param>
        public static void SetField(object obj, string field, object fieldValue)
        {
            Type type = obj.GetType();
            FieldInfo fieldInfo = type.GetField(field, BindingFlags.NonPublic | BindingFlags.Instance);
            fieldInfo.SetValue(obj, fieldValue);
        }

        /// <summary>
        /// Gets a named property on an object
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="property"></param>
        /// <param name="propertyValue"></param>
        public static object GetProperty(object obj, string property)
        {
            Type type = obj.GetType();
            PropertyInfo propertyInfo = type.GetProperty(property);

            Assert.True(propertyInfo != null, "property is not found: " + property + ", type: " + type.ToString());

            return propertyInfo.GetValue(obj);
        }

        /// <summary>
        /// Checks initial value, sets and then checks value. Works with multiple properties.
        /// </summary>
        /// <param name="context"> <see cref="GetSetContext"/>, drives the test.</param>
        public static void GetSet(GetSetContext context)
        {
            Type type = context.Object.GetType();

            foreach (KeyValuePair<string, List<object>> propertyKV in context.PropertyNamesAndSetGetValue)
            {
                PropertyInfo propertyInfo = type.GetProperty(propertyKV.Key);
                try
                {
                    if (propertyInfo.GetMethod != null)
                    {
                        object initialValue = propertyInfo.GetValue(context.Object, null);
                        if ((initialValue == null && propertyKV.Value[0] != null))
                        {
                            context.Errors.Add(propertyKV.Key + ": initial value == null && expected != null, expect initial value: " + propertyKV.Value[0].ToString());
                        }
                        else if (initialValue != null && propertyKV.Value[0] == null)
                        {
                            context.Errors.Add(propertyKV.Key + ": initial value != null && expected == null, initial value: " + initialValue.ToString());
                        }
                        else if (initialValue != null && !initialValue.Equals(propertyKV.Value[0]))
                        {
                            context.Errors.Add(propertyKV.Key + ", initial value != expected. expected: " + propertyKV.Value[0].ToString() + ", was: " + initialValue.ToString());
                        }
                    }

                    if (propertyInfo.SetMethod != null)
                    {
                        for (int i = 1; i < propertyKV.Value.Count; i++)
                        {
                            propertyInfo.SetValue(context.Object, propertyKV.Value[i]);
                            object getVal = propertyInfo.GetValue(context.Object, null);
                            if ((getVal == null && propertyKV.Value[i] != null))
                            {
                                context.Errors.Add(propertyKV.Key + "( " + i.ToString() + "), Get returned null, set was: " + propertyKV.Value[i].ToString());
                            }
                            else if (getVal != null && propertyKV.Value[i] == null)
                            {
                                context.Errors.Add(propertyKV.Key + "( " + i.ToString() + "), Get not null, set was null, get was: " + getVal);
                            }
                            else if (getVal != null && !getVal.Equals(propertyKV.Value[i]))
                            {
                                context.Errors.Add(propertyKV.Key + "( " + i.ToString() + ") Set did not equal get: " + propertyKV.Value[i].ToString() + ", " + getVal + ".");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    context.Errors.Add(ex.ToString());
                }
            }
        }

        /// <summary>
        /// Gets and sets a named property on an object. Checks: initial value.
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="property"></param>
        /// <param name="initialPropertyValue"></param>
        /// <param name="setPropertyValue"></param>
        public static void GetSet(object obj, string property, object initialPropertyValue, object[] setPropertyValues, List<string> errors)
        {
            Type type = obj.GetType();
            PropertyInfo propertyInfo = type.GetProperty(property);

            if (propertyInfo == null)
            {
                errors.Add("property get is not found: " + property + ", type: " + type.ToString());
                return;
            }

            object retval = propertyInfo.GetValue(obj);
            if (initialPropertyValue != retval)
            {
                errors.Add("initialPropertyValue != retval: " + initialPropertyValue + " , " + retval);
                return;
            }

            if (propertyInfo.CanWrite)
            {
                foreach (object propertyValue in setPropertyValues)
                {
                    propertyInfo.SetValue(obj, propertyValue);
                    retval = propertyInfo.GetValue(obj);
                    if (propertyValue != retval)
                    {
                        errors.Add("propertyValue != retval: " + propertyValue + " , " + retval);
                    }
                }
            }
        }

        public static string SerializeAsSingleCommaDelimitedString(IEnumerable<string> strings)
        {
            if (null == strings)
            {
                return "null";
            }

            StringBuilder sb = new StringBuilder();
            bool first = true;
            foreach (string str in strings)
            {
                if (first)
                {
                    sb.AppendFormat("{0}", str ?? "null");
                    first = false;
                }
                else
                {
                    sb.AppendFormat(", {0}", str ?? "null");
                }
            }

            if (first)
            {
                return "empty";
            }

            return sb.ToString();
        }

        /// <summary>
        /// Sets a property, then checks it, checking for an expected exception.
        /// </summary>
        /// <param name="obj">object that has a 'setter'.</param>
        /// <param name="property">the name of the property.</param>
        /// <param name="propertyValue">value to set on the property.</param>
        /// <param name="expectedException">checks that exception is correct.</param>
        public static void SetGet(object obj, string property, object propertyValue, ExpectedException expectedException)
        {
            Assert.NotNull(obj);
            Assert.False(string.IsNullOrWhiteSpace(property));

            Type type = obj.GetType();
            PropertyInfo propertyInfo = type.GetProperty(property);

            Assert.True(propertyInfo != null, "'get is not found for property: '" + property + "', type: '" + type.ToString() + "'");
            Assert.True(propertyInfo.CanWrite, "can not write to property: '" + property + "', type: '" + type.ToString() + "'");

            try
            {
                propertyInfo.SetValue(obj, propertyValue);
                object retval = propertyInfo.GetValue(obj);
                Assert.Equal(propertyValue, retval);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                // pass inner exception
                expectedException.ProcessException(exception.InnerException);
            }
        }

        /// <summary>
        /// Set a named property on an object
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="property"></param>
        /// <param name="propertyValue"></param>
        public static void SetProperty(object obj, string property, object propertyValue)
        {
            Type type = obj.GetType();
            PropertyInfo propertyInfo = type.GetProperty(property);

            Assert.True(propertyInfo != null, "property is not found: " + property + ", type: " + type.ToString());

            object retval = propertyInfo.GetValue(obj);
            if (propertyInfo.CanWrite)
            {
                propertyInfo.SetValue(obj, propertyValue);
            }
            else
            {
                Assert.True(false, "property 'set' is not found: " + property + ", type: " + type.ToString());
            }
        }
  
        public static ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, ISecurityTokenValidator tokenValidator, ExpectedException expectedException)
        {
            ClaimsPrincipal retVal = null;
            try
            {
                SecurityToken validatedToken;
                retVal = tokenValidator.ValidateToken(securityToken, validationParameters, out validatedToken);
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            return retVal;
        }

        public static void ValidateTokenReplay(string securityToken, ISecurityTokenValidator tokenValidator, TokenValidationParameters validationParameters)
        {
            TokenValidationParameters tvp = validationParameters.Clone() as TokenValidationParameters;
            TokenReplayCache replayCache =
               new TokenReplayCache()
               {
                   OnAddReturnValue = true,
                   OnFindReturnValue = false,
               };

            tvp.TokenReplayCache = replayCache;
            TestUtilities.ValidateToken(securityToken, tvp, tokenValidator, ExpectedException.NoExceptionExpected);

            replayCache.OnFindReturnValue = true;
            TestUtilities.ValidateToken(securityToken, tvp, tokenValidator, ExpectedException.SecurityTokenReplayDetected());

            replayCache.OnFindReturnValue = false;
            replayCache.OnAddReturnValue = false;
            TestUtilities.ValidateToken(securityToken, tvp, tokenValidator, ExpectedException.SecurityTokenReplayAddFailed());
        }

        public static void AssertEqual(string testid, object obj1, object obj2,  Func<object, object, CompareContext, bool> areEqual, CompareContext cc)
        {
            areEqual(obj1, obj2, cc);
        }

        public static void AssertFailIfErrors(string testId, List<string> errors)
        {
            if (errors.Count != 0)
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine(testId);
                sb.AppendLine(Environment.NewLine);
                foreach (string str in errors)
                    sb.AppendLine(str);

                Assert.True(false, sb.ToString());
            }
        }
    }
}