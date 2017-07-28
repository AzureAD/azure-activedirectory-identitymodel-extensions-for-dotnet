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
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Tests
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
    /// Set defaults for TheoryData
    /// </summary>
    public class TheoryDataBase
    {
        public ExpectedException ExpectedException { get; set; } = ExpectedException.NoExceptionExpected;

        public bool First { get; set; } = false;

        public string TestId { get; set; }

        public override string ToString()
        {
            return $"{TestId}, {ExpectedException}";
        }
    }

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
            PropertyInfo[] propertyInfos = type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly);

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
                    throw new TestException(string.Format("Testcase: '{0}', type: '{1}', property: '{2}', exception: '{3}'", type, testcase ?? "testcase is null", propertyInfo.Name, ex));
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
            return fieldInfo.GetValue(obj);
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
            if (propertyInfo == null)
                throw new TestException("property is not found: " + property + ", type: " + type.ToString());

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
            if (strings == null)
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
            if (obj == null)
                throw new TestException("obj == null");

            if (string.IsNullOrWhiteSpace(property))
                throw new TestException("string.IsNullOrWhiteSpace(property)");

            Type type = obj.GetType();
            PropertyInfo propertyInfo = type.GetProperty(property);

            if (propertyInfo == null)
                throw new TestException("'get is not found for property: '" + property + "', type: '" + type.ToString() + "'");

            if (!propertyInfo.CanWrite)
                throw new TestException("can not write to property: '" + property + "', type: '" + type.ToString() + "'");

            try
            {
                propertyInfo.SetValue(obj, propertyValue);
                object retval = propertyInfo.GetValue(obj);
                if (!IdentityComparer.AreEqual(propertyValue, retval))
                    throw new TestException($"propertyValue != retval: '{propertyValue} : {retval}'");

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
            if (propertyInfo == null)
                throw new TestException("property is not found: " + property + ", type: " + type.ToString());

            object retval = propertyInfo.GetValue(obj);
            if (propertyInfo.CanWrite)
            {
                propertyInfo.SetValue(obj, propertyValue);
            }
            else
            {
                throw new TestException("property 'set' is not found: " + property + ", type: " + type.ToString());
            }
        }

        public static ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, ISecurityTokenValidator tokenValidator, ExpectedException expectedException)
        {
            ClaimsPrincipal retVal = null;
            try
            {
                retVal = tokenValidator.ValidateToken(securityToken, validationParameters, out SecurityToken validatedToken);
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
            if (!validationParameters.ValidateTokenReplay)
                return;

            TokenValidationParameters tvp = validationParameters.Clone();
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

        public static void AssertFailIfErrors(List<string> errors)
        {
            AssertFailIfErrors(null, errors);
        }

        public static void AssertFailIfErrors(CompareContext context)
        {
            AssertFailIfErrors(context.Title, context.Diffs);
        }

        public static void AssertFailIfErrors(string testId, List<string> errors)
        {
            if (errors.Count != 0)
            {
                StringBuilder sb = new StringBuilder();
                if (!string.IsNullOrEmpty(testId))
                {
                    sb.AppendLine(testId);
                    sb.AppendLine(Environment.NewLine);
                }

                foreach (string str in errors)
                    sb.AppendLine(str);

                throw new TestException(sb.ToString());
            }
        }

        public static byte[] HexToByteArray(string hexString)
        {
            byte[] bytes = new byte[hexString.Length / 2];

            for (int i = 0; i < hexString.Length; i += 2)
            {
                string s = hexString.Substring(i, 2);
                bytes[i / 2] = byte.Parse(s, NumberStyles.HexNumber, null);
            }

            return bytes;
        }

        public static void XORBytes(byte[] bytes)
        {
            for (int i=0; i < bytes.Length-1; i++)
            {
                bytes[i] = (byte)(bytes[i] ^ bytes[i + 1]);
            }
        }

        public static void TestHeader(string testcase, string variation, ref bool first)
        {
            TestHeader($"{testcase} : {variation}", ref first);
        }

        public static void TestHeader(string testcase, ref bool first)
        {
            if (first)
                Console.WriteLine("====================================");

            first = false;
            Console.WriteLine(">>>> " + testcase);
        }

        public static void WriteHeader(string testcase, string variation, bool first)
        {
            WriteHeader($"{testcase} : {variation}", first);
        }

        public static void WriteHeader(string testcase, TheoryDataBase theoryData)
        {
            WriteHeader($"{testcase} : {theoryData.TestId}", theoryData.First);
        }

        public static void WriteHeader(string testcase, bool first)
        {
            if (first)
                Console.WriteLine("====================================");

            Console.WriteLine(">>>> " + testcase);
        }
    }
}
