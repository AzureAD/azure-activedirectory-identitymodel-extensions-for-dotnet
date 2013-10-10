//----------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//----------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Configuration;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    /// 
    [Serializable]
    public class TestContextProvider
    {
        private const string DescriptionParameterName = "Description";
        private const string ObservationKey = "Observations";

        private const string MultipleParametersErrorString =
            @"At {0} we found Parameter {1} is passed through multiple places, 
            You should pass it either through TAEF or ETCM Environment or ETCM Parameter attributes";

        private TestContext _taefTestContext;

        private Dictionary<string, object> _customProperties;

        /// <summary>
        /// Constructor for the TestContext provider class, Initializes all the contexts.
        /// </summary>
        /// <param name="taefTestContext">TAEF test context.</param>
        public TestContextProvider( TestContext taefTestContext )
        {
            _taefTestContext = taefTestContext;
            _customProperties = new Dictionary<string, object>();
            _customProperties.Add("Observations", new List<object>());
        }

        /// <summary>
        /// List of observations collected during the test run.
        /// </summary>
        public List<object> Observations
        {
            get
            {
                return (List<object>)_customProperties[ObservationKey];
            }
        }

        /// <summary>
        /// Set a custom property that will be used for AcsTestContext
        /// </summary>
        public void SetCustomProperty(string name, object value)
        {
            if (_customProperties.ContainsKey(name))
            {
                _customProperties.Remove(name);
            }

            _customProperties.Add(name, value);
        }

        /// <summary>
        /// Extract enum from context.
        /// </summary>
        public TEnum GetEnum<TEnum>(string propertyName, TEnum defaultValue)
        {
            string propertyValue = this.GetValue<string>(propertyName);

            if (null == propertyValue)
            {
                return defaultValue;
            }

            return (TEnum)Enum.Parse(typeof(TEnum), propertyValue, true);
        }

        /// <summary>
        /// Retrvies the value for the property from the Test context.
        /// </summary>
        /// <param name="propertyName">Name of the property whose value should be retrived.</param>
        /// <returns>returns the object corresponding to the property name.</returns>
        public TValue GetValue<TValue>(string propertyName)
        {
            return GetValue<TValue>(propertyName, default(TValue));
        }

        /// <summary>
        /// Retrvies the value for the property from the Test context.
        /// </summary>
        /// <param name="propertyName">Name of the property whose value should be retrived.</param>
        /// <param name="defaultValue">default value of the property.</param>
        /// <returns>returns the object correspoonding to the property name.</returns>
        public TValue GetValue<TValue>(string propertyName, TValue defaultValue)
        {
            TValue retVal = default(TValue);
            bool retValSet = false;

            if (_customProperties.ContainsKey(propertyName))
            {
                return (TValue)_customProperties[propertyName];
            }

            if (_taefTestContext != null)
            {
                // Try to read from the TAEF command line arguments.
                if (_taefTestContext.Properties.Contains(propertyName) == true)
                {
                    retVal = ConvertParameter<TValue>(_taefTestContext.Properties[propertyName]);
                    retValSet |= true;
                }

                // Try to read from the TAEF data driven test parameters.
                if (_taefTestContext.DataRow != null && _taefTestContext.DataRow.Table.Columns.Contains(propertyName) == true &&
                   _taefTestContext.DataRow[propertyName] != DBNull.Value)
                {
                    Assert.IsFalse(retValSet, string.Format(MultipleParametersErrorString, "reading from TAEF Context", propertyName));

                    retVal = ConvertParameter<TValue>(_taefTestContext.DataRow[propertyName]);
                    retValSet |= true;
                }
            }

            if (retValSet)
            {
                return retVal;
            }
            else
            {
                // Use the default value if nothing works out.
                return defaultValue;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="variableName"></param>
        /// <returns></returns>
        public string GetValueFromEnvironmentVariable(string variableName)
        {
            return Environment.GetEnvironmentVariable(variableName);
        }

        /// <summary>
        /// Returns the config value for the particular config key from the application configuration file.
        /// </summary>
        /// <param name="configKey">Configuration key.</param>
        /// <returns>Return the configuration value;</returns>
        public string GetValueFromConfig(string configKey)
        {
            return ConfigurationManager.AppSettings[configKey];
        }

        /// <summary>
        /// Checks if value is available from context.
        /// </summary>
        /// <param name="key">Key in dictionary.</param>
        /// <param name="values">Table of values expected</param>
        /// <returns>True if one of values is in the context</returns>
        public bool HasValue<T>(string key, params T[] values)
        {
            foreach (T value in values)
            {
                T result = this.GetValue<T>(key, default(T));

                if (result == null && value == null)
                {
                    return true;
                }

                if (result != null && result.Equals(value))
                {
                    return true;
                }
            }

            return false;
        }

        private TValue ConvertParameter<TValue>(object value)
        {
            if (value is string)
            {
                return ConvertStringParameter<TValue>((string)value);
            }
            else
            {
                return (TValue)value;
            }
        }

        private TValue ConvertStringParameter<TValue>(string valueString)
        {
            Type parameterType = typeof(TValue);
            if (parameterType == typeof(string))
            {
                return (TValue)(object)valueString;
            }
            else if (parameterType == typeof(int))
            {
                return (TValue)(object)int.Parse(valueString);
            }
            else if (parameterType == typeof(TimeSpan))
            {
                return (TValue)(object)TimeSpan.Parse(valueString);
            }
            else if (parameterType == typeof(bool))
            {
                return (TValue)(object)bool.Parse(valueString);
            }
            else if (parameterType == typeof(double))
            {
                return (TValue)(object)double.Parse(valueString);
            }
            else
            {
                throw new NotSupportedException(
                    string.Format("The parameter type '{0}' is not supported.", parameterType.FullName));
            }
        }
    }
}
