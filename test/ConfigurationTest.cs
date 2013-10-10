//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.IdentityModel.Configuration;
using System.Reflection;

namespace System.IdentityModel.Test
{
    public abstract class ConfigurationTest : RemoteDomainManager
    {
        const string CommonConfigurationHeader = @"
                <configuration>
                    <configSections>
                        <section name='system.identityModel' type='System.IdentityModel.Configuration.SystemIdentityModelSection, System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=B77A5C561934E089' />
                    </configSections>";

        const string CommonConfigurationFooter = @"
                </configuration>";

        // derived tests use these two hook points to produce config and validate test
        protected virtual string GetConfiguration( string testCase ) { throw new NotImplementedException( "need to implement " ); }
        protected virtual string GetConfiguration() { throw new NotImplementedException( "need to implement " ); }

        protected abstract void ValidateTestCase( string testCase );

        public virtual void RunTestCase( string testCase )
        {
            Type remoteDomainType = typeof( RemoteDomain<> ).MakeGenericType( new Type[] { this.GetType() } );

            PropertyInfo domainManagerPropertyInfo = remoteDomainType.GetProperty( "DomainManager" );

            string configuration = GetConfiguration( testCase );

            object remoteDomain = null;
            try
            {
                remoteDomain = Activator.CreateInstance( remoteDomainType, this.GetType().ToString(), CommonConfigurationHeader + configuration + CommonConfigurationFooter );
                RemoteDomainManager domainManager = (RemoteDomainManager)domainManagerPropertyInfo.GetValue( remoteDomain, null );
                domainManager.Start( testCase );
            }
            finally
            {
                if ( null != remoteDomain )
                {
                    ( (IDisposable)remoteDomain ).Dispose();
                }
            }
        }

        public sealed override void Start(string testCase)
        {
            // touches the config to force config exceptions out before constructing anything else.
            try
            {
                var unused = SystemIdentityModelSection.Current;
            }
            catch ( Exception )
            {
            }

            ValidateTestCase( testCase );
        }

        public sealed override void Stop()
        {
        }

        public sealed override void TearDown()
        {
        }
    }
}