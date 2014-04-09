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

using System.CodeDom.Compiler;
using System.Diagnostics;
using System.IO;
using System.Security.Policy;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// This whole remote domain is about loading config using .Net into an application space to 
    /// test different configuration variations.
    /// </summary>
    public class RemoteDomain<T> : IDisposable where T : RemoteDomainManager
    {
        internal static bool KeepConfigFile = false;

        AppDomain           _domain;
        T                   _domainManager;
        TempFileCollection  _tempFileCollection;

        /// <summary>
        /// Creates a new AppDomain loaded with the configuration data specified.
        /// </summary>
        /// <param name="domainName">The name of the app domain created.</param>
        /// <param name="configContents">The xml contents of the configuration the new AppDomain should be loaded with.</param>
        public RemoteDomain( string domainName, string configContents )
        {
            //
            // Spin off a new appdomain.
            //
            _domain = CreateDomain( domainName, configContents );
            //
            // Acquire a reference to a new service manager 
            // running in the appdomain.
            //
            _domainManager = CreateDomainManager();
        }

        ~RemoteDomain()
        {
            Dispose( false );
        }

        private AppDomain CreateDomain( string domainName, string configContents )
        {
            Debug.Assert( domainName != null && domainName.Length > 0 );

            //
            // Make our configuration file
            //
            string configFileName = CreateTemporaryFile( "config", configContents );
            //
            // Figure out what the app base should be.
            //
            string appBase        = AppDomain.CurrentDomain.BaseDirectory;
            string relativeSearch = AppDomain.CurrentDomain.RelativeSearchPath;

            Evidence baseEvidence = AppDomain.CurrentDomain.Evidence;
            Evidence evidence     = new Evidence( baseEvidence );

            AppDomainSetup setup = new AppDomainSetup();

            setup.ApplicationName   = "Te";
            setup.ConfigurationFile = configFileName;
            setup.ApplicationBase   = appBase;
            setup.PrivateBinPath    = relativeSearch;

            AppDomain serviceDomain = AppDomain.CreateDomain( domainName, evidence, setup );

            return serviceDomain;
        }

        protected virtual T CreateDomainManager()
        {
            //
            // Acquire a reference to a new service manager 
            // running in the appdomain.
            //
            return RemoteDomainManager.CreateInDomain<T>( _domain );
        }

        /// <summary>
        /// Creates a temporary file with the provided contents.
        /// </summary>
        /// <param name="extension">The file extension requested</param>
        /// <param name="contents">Data containing the contents of the requested file.</param>
        /// <returns>A full path name to the newly created file.</returns>
        private string CreateTemporaryFile( string extension, string contents )
        {
            Debug.Assert( extension != null && extension.Length > 0 );

            if ( _tempFileCollection == null )
                _tempFileCollection = new TempFileCollection();

            //
            // Create the temp file.
            //
            string fileName = _tempFileCollection.AddExtension( extension, KeepConfigFile );

            //
            // Populate the file.
            //
            if ( contents != null )
            {
                using ( StreamWriter sw = new StreamWriter( fileName, false ) )
                {
                    sw.Write( contents );
                }
            }

            return fileName;
        }

        /// <summary>
        /// The AppDomain containing the web service.
        /// </summary>
        public AppDomain Domain
        {
            get { return _domain; }
        }

        /// <summary>
        /// A reference to a service manager running
        /// in the web service AppDomain.
        /// </summary>
        public T DomainManager
        {
            get { return _domainManager; }
        }

        #region IDisposable

        public void Dispose()
        {
            Dispose( true );
            GC.SuppressFinalize( this );
        }

        protected virtual void Dispose( bool isDisposing )
        {
            if ( isDisposing )
            {
                if ( _domain != null )
                {
                    try
                    {
                        if ( _domainManager != null )
                            _domainManager.TearDown();

                        AppDomain.Unload( _domain );
                    }
                    catch ( CannotUnloadAppDomainException )
                    {
                        //
                        // Don't do anything about this for now.
                        //
                    }
                    finally
                    {
                        _domain = null;
                    }
                }

                if ( _tempFileCollection != null )
                {
                    _tempFileCollection.Delete();
                    _tempFileCollection = null;
                }
            }
        }

        #endregion

    }
}
