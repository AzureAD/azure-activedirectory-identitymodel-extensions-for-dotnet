// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

namespace System.IdentityModel.Test
{
    /// <summary>
    /// Part of the machinery for simulating loading config from web.config
    /// </summary>
    [Serializable]
    public abstract class RemoteDomainManager : MarshalByRefObject
    {
        public static T CreateInDomain<T>( AppDomain domain )
        {
            return (T)domain.CreateInstanceAndUnwrap( typeof( T ).Assembly.FullName, typeof( T ).FullName );
        }

        public abstract void Start( string testCase );
        public abstract void Stop();
        public abstract void TearDown();
    }
}
