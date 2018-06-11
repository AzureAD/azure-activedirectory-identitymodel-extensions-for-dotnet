using System;
using System.Security.Cryptography.X509Certificates;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using Microsoft.IdentityModel.Logging;

namespace AsyncWebsite
{
    public class WebApiApplication : System.Web.HttpApplication
    {
        // constants related to this site: AsyncWebsite
        public const string Address    = "http://localhost:39273/";
        public const string Authority  = "https://testingsts.azurewebsites.net/";
        public const string Audience1  = "http://AsyncWebsite";
        public const string Audience2  = "http://AsyncWebsite/";
        public const string ClientId = "api-001";
        //public const string ClientId = "2d149917-123d-4ba3-8774-327b875f5540";
        public const string Endpoint   = Address + @"api/AccessTokenProtected/ProtectedApi";
        public const string SiteName   = "AsyncWebsite";
        public const string Tennant    = "add29489-7269-41f4-8841-b63c95564420";
        public const string Thumbprint = "8BDD5C76F165FA88C5A73E978D0522C47F934C90";

        // Outbound policy names
        public const string AppAssertedUserV1Policy = "AppAssertedUserV1Policy";
        public const string AppTokenPolicy = "AppTokenPolicy";
        public const string AccessTokenPolicy = "AccessTokenPolicy";
        public const string ServiceAssertedV1Policy = "ServiceAssertedV1Policy";

        // S2SBackend metadata
        public const string BackendAddress  = "http://localhost:39274/";
        public const string BackendEndpoint = BackendAddress + "api/S2STokenProtected/S2SProtectedCall";
        public const string BackendAppId = "http://S2SBackend";

        protected void Application_Start()
        {
            IdentityModelEventSource.ShowPII = true;
            AreaRegistration.RegisterAllAreas();
            GlobalConfiguration.Configure(WebApiConfig.Register);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }

        public static X509Certificate2 FindCertificate(StoreLocation storeLocation, StoreName storeName, string thumbprint)
        {
            X509Store x509Store = new X509Store(storeName, storeLocation);
            x509Store.Open(OpenFlags.ReadOnly);
            try
            {
                foreach (var cert in x509Store.Certificates)
                {
                    if (cert.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        return cert;
                    }
                }

                throw new ArgumentException(
                    string.Format("AsyncWebsite communicates with AzureAD using a Certificate with thumbprint: '{0}'. SAL_SDK includes '<ROOT>\\src\\Certs\\AsyncWebsite.pfx' that needs to be imported into 'LocalComputer\\Personal' (password is: AsyncWebsite).{1}'<ROOT>\\src\\ToolsAndScripts\\AddPfxToCertStore.ps1' can be used install certs.{1}Make sure to open the powershell window as an administrator.", 
                        thumbprint,
                        Environment.NewLine));
            }
            finally
            {
                if (x509Store != null)
                {
                    x509Store.Close();
                }
            }
        }
    }
}
