using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using Microsoft.IdentityModel.Logging;

namespace AsyncWebsite
{
    public class MvcApplication : System.Web.HttpApplication
    {
        public const string SiteName = "AsyncWebsite";

        protected void Application_OnStart()
        {
        }

        protected void Application_Start()
        {
            IdentityModelEventSource.ShowPII = true;
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }
    }
}
