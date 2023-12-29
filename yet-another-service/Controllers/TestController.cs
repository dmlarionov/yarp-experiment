using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace YetAnotherService.Controllers
{
    public class TestController : Controller
    {
        private const string RequestCountKey = "RequestCount";

        // GET: /<controller>/
        public IActionResult Index()
        {
            return Json(new
            {
                About = "This method is accessible by anyone.",
                RequestMadeBy = new
                {
                    UserName = HttpContext.User.Identity?.Name ?? "Unknown",
                    IsInPowerRole = HttpContext.User.IsInRole("power")
                },
                RequestCount = RequestCount()
            });
        }

        [Authorize]
        public IActionResult Authorized()
        {
            return Json(new
            {
                About = "This method is accessible only by authorized users.",
                RequestMadeBy = new
                {
                    UserName = HttpContext.User.Identity?.Name ?? "Unknown",
                    IsInPowerRole = HttpContext.User.IsInRole("power")
                },
                RequestCount = RequestCount()
            });
        }

        [Authorize(Roles = "power")]
        public IActionResult Power1()
        {
            return Json(new
            {
                About = "This method is accessible only by 'power' role members. It is protected with [Authorize(Roles = \"power\")].",
                RequestMadeBy = new
                {
                    UserName = HttpContext.User.Identity?.Name ?? "Unknown",
                    IsInPowerRole = HttpContext.User.IsInRole("power")
                },
                RequestCount = RequestCount()
            });
        }

        [Authorize(Policy = "powerpolicy")]
        public IActionResult Power2()
        {
            return Json(new
            {
                About = "This method is accessible only by 'power' role members. It is protected with [Authorize(Policy = \"powerpolicy\")].",
                RequestMadeBy = new
                {
                    UserName = HttpContext.User.Identity?.Name ?? "Unknown",
                    IsInPowerRole = HttpContext.User.IsInRole("power")
                },
                RequestCount = RequestCount()
            });
        }

        private int RequestCount()
        {
            var requestCount = (HttpContext.Session.GetInt32(RequestCountKey) ?? 0) + 1;
            HttpContext.Session.SetInt32(RequestCountKey, requestCount);
            return requestCount;
        }
    }
}

