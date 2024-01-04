using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Distributed.Permissions;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace YetAnotherService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestController : Controller
    {
        private const string RequestCountKey = "RequestCount";

        [HttpGet("/one")]
        public IActionResult One()
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
        [HttpGet("/two")]
        public IActionResult Two()
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
        [HttpGet("/three")]
        public IActionResult Three()
        {
            return Json(new
            {
                About = "This method is accessible only by 'power' role members.",
                RequestMadeBy = new
                {
                    UserName = HttpContext.User.Identity?.Name ?? "Unknown",
                    IsInPowerRole = HttpContext.User.IsInRole("power")
                },
                RequestCount = RequestCount()
            });
        }

        [Authorize]
        [HttpGet("/four")]
        public IActionResult Four()
        {
            if (HttpContext.HasPermission("Alcohol.Drink"))
                return Json(new
                {
                    About = "This code path is accessible only by those who has \"Alcohol.Drink\" permission. Congratulations!",
                    RequestMadeBy = new
                    {
                        UserName = HttpContext.User.Identity?.Name ?? "Unknown",
                        IsInPowerRole = HttpContext.User.IsInRole("power")
                    },
                    RequestCount = RequestCount()
                });
            else
                return Json(new
                {
                    About = "You don't have \"Alcohol.Drink\" permission. Sorry.",
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

