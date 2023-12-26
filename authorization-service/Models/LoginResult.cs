using System;
using System.Security.Claims;

namespace AuthorizationService.Models
{
	public class LoginResult
	{
		public string Code { get; set; }
		public string Explanation { get; set; }
		public IEnumerable<Claim> Claims { get; set; }

		public LoginResult(string code, IEnumerable<Claim>? claims = null)
		{
            Code = code;
            Explanation = string.Empty;
            Claims = claims ?? new List<Claim>();
        }

        public LoginResult(string code, string? explanation, IEnumerable<Claim>? claims = null)
		{
			Code = code;
			Explanation = explanation ?? string.Empty;
			Claims = claims ?? new List<Claim>();
		}
	}
}

