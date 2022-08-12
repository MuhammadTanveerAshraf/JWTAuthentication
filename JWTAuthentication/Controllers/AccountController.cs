using JWTAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication.Controllers
{
	[Authorize]
	[Route("api/[controller]")]
	[ApiController]
	public class AccountController : ControllerBase
	{
		private readonly IJWTAuthenticationManager AuthenticationManager;

		public AccountController(IJWTAuthenticationManager authenticationManager)
		{
			AuthenticationManager = authenticationManager;
		}

		[HttpGet]
		public IEnumerable<string> Get()
		{
			return new string[] { "New Jersey", "Ohio", "New york" };
		}

		[AllowAnonymous]
		[HttpPost("authenticate")]
		public IActionResult Authenticate([FromBody] UserCred userCred)
		{
			var token = AuthenticationManager.Authenticate(userCred.UserName, userCred.Password);
			if (token is null)
			{
				return Unauthorized();
			}
			return Ok(token);
		}
	}
}
