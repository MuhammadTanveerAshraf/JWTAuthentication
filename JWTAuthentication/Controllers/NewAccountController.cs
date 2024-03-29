﻿using JWTAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JWTAuthentication.Controllers
{
	[Authorize]
	[Route("api/[controller]")]
	[ApiController]
	public class NewAccountController : ControllerBase
	{
		private readonly IJWTAuthenticationManager AuthenticationManager;

		public NewAccountController(IJWTAuthenticationManager authenticationManager)
		{
			AuthenticationManager = authenticationManager;
		}


		// GET: api/<NewAccountController>
		[HttpGet]
		public IEnumerable<string> Get()
		{
			return new string[] { "value1", "value2" };
		}

		// GET api/<NewAccountController>/5
		[HttpGet("{id}")]
		public string Get(int id)
		{
			return "value";
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
