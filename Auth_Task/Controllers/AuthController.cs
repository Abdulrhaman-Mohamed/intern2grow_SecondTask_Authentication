using Auth_Task.Services;
using Auth_Task.ViewModel;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Win32;
using System.Security.Claims;

namespace Auth_Task.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuth _auth;
        private readonly UserManager<IdentityUser> _userManager;

        public AuthController(IAuth auth , UserManager<IdentityUser> userManager)
        {
            _auth = auth;
            _userManager = userManager;
        }
        //Create New User (End-Point)
        [HttpPost("register")]
        public async Task<IActionResult> CreateUserAynsc(RegisterView register)
        {
            if(!ModelState.IsValid)
                return BadRequest(ModelState);

            var Creation = await _auth.Registeration(register);

            if(!Creation.IsAuthenticated)
                return BadRequest(Creation.Message);

            return Ok(new{ Creation.Token , Creation.ExpireOn});
        }

        // Login with Exist User
        [HttpPost("Login")]
        public async Task<IActionResult> LoginAynsc(LoginToken login)
        {
            if(!ModelState.IsValid)
                return BadRequest(ModelState);

            var Creation = await _auth.Login(login);

            if (!Creation.IsAuthenticated)
                return BadRequest(Creation.Message);

            return Ok(new {Creation.Token , Creation.ExpireOn});
        }


    }
}
