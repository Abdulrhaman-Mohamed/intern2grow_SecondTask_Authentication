using Auth_Task.Helper;
using Auth_Task.Model;
using Auth_Task.ViewModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Auth_Task.Services
{
    public class Auth : IAuth
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JWT _jwt;

        public Auth(UserManager<IdentityUser> userManager, IOptions<JWT> jwt)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
        }

        public async Task<AuthModelcs> Login(LoginToken model)
        {
            var authModel = new AuthModelcs();

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password is incorrect!";
                return authModel;
            }

            var jwtSecurityToken = await CreateJwtToken(user);
            var rolesList = await _userManager.GetRolesAsync(user);

            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            authModel.ExpireOn = jwtSecurityToken.ValidTo;
            authModel.Roles = rolesList.ToList();

            return authModel;
        }

        //Create User
        public async Task<AuthModelcs> Registeration(RegisterView model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModelcs { Message = "Email is already registered!" };

            if (await _userManager.FindByNameAsync(model.UserName) is not null)
                return new AuthModelcs { Message = "Username is already registered!" };

            var user = new IdentityUser
            {
                UserName = model.UserName,
                Email = model.Email    
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                var errors = string.Empty;

                foreach (var error in result.Errors)
                    errors += $"{error.Description},";

                return new AuthModelcs { Message = errors };
            }

            await _userManager.AddToRoleAsync(user, "User");

            var Token = await CreateJwtToken(user);


            return new AuthModelcs
            {
                Email = user.Email,
                ExpireOn = Token.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(Token),
                Username = user.UserName,
                Message = "Succeeded ^_^"
            };


        }
        //Create Token
        private async Task<JwtSecurityToken> CreateJwtToken(IdentityUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DuratioByDay),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
    }
}
