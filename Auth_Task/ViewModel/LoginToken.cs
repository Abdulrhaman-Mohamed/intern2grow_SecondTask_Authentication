using System.ComponentModel.DataAnnotations;

namespace Auth_Task.ViewModel
{
    public class LoginToken
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
