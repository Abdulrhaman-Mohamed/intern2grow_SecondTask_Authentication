
using System.ComponentModel.DataAnnotations;

namespace Auth_Task.ViewModel
{
    public class RegisterView
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        [EmailAddress]
        public string Email { get; set; }
    }
}
