using Auth_Task.Model;
using Auth_Task.ViewModel;

namespace Auth_Task.Services
{
    public interface IAuth
    {
        public Task<AuthModelcs> Registeration(RegisterView model);

        public Task<AuthModelcs> Login(LoginToken model);
    }
}
