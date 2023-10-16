using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Auth_Task.Model
{
    public class ApllicationDbContext : IdentityDbContext
    {
        public ApllicationDbContext(DbContextOptions<ApllicationDbContext> options):base(options) { }





    }
}
