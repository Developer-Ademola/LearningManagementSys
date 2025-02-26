using LearningManagementSys.Models;
using Microsoft.Azure.Cosmos;

namespace LearningManagementSys.Data
{
    public class CosmosDbService
    {
        private readonly Container _container;

        public CosmosDbService(IConfiguration configuration)
        {
            var cosmosClient = new CosmosClient(configuration["CosmosDb:ConnectionString"]);
            var database = cosmosClient.GetDatabase(configuration["CosmosDb:DatabaseName"]);
            _container = database.GetContainer(configuration["CosmosDb:ContainerName"]);
        }

        // ✅ Add a new user to CosmosDB
        public async Task AddUserAsync(AppUser user)
        {
            await _container.CreateItemAsync(user, new PartitionKey(user.Id)); // ✅ Use auto-generated id
        }


        // ✅ Get a user by Email
        //public async Task<AppUser> GetUserByEmailAsync(string email)
        //{
        //    var query = new QueryDefinition("SELECT * FROM c WHERE c.email = @email")
        //        .WithParameter("@email", email);

        //    var iterator = _container.GetItemQueryIterator<AppUser>(query);
        //    var users = new List<AppUser>();

        //    while (iterator.HasMoreResults)
        //    {
        //        var response = await iterator.ReadNextAsync();
        //        users.AddRange(response.ToList());
        //    }

        //    return users.FirstOrDefault();
        //}

        // ✅ Get user by ID (PartitionKey is `id`)
        public async Task<AppUser> GetUserByIdAsync(string id)
        {
            try
            {
                ItemResponse<AppUser> response = await _container.ReadItemAsync<AppUser>(id, new PartitionKey(id));
                return response.Resource;
            }
            catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return null;
            }
        }

        // ✅ Update an existing user
        public async Task UpdateUserAsync(AppUser user)
        {
            await _container.UpsertItemAsync(user, new PartitionKey(user.Id));
        }

        // ✅ Delete a user (if needed)
        public async Task DeleteUserAsync(string id)
        {
            await _container.DeleteItemAsync<AppUser>(id, new PartitionKey(id));
        }

        // ✅ Get All Users
        public async Task<List<AppUser>> GetAllUsersAsync()
        {
            var query = new QueryDefinition("SELECT * FROM c");
            var iterator = _container.GetItemQueryIterator<AppUser>(query);
            var users = new List<AppUser>();

            while (iterator.HasMoreResults)
            {
                var response = await iterator.ReadNextAsync();
                users.AddRange(response.ToList());
            }

            return users;
        }

        // ✅ Get User By Email
        public async Task<AppUser> GetUserByEmailAsync(string email)
        {
            var query = new QueryDefinition("SELECT * FROM c WHERE c.email = @email")
                .WithParameter("@email", email);

            var iterator = _container.GetItemQueryIterator<AppUser>(query);
            var users = new List<AppUser>();

            while (iterator.HasMoreResults)
            {
                var response = await iterator.ReadNextAsync();
                users.AddRange(response.ToList());
            }

            return users.FirstOrDefault();
        }
    }
}
