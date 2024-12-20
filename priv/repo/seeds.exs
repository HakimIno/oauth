# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs
#
# Inside the script, you can read and write to any of your
# repositories directly:
#
#     AuthApi.Repo.insert!(%AuthApi.SomeSchema{})
#
# We recommend using the bang functions (`insert!`, `update!`
# and so on) as they will fail if something goes wrong.

alias AuthApi.Repo
alias AuthApi.Accounts.User
alias AuthApi.OAuth.{Application, Scope}

# Create default scopes
scopes = [
  %{name: "read", description: "Read access to user data"},
  %{name: "write", description: "Write access to user data"},
  %{name: "profile", description: "Access to user profile"},
  %{name: "email", description: "Access to user email"}
]

Enum.each(scopes, fn scope ->
  Repo.insert!(
    %Scope{
      name: scope.name,
      description: scope.description
    },
    on_conflict: :nothing
  )
end)

# Create test user first
{:ok, user} =
  Repo.insert(
    %User{
      email: "test@example.com",
      password_hash: Bcrypt.hash_pwd_salt("password123")
    },
    on_conflict: :nothing
  )

# Then create test OAuth application
client_id = "RFrMmO9SiD2KWcMAflfxq2p4mTLMDC3o"
existing_app = Repo.get_by(Application, client_id: client_id)

if is_nil(existing_app) do
  Repo.insert!(%Application{
    name: "Test App",
    client_id: client_id,
    client_secret: "72WhQyXx__Yenkhp7xXFu_5LCQhrlwzovdzAEOpo-9RMqNJmec9igvvBxPktJIma",
    redirect_uri: "http://localhost:4000/test/oauth_client.html",
    user_id: user.id
  })
end
