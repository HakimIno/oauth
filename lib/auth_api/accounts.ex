defmodule AuthApi.Accounts do
  alias AuthApi.Repo
  alias AuthApi.Accounts.User

  def get_user!(id) do
    Repo.get!(User, id)
  end

  def create_user(attrs \\ %{}) do
    %User{}
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  def authenticate_user(email, password) do
    user = Repo.get_by(User, email: email)

    case user do
      nil ->
        {:error, :unauthorized}

      user ->
        if verify_password(password, user.password_hash) do
          {:ok, user}
        else
          {:error, :unauthorized}
        end
    end
  end

  defp verify_password(password, stored_hash) do
    Bcrypt.verify_pass(password, stored_hash)
  end
end
