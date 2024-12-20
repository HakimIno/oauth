defmodule AuthApiWeb.AuthJSON do
  def user(%{user: user, token: token}) do
    %{
      data: %{
        id: user.id,
        email: user.email,
        token: token
      }
    }
  end

  def error(%{changeset: changeset}) do
    %{errors: Ecto.Changeset.traverse_errors(changeset, &translate_error/1)}
  end

  defp translate_error({msg, opts}) do
    Enum.reduce(opts, msg, fn {key, value}, acc ->
      String.replace(acc, "%{#{key}}", to_string(value))
    end)
  end
end
