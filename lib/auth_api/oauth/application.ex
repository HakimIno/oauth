defmodule AuthApi.OAuth.Application do
  use Ecto.Schema
  import Ecto.Changeset

  schema "oauth_applications" do
    field :name, :string
    field :client_id, :string
    field :client_secret, :string
    field :redirect_uri, :string
    belongs_to :user, AuthApi.Accounts.User

    timestamps()
  end

  def changeset(application, attrs) do
    application
    |> cast(attrs, [:name, :redirect_uri, :user_id])
    |> validate_required([:name, :redirect_uri, :user_id])
    |> put_client_id()
    |> put_client_secret()
  end

  defp put_client_id(changeset) do
    put_change(changeset, :client_id, generate_client_id())
  end

  defp put_client_secret(changeset) do
    put_change(changeset, :client_secret, generate_client_secret())
  end

  defp generate_client_id do
    :crypto.strong_rand_bytes(24) |> Base.url_encode64(padding: false)
  end

  defp generate_client_secret do
    :crypto.strong_rand_bytes(48) |> Base.url_encode64(padding: false)
  end
end
