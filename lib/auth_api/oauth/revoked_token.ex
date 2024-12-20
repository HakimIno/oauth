defmodule AuthApi.OAuth.RevokedToken do
  use Ecto.Schema
  import Ecto.Changeset

  schema "oauth_revoked_tokens" do
    field :token, :string
    field :revoked_at, :utc_datetime
    field :reason, :string
    field :revoked_by_user_id, :integer

    timestamps()
  end

  def changeset(revoked_token, attrs) do
    revoked_token
    |> cast(attrs, [:token, :reason, :revoked_by_user_id])
    |> validate_required([:token])
    |> put_revoked_at()
    |> unique_constraint(:token)
  end

  defp put_revoked_at(changeset) do
    put_change(changeset, :revoked_at, DateTime.utc_now())
  end
end
