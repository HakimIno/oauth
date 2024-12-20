defmodule AuthApi.OAuth.Scope do
  use Ecto.Schema
  import Ecto.Changeset

  schema "oauth_scopes" do
    field :name, :string
    field :description, :string

    many_to_many :access_tokens, AuthApi.OAuth.AccessToken,
      join_through: "oauth_access_token_scopes",
      on_replace: :delete

    timestamps()
  end

  def changeset(scope, attrs) do
    scope
    |> cast(attrs, [:name, :description])
    |> validate_required([:name])
    |> unique_constraint(:name)
  end

  # ฟังก์ชันสำหรับตรวจสอบ scopes
  def validate_scopes(requested_scopes) when is_binary(requested_scopes) do
    requested_scopes
    |> String.split(" ")
    |> validate_scopes()
  end

  def validate_scopes(requested_scopes) when is_list(requested_scopes) do
    available = available_scopes()
    invalid = requested_scopes -- available

    if invalid == [] do
      {:ok, requested_scopes}
    else
      {:error, "Invalid scopes: #{Enum.join(invalid, ", ")}"}
    end
  end

  # รายการ scopes ที่ระบบรองรับ
  def available_scopes do
    ~w(read write profile email admin)
  end
end
