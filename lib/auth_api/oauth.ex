defmodule AuthApi.OAuth do
  use Phoenix.Controller
  import Plug.Conn, except: [assign: 3]
  import Phoenix.Component, only: [assign: 3]

  import Ecto.Query
  alias AuthApi.Repo
  alias AuthApi.OAuth.{Application, AccessToken, RevokedToken, RefreshToken, AccessTokenScope}
  alias AuthApi.OAuth.Scope
  require Logger

  @auth_code_table :auth_codes

  # Add this to initialize ETS table when the module is loaded
  def init_storage do
    :ets.new(@auth_code_table, [:set, :public, :named_table])
  end

  def create_application(attrs) do
    %Application{}
    |> Application.changeset(attrs)
    |> Repo.insert()
  end

  def get_application_by_client_id(client_id) do
    case Repo.get_by(Application, client_id: client_id) do
      nil -> {:error, "invalid_client"}
      application -> {:ok, application}
    end
  end

  def create_access_token(attrs) do
    %AccessToken{}
    |> AccessToken.changeset(attrs)
    |> Repo.insert()
  end

  def get_application_by_code(code) do
    case Repo.get_by(AccessToken, token: code) do
      nil -> {:error, "invalid_grant"}
      token -> {:ok, token}
    end
  end

  def exchange_code_for_token(params) do
    with {:ok, application} <- get_application_by_client_id(params["client_id"]),
         true <- application.client_secret == params["client_secret"],
         {:ok, code_data} <- get_stored_code_data(params["code"]),
         :ok <- verify_code_verifier(code_data["code_challenge"], params["code_verifier"]) do
      # Delete the used code
      :ets.delete(@auth_code_table, params["code"])

      # Create token pair
      case create_token_pair(application, ["read"]) do
        {:ok, {access_token, refresh_token}} ->
          {:ok,
           %{
             access_token: access_token.token,
             token_type: "bearer",
             expires_in: 3600,
             refresh_token: refresh_token.token
           }}

        error ->
          error
      end
    else
      false ->
        {:error, :invalid_client}

      error ->
        Logger.error("Token exchange error: #{inspect(error)}")
        {:error, :invalid_grant}
    end
  end

  def store_code_data(code, code_challenge) do
    data = %{
      "code_challenge" => code_challenge,
      "expires_at" => DateTime.utc_now() |> DateTime.add(600, :second)
    }

    true = :ets.insert(@auth_code_table, {code, data})
    {:ok, code}
  end

  defp get_stored_code_data(code) do
    case :ets.lookup(@auth_code_table, code) do
      [{^code, data}] ->
        # Check if code hasn't expired
        if DateTime.compare(data["expires_at"], DateTime.utc_now()) == :gt do
          {:ok, data}
        else
          :ets.delete(@auth_code_table, code)
          {:error, :code_expired}
        end

      [] ->
        {:error, :invalid_code}
    end
  end

  defp verify_code_verifier(challenge, verifier)
       when is_binary(challenge) and is_binary(verifier) do
    calculated_challenge =
      :crypto.hash(:sha256, verifier)
      |> Base.url_encode64(padding: false)
      |> String.replace("+", "-")
      |> String.replace("/", "_")
      |> String.replace("=", "")

    if challenge == calculated_challenge do
      :ok
    else
      {:error, :invalid_code_verifier}
    end
  end

  defp verify_code_verifier(_, _), do: {:error, :invalid_code_verifier}

  defp generate_token do
    :crypto.strong_rand_bytes(32)
    |> Base.url_encode64(padding: false)
  end

  def verify_access_token(token) do
    with {:ok, token_record} <- get_token(token),
         false <- token_revoked?(token),
         true <- token_not_expired?(token_record) do
      {:ok, token_record}
    else
      true -> {:error, :token_revoked}
      false -> {:error, :token_expired}
      error -> error
    end
  end

  def revoke_token(token, user_id, reason \\ nil) do
    %RevokedToken{}
    |> RevokedToken.changeset(%{
      token: token,
      reason: reason,
      revoked_by_user_id: user_id
    })
    |> Repo.insert()
    |> case do
      {:ok, _} = result ->
        # ถ้าเป็น access token ให้ revoke refresh token ด้วย
        case get_token(token) do
          {:ok, token_record} -> revoke_refresh_token(token_record.refresh_token, user_id)
          _ -> nil
        end

        result

      error ->
        error
    end
  end

  def revoke_refresh_token(refresh_token, user_id) do
    %RevokedToken{}
    |> RevokedToken.changeset(%{
      token: refresh_token,
      reason: "access_token_revoked",
      revoked_by_user_id: user_id
    })
    |> Repo.insert()
  end

  def token_revoked?(token) do
    case Repo.get_by(RevokedToken, token: token) do
      nil ->
        false

      revoked ->
        DateTime.compare(revoked.revoked_at, DateTime.utc_now()) == :lt
    end
  end

  defp token_not_expired?(token) do
    DateTime.compare(token.expires_at, DateTime.utc_now()) == :gt
  end

  def list_revoked_tokens(opts \\ []) do
    RevokedToken
    |> filter_by_date(opts[:from], opts[:to])
    |> filter_by_user(opts[:user_id])
    |> Repo.all()
  end

  defp filter_by_date(query, nil, nil), do: query

  defp filter_by_date(query, from, nil) do
    from q in query,
      where: q.revoked_at >= ^from
  end

  defp filter_by_date(query, nil, to) do
    from q in query,
      where: q.revoked_at <= ^to
  end

  defp filter_by_date(query, from, to) do
    from q in query,
      where: q.revoked_at >= ^from and q.revoked_at <= ^to
  end

  defp filter_by_user(query, nil), do: query

  defp filter_by_user(query, user_id) do
    from q in query,
      where: q.revoked_by_user_id == ^user_id
  end

  def validate_scopes(requested_scopes) do
    available_scopes = list_available_scopes()

    requested_scopes
    |> String.split(" ")
    |> Enum.all?(fn scope -> Enum.member?(available_scopes, scope) end)
  end

  def list_available_scopes do
    Repo.all(Scope)
    |> Enum.map(& &1.name)
  end

  def get_default_scopes do
    Repo.all(from s in Scope, where: s.is_default == true)
    |> Enum.map(& &1.name)
  end

  def get_token(token) do
    case Repo.get_by(AccessToken, token: token) do
      nil -> {:error, :token_not_found}
      token_record -> {:ok, token_record}
    end
  end

  defp create_token_pair(application, scopes) do
    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
    access_token_expires = NaiveDateTime.add(now, 3600, :second)
    refresh_token_expires = NaiveDateTime.add(now, 30 * 24 * 60 * 60, :second)

    access_token_attrs = %{
      token: generate_token(),
      application_id: application.id,
      expires_at: access_token_expires,
      scope_list: scopes
    }

    Ecto.Multi.new()
    |> Ecto.Multi.insert(:access_token, AccessToken.changeset(%AccessToken{}, access_token_attrs))
    |> Ecto.Multi.insert(:refresh_token, fn %{access_token: access_token} ->
      RefreshToken.changeset(%RefreshToken{}, %{
        token: generate_token(),
        # ใช้ access_token_id แทน application_id
        access_token_id: access_token.id,
        expires_at: refresh_token_expires
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{access_token: access_token, refresh_token: refresh_token}} ->
        {:ok, {access_token, refresh_token}}

      {:error, _, changeset, _} ->
        {:error, changeset}
    end
  end

  def refresh_access_token(refresh_token, client_id, client_secret) do
    with {:ok, application} <- get_application_by_client_id(client_id),
         true <- application.client_secret == client_secret,
         {:ok, refresh_token_record} <- get_refresh_token(refresh_token),
         {:ok, old_access_token} <- get_access_token_by_id(refresh_token_record.access_token_id),
         {:ok, scopes} <- get_token_scopes(old_access_token) do
      Repo.transaction(fn ->
        with {:ok, _} <- delete_old_tokens(refresh_token_record),
             {:ok, {access_token, refresh_token}} <- create_token_pair(application, scopes) do
          {:ok, {access_token, refresh_token}}
        else
          error -> Repo.rollback(error)
        end
      end)
    else
      false -> {:error, :invalid_client}
      nil -> {:error, :invalid_refresh_token}
      error -> error
    end
  end

  defp get_token_scopes(token) do
    scopes =
      Repo.all(
        from s in Scope,
          join: ats in "oauth_access_token_scopes",
          on: ats.scope_id == s.id,
          where: ats.access_token_id == ^token.id,
          select: s.name
      )

    {:ok, scopes}
  end

  # Private function to handle token deletion
  defp delete_old_tokens(refresh_token) do
    # Load access token
    access_token =
      refresh_token.access_token_id
      |> get_access_token_by_id()
      |> case do
        {:ok, token} -> token
        _ -> nil
      end

    if access_token do
      # Delete in correct order to maintain referential integrity
      Repo.transaction(fn ->
        # 1. Delete access token scopes
        Repo.delete_all(
          from ats in "oauth_access_token_scopes",
            where: ats.access_token_id == ^access_token.id
        )

        # 2. Delete refresh tokens
        Repo.delete_all(
          from rt in RefreshToken,
            where: rt.access_token_id == ^access_token.id
        )

        # 3. Delete access token
        Repo.delete_all(
          from at in AccessToken,
            where: at.id == ^access_token.id
        )
      end)
    end
  end

  defp is_valid_refresh_token?(nil), do: false

  defp is_valid_refresh_token?(refresh_token) do
    not is_nil(refresh_token) and
      is_nil(refresh_token.revoked_at) and
      DateTime.compare(refresh_token.expires_at, DateTime.utc_now()) == :gt
  end

  defp expires_at do
    DateTime.utc_now()
    # 24 hours
    |> DateTime.add(24 * 60 * 60, :second)
    |> DateTime.truncate(:second)
  end

  defp get_token_from_header(%Plug.Conn{} = conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> {:ok, token}
      _ -> {:error, :missing_token}
    end
  end

  defp get_token_from_header(_), do: {:error, :invalid_conn}

  defp get_access_token(token) do
    case Repo.get_by(AccessToken, token: token) do
      nil -> {:error, :not_found}
      token -> {:ok, token}
    end
  end

  def verify_token_scope(conn, scope) do
    with {:ok, token} <- get_token_from_header(conn),
         {:ok, access_token} <- get_access_token(token) do
      # Query token with its scopes
      query =
        from t in AccessToken,
          where: t.id == ^access_token.id,
          join: s in assoc(t, :scopes),
          select: s.name

      scopes = Repo.all(query)

      if scope in scopes do
        {:ok, access_token}
      else
        {:error, :invalid_scope}
      end
    end
  end

  def assign_scopes(token, scopes) when is_list(scopes) do
    results =
      Enum.map(scopes, fn scope ->
        create_access_token_scope(%{
          access_token_id: token.id,
          scope_id: get_scope_id(scope)
        })
      end)

    case Enum.find(results, &match?({:error, _}, &1)) do
      nil -> :ok
      error -> error
    end
  end

  def assign_scopes(token, scopes) when is_binary(scopes) do
    assign_scopes(token, String.split(scopes, " "))
  end

  defp get_scope_id(scope_name) do
    case Repo.get_by(Scope, name: scope_name) do
      nil ->
        {:ok, scope} = create_scope(%{name: scope_name})
        scope.id

      scope ->
        scope.id
    end
  end

  def create_access_token(application, scopes) do
    access_token =
      Repo.insert!(%AccessToken{
        token: generate_token(),
        application_id: application.id,
        expires_at: expires_at()
      })

    assign_scopes(access_token, scopes)
  end

  defp generate_authorization_code do
    :crypto.strong_rand_bytes(32)
    |> Base.url_encode64(padding: false)
  end

  def handle_authorize(conn, %{"action" => "authorize", "client_id" => client_id}) do
    redirect_uri = get_session(conn, "redirect_uri")
    session_state = get_session(conn, "state")

    Logger.info("""
    handle_authorize/2:
      redirect_uri from session: #{redirect_uri}
      state from session: #{session_state}
      client_id: #{client_id}
    """)

    with {:ok, application} <- get_application_by_client_id(client_id),
         true <- application.redirect_uri == redirect_uri do
      # Generate authorization code
      code = generate_authorization_code()

      # Clear session data
      conn =
        conn
        |> delete_session("redirect_uri")
        |> delete_session("state")
        |> delete_session("code_challenge")

      # Redirect back to client with code
      redirect_uri = "#{redirect_uri}?code=#{code}&state=#{session_state}"

      conn
      |> redirect(external: redirect_uri)
    else
      _ ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_request"})
    end
  end

  def authorize(conn, params) do
    # Generate state if not exists
    state = params["state"] || generate_state()

    Logger.info("""
    authorize/2 storing in session:
      state: #{state}
      code_challenge: #{params["code_challenge"]}
      redirect_uri: #{params["redirect_uri"]}
    """)

    # Store data in session
    conn =
      conn
      |> put_session("state", state)
      |> put_session("redirect_uri", params["redirect_uri"])
      |> put_session("code_challenge", params["code_challenge"])

    case get_application_by_client_id(params["client_id"]) do
      {:ok, application} ->
        conn
        |> assign(:application, application)
        |> assign(:scopes, String.split(params["scope"] || "", " "))
        |> render(:authorize)

      _ ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid client_id"})
    end
  end

  defp generate_state do
    :crypto.strong_rand_bytes(16)
    |> Base.url_encode64(padding: false)
  end

  def create_access_token_scope(attrs) do
    %AccessTokenScope{}
    |> AccessTokenScope.changeset(attrs)
    |> Repo.insert()
  end

  def create_scope(attrs) do
    %Scope{}
    |> Scope.changeset(attrs)
    |> Repo.insert()
  end

  def get_access_token_by_id(id) do
    case Repo.get(AccessToken, id) do
      nil -> {:error, :not_found}
      token -> {:ok, token}
    end
  end

  def get_refresh_token(token) do
    case Repo.get_by(RefreshToken, token: token) do
      nil -> {:error, :not_found}
      refresh_token -> {:ok, refresh_token}
    end
  end
end
