defmodule AuthApiWeb.OAuthController do
  use AuthApiWeb, :controller
  alias AuthApi.OAuth

  def authorize(conn, params) do
    state = params["state"] || generate_state()
    scopes = String.split(params["scope"] || "", " ")

    with {:ok, _} <- validate_client(params),
         {:ok, _} <- validate_pkce_params(params),
         {:ok, _} <- validate_state_param(%{"state" => state}),
         {:ok, application} <- OAuth.get_application_by_client_id(params["client_id"]) do
      # Store PKCE and state in session for later verification
      conn
      |> put_session("state", state)
      |> put_session("code_challenge", params["code_challenge"])
      |> put_session("redirect_uri", params["redirect_uri"])
      |> assign(:scopes, scopes)
      |> assign(:application, application)
      |> render("authorize.html")
    else
      {:error, error_code} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: error_code})
    end
  end

  defp generate_state do
    :crypto.strong_rand_bytes(16)
    |> Base.url_encode64(padding: false)
  end

  def token(conn, %{"grant_type" => "authorization_code"} = params) do
    case OAuth.exchange_code_for_token(params) do
      {:ok, token_response} ->
        json(conn, token_response)

      {:error, error} ->
        render_error(conn, error)
    end
  end

  def token(conn, %{"grant_type" => "refresh_token"} = params) do
    case OAuth.refresh_access_token(params["refresh_token"]) do
      {:ok, token} -> render_token_response(conn, token)
      {:error, error_code} -> render_error(conn, error_code)
    end
  end

  def token(conn, _params) do
    render_error(conn, "unsupported_grant_type")
  end

  # PKCE Validation
  defp validate_pkce_params(%{"code_challenge" => challenge, "code_challenge_method" => "S256"})
       when byte_size(challenge) > 0 do
    {:ok, challenge}
  end

  defp validate_pkce_params(_), do: {:error, "invalid_pkce_params"}

  defp verify_pkce(conn, %{"code_verifier" => verifier}) do
    stored_challenge = get_session(conn, :code_challenge)
    calculated = calculate_challenge(verifier)

    if stored_challenge && secure_compare(stored_challenge, calculated) do
      {:ok, verifier}
    else
      {:error, "invalid_code_verifier"}
    end
  end

  # State Validation
  defp validate_state_param(%{"state" => state}) when is_binary(state) do
    {:ok, state}
  end

  defp validate_state_param(_), do: {:ok, generate_state()}

  defp verify_state(conn, %{"state" => state}) do
    stored_state = get_session(conn, :state)

    if stored_state && secure_compare(stored_state, state) do
      {:ok, state}
    else
      {:error, "invalid_state"}
    end
  end

  # Client Validation
  defp validate_client(%{"client_id" => client_id, "redirect_uri" => redirect_uri}) do
    case OAuth.get_application_by_client_id(client_id) do
      {:ok, app} when app.redirect_uri == redirect_uri -> {:ok, app}
      _ -> {:error, "invalid_client"}
    end
  end

  defp validate_client(_), do: {:error, "invalid_request"}

  # Helpers
  defp store_pkce_and_state(conn, params) do
    conn
    |> put_session(:code_challenge, params["code_challenge"])
    |> put_session(:state, params["state"])
  end

  defp calculate_challenge(verifier) do
    :crypto.hash(:sha256, verifier)
    |> Base.url_encode64(padding: false)
  end

  defp secure_compare(a, b) when is_binary(a) and is_binary(b) do
    if byte_size(a) == byte_size(b) do
      :crypto.secure_compare(a, b)
    else
      false
    end
  end

  defp secure_compare(_, _), do: false

  defp render_token_response(conn, token) do
    conn
    |> put_status(:ok)
    |> json(%{
      access_token: token.token,
      token_type: "bearer",
      expires_in: 3600,
      refresh_token: token.refresh_token
    })
  end

  defp render_error(conn, error_code) do
    conn
    |> put_status(:unauthorized)
    |> json(%{error: error_code})
  end

  def revoke(conn, %{"token" => token}) do
    current_user = conn.assigns.current_user

    case OAuth.revoke_token(token, current_user.id) do
      {:ok, _} ->
        conn
        |> put_status(:ok)
        |> json(%{message: "Token revoked successfully"})

      {:error, _reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Failed to revoke token"})
    end
  end

  def revoked_tokens(conn, params) do
    tokens =
      OAuth.list_revoked_tokens(%{
        from: parse_datetime(params["from"]),
        to: parse_datetime(params["to"]),
        user_id: params["user_id"]
      })

    render(conn, "revoked_tokens.json", tokens: tokens)
  end

  defp parse_datetime(nil), do: nil

  defp parse_datetime(string) do
    case DateTime.from_iso8601(string) do
      {:ok, datetime, _} -> datetime
      _ -> nil
    end
  end

  # Add this function to handle the POST request from the authorize form
  def handle_authorize(conn, %{"action" => "authorize"} = params) do
    with {:ok, application} <- OAuth.get_application_by_client_id(params["client_id"]),
         true <- application.redirect_uri == params["redirect_uri"] do
      # Generate authorization code
      code = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

      # Store code data with PKCE challenge
      OAuth.store_code_data(code, params["code_challenge"])

      # Get state from session
      state = get_session(conn, "state") || ""

      # Build redirect URI
      redirect_uri = "#{params["redirect_uri"]}?code=#{code}&state=#{state}"

      # Clear session data
      conn
      |> delete_session("state")
      |> delete_session("code_challenge")
      |> delete_session("redirect_uri")
      |> redirect(external: redirect_uri)
    else
      _ ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_request"})
    end
  end

  def handle_authorize(conn, %{"action" => "deny"}) do
    redirect_uri = get_session(conn, "redirect_uri")
    state = get_session(conn, "state")

    # Clear session data
    conn =
      conn
      |> delete_session("redirect_uri")
      |> delete_session("state")
      |> delete_session("code_challenge")

    error_uri = "#{redirect_uri}?error=access_denied&state=#{state}"

    conn
    |> redirect(external: error_uri)
  end

  def handle_authorize(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "invalid_request"})
  end

  # Add this helper function
  defp store_authorization_code(conn, code, code_challenge) do
    put_session(conn, "authorization_codes", %{
      code: code,
      code_challenge: code_challenge,
      expires_at: DateTime.utc_now() |> DateTime.add(600, :second)
    })
  end
end