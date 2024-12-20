# lib/auth_api_web/controllers/auth_controller.ex
defmodule AuthApiWeb.AuthController do
  use AuthApiWeb, :controller

  alias AuthApi.Accounts
  alias AuthApi.Guardian

  def register(conn, %{"user" => user_params}) do
    case Accounts.create_user(user_params) do
      {:ok, user} ->
        {:ok, token, _claims} = Guardian.encode_and_sign(user)

        conn
        |> put_status(:created)
        |> render("user.json", %{user: user, token: token})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> render("error.json", changeset: changeset)
    end
  end

  def login(conn, %{"email" => email, "password" => password}) do
    case Accounts.authenticate_user(email, password) do
      {:ok, user} ->
        {:ok, token, _claims} = Guardian.encode_and_sign(user)

        conn
        |> put_status(:ok)
        |> render("user.json", %{user: user, token: token})

      {:error, :unauthorized} ->
        conn
        |> put_status(:unauthorized)
        |> render("error.json", message: "Invalid email or password")
    end
  end
end
