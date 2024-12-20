defmodule AuthApiWeb.UserController do
  use AuthApiWeb, :controller

  def show(conn, _params) do
    json(conn, %{message: "User profile"})
  end

  def update(conn, _params) do
    json(conn, %{message: "Profile updated"})
  end
end
