defmodule AuthApiWeb.Router do
  use AuthApiWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :protect_from_forgery
    plug :put_root_layout, html: {AuthApiWeb.Layouts, :root}
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  pipeline :oauth_api do
    plug :accepts, ["html", "json"]
    plug :fetch_session
    plug :put_secure_browser_headers
    plug AuthApiWeb.Plugs.SecurityHeaders
    plug CORSPlug
  end

  pipeline :oauth_token do
    plug :accepts, ["json"]
    plug :fetch_session
  end

  scope "/api", AuthApiWeb do
    pipe_through :api

    post "/register", AuthController, :register
    post "/login", AuthController, :login

    pipe_through [:verify_scope_read]
    get "/profile", UserController, :show

    pipe_through [:verify_scope_write]
    put "/profile", UserController, :update
  end

  scope "/oauth", AuthApiWeb do
    pipe_through [:oauth_api]

    get "/authorize", OAuthController, :authorize
    post "/authorize", OAuthController, :handle_authorize
  end

  scope "/oauth", AuthApiWeb do
    pipe_through :oauth_token

    post "/token", OAuthController, :token
  end

  scope "/", AuthApiWeb do
    pipe_through :browser

    get "/", PageController, :home
    get "/test/oauth_client.html", PageController, :static_oauth_client
  end

  pipeline :verify_scope_read do
    plug AuthApiWeb.Plugs.VerifyScopes, ["read"]
  end

  pipeline :verify_scope_write do
    plug AuthApiWeb.Plugs.VerifyScopes, ["write"]
  end

  scope "/api/test", AuthApiWeb do
    pipe_through :api

    get "/public", TestController, :public

    pipe_through [:verify_scope_read]
    get "/read", TestController, :read_only

    pipe_through [:verify_scope_write]
    post "/write", TestController, :write_access
  end
end
