defmodule AuthApi.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    # Initialize ETS table for auth codes
    AuthApi.OAuth.init_storage()

    children = [
      AuthApi.Repo,
      AuthApiWeb.Telemetry,
      {DNSCluster, query: Application.get_env(:auth_api, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: AuthApi.PubSub},
      # Start the Finch HTTP client for sending emails
      {Finch, name: AuthApi.Finch},
      # Start a worker by calling: AuthApi.Worker.start_link(arg)
      # {AuthApi.Worker, arg},
      # Start to serve requests, typically the last entry
      AuthApiWeb.Endpoint,
      # Add cache supervision
      {Cachex, name: :oauth_cache}
    ]

    opts = [strategy: :one_for_one, name: AuthApi.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    AuthApiWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
