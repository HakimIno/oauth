defmodule AuthApiWeb.CoreComponents do
  @moduledoc """
  Provides core UI components.
  """
  use Phoenix.Component
  alias Phoenix.LiveView.JS

  # You can add more components here as needed, but for now let's start with a minimal setup
  # The following is a minimal implementation to get your app running

  @doc """
  Renders a modal.
  """
  attr :id, :string, required: true
  attr :show, :boolean, default: false
  slot :inner_block, required: true

  def modal(assigns) do
    ~H"""
    <div
      id={@id}
      phx-mounted={@show && show_modal(@id)}
      phx-remove={hide_modal(@id)}
      data-cancel={JS.exec("phx-remove", to: "##{@id}")}
      class="relative z-50 hidden"
    >
      <div class="modal-content">
        <%= render_slot(@inner_block) %>
      </div>
    </div>
    """
  end

  ## JS Commands
  def show_modal(js \\ %JS{}, id) when is_binary(id) do
    JS.show(js, to: "##{id}")
  end

  def hide_modal(js \\ %JS{}, id) do
    JS.hide(js, to: "##{id}")
  end
end
