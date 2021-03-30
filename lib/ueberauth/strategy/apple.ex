defmodule Ueberauth.Strategy.Apple do
  @moduledoc """
  Google Strategy for Überauth.
  """

  use Ueberauth.Strategy, uid_field: :uid, default_scope: "name email"

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Handles initial request for Apple authentication.
  """
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    opts = oauth_client_options_from_conn(conn)

    authorize_url =
      [scope: scopes]
      |> with_optional(:prompt, conn)
      |> with_optional(:access_type, conn)
      |> with_optional(:response_mode, conn)
      |> with_param(:access_type, conn)
      |> with_param(:prompt, conn)
      |> with_param(:state, conn)
      |> Ueberauth.Strategy.Apple.OAuth.authorize_url!(opts)

    put_private(conn, :authorize_url, authorize_url)
  end

  @doc """
  Handles the callback from Apple.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = oauth_client_options_from_conn(conn)

    with {:ok, token} <- Ueberauth.Strategy.Apple.OAuth.get_access_token([code: code], opts),
         {:ok, user} <- UeberauthApple.user_from_id_token(token.other_params["id_token"])
    do
      conn
      |> put_private(:apple_token, token)
      |> put_private(:apple_user, update_user_name(user, conn.params))
    else
      {:error, {error_code, error_description}} ->
        set_errors!(conn, [error(error_code, error_description)])
      {:error, error} ->
        set_errors!(conn, [error("auth_failed", error)])
    end
  end

  def handle_callback!(%Plug.Conn{params: %{"id_token" => id_token}} = conn) do
    with {:ok, user} = UeberauthApple.user_from_id_token(id_token) do
      conn
      |> put_private(:apple_token, OAuth2.AccessToken.new(id_token))
      |> put_private(:apple_user, update_user_name(user, conn.params))
    else
      {:error, error} ->
        set_errors!(conn, [error("auth_failed", error)])
    end
  end

  @doc false
  def handle_callback!(%Plug.Conn{params: %{"error" => error}} = conn) do
    set_errors!(conn, [error("auth_failed", error)])
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:apple_user, nil)
    |> put_private(:apple_token, nil)
  end

  defp update_user_name(user, %{"user" => params}) do
    update_user_name(user, Ueberauth.json_library().decode!(params))
  end
  defp update_user_name(user, %{"name" => name}) when not is_nil(name) and name != "" do
    Map.put(user, "name", name)
  end
  defp update_user_name(user, _params), do: user

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.apple_user[uid_field]
  end

  @doc """
  Includes the credentials from the Apple response.
  """
  def credentials(conn) do
    token = conn.private.apple_token
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",")

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      scopes: scopes,
      token_type: Map.get(token, :token_type),
      refresh_token: token.refresh_token,
      token: token.access_token
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.apple_user

    put_name(%Info{
      email: user["email"]
    }, user["name"])
  end

  defp put_name(params, name) when is_binary(name) do
    Map.put(params, :name, name)
  end
  defp put_name(params, name) when is_map(name) or is_list(name) do
    params
    |> Map.put(:first_name, name["firstName"])
    |> Map.put(:last_name, name["lastName"])
  end
  defp put_name(params, _), do: params

  @doc """
  Stores the raw information (including the token) obtained from the google callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.apple_token,
        user: conn.private.apple_user
      }
    }
  end

  defp with_param(opts, key, conn) do
    if value = conn.params[to_string(key)], do: Keyword.put(opts, key, value), else: opts
  end

  defp with_optional(opts, key, conn) do
    if option(conn, key), do: Keyword.put(opts, key, option(conn, key)), else: opts
  end

  defp oauth_client_options_from_conn(conn) do
    base_options = [redirect_uri: callback_url(conn)]
    request_options = conn.private[:ueberauth_request_options].options

    case {request_options[:client_id], request_options[:client_secret]} do
      {nil, _} -> base_options
      {_, nil} -> base_options
      {id, secret} -> [client_id: id, client_secret: secret] ++ base_options
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
