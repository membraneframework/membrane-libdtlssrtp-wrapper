defmodule Membrane.Core.Element.CapsController do
  @moduledoc false
  # Module handling caps received on input pads.

  alias Membrane.{Caps, Core, Element, Pad}
  alias Core.{CallbackHandler, InputBuffer}
  alias Core.Child.PadModel
  alias Core.Element.{ActionHandler, State}
  alias Element.CallbackContext
  require CallbackContext.Caps
  require PadModel
  use Core.Element.Log
  use Bunch

  @doc """
  Handles incoming caps: either stores them in InputBuffer, or executes element callback.
  """
  @spec handle_caps(Pad.ref_t(), Caps.t(), State.t()) :: State.stateful_try_t()
  def handle_caps(pad_ref, caps, state) do
    PadModel.assert_data!(state, pad_ref, %{direction: :input})
    data = PadModel.get_data!(state, pad_ref)

    if data.mode == :pull and not (data.input_buf |> InputBuffer.empty?()) do
      state |> PadModel.update_data(pad_ref, :input_buf, &(&1 |> InputBuffer.store(:caps, caps)))
    else
      exec_handle_caps(pad_ref, caps, state)
    end
  end

  @spec exec_handle_caps(Pad.ref_t(), Caps.t(), params :: map, State.t()) ::
          State.stateful_try_t()
  def exec_handle_caps(pad_ref, caps, params \\ %{}, state) do
    %{accepted_caps: accepted_caps} = PadModel.get_data!(state, pad_ref)

    context = &CallbackContext.Caps.from_state(&1, pad: pad_ref)

    withl match: true <- Caps.Matcher.match?(accepted_caps, caps),
          callback:
            {:ok, state} <-
              CallbackHandler.exec_and_handle_callback(
                :handle_caps,
                ActionHandler,
                %{context: context} |> Map.merge(params),
                [pad_ref, caps],
                state
              ) do
      {:ok, PadModel.set_data!(state, pad_ref, :caps, caps)}
    else
      match: false ->
        warn_error(
          """
          Received caps: #{inspect(caps)} that are not specified in def_input_pad
          for pad #{inspect(pad_ref)}. Specs of accepted caps are:
          #{inspect(accepted_caps, pretty: true)}
          """,
          :invalid_caps,
          state
        )

      callback: {{:error, reason}, state} ->
        warn_error("Error while handling caps", reason, state)
    end
  end
end
