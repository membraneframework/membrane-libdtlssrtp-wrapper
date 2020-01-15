defmodule Membrane.CallbackContext do
  @moduledoc """
  Parent module for all contexts passed to callbacks.

  The idea of context is to provide access to commonly used information without
  forcing user to hold it in state. Context differs depending on callback.
  """

  alias Membrane.Pad
  alias Membrane.Core
  alias Core.Element
  alias Core.Bin
  use Bunch

  @macrocallback from_state(Element.State.t() | Bin.State.t(), keyword()) :: Macro.t()

  defmacro __using__(fields) do
    quote do
      default_fields_names = [:pads, :playback_state, :clock, :parent_clock]
      fields_names = unquote(fields |> Keyword.keys())

      @type t :: %__MODULE__{
              unquote_splicing(fields),
              pads: %{Pad.ref_t() => Pad.Data.t()},
              playback_state: Membrane.PlaybackState.t()
            }

      @behaviour unquote(__MODULE__)

      @enforce_keys Module.get_attribute(__MODULE__, :enforce_keys)
                    ~> (&1 || fields_names)
                    |> Bunch.listify()
                    ~> (&1 ++ default_fields_names)

      defstruct fields_names ++ default_fields_names

      @impl true
      defmacro from_state(state, args \\ []) do
        quote do
          state = unquote(state)

          %unquote(__MODULE__){
            unquote_splicing(args),
            playback_state: state.playback.state,
            pads: state.pads.data,
            clock: state.synchronization.clock,
            parent_clock: state.synchronization.parent_clock
          }
        end
      end

      defoverridable unquote(__MODULE__)
    end
  end
end
