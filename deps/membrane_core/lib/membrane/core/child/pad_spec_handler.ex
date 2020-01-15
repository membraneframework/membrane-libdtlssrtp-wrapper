defmodule Membrane.Core.Child.PadSpecHandler do
  @moduledoc false
  # Module parsing pads specifications in elements and bins.

  alias Membrane.{Core, Pad}
  alias Core.{Bin, Element}
  alias Core.Child.PadModel
  require Pad
  use Bunch
  use Core.Element.Log

  @private_input_pad_spec_keys [:demand_unit]

  @doc """
  Initializes pads info basing on element's or bin's pads specifications.
  """
  @spec init_pads(Element.State.t() | Bin.State.t()) ::
          Element.State.t() | Bin.State.t()
  def init_pads(%{module: module} = state) do
    pads = %{
      data: %{},
      info:
        module.membrane_pads()
        |> add_private_pads()
        |> Bunch.KVList.map_values(&init_pad_info/1)
        |> Map.new(),
      dynamic_currently_linking: []
    }

    state
    |> Map.put(:pads, pads)
  end

  @spec init_pad_info(Pad.description_t()) :: PadModel.pad_info_t()
  defp init_pad_info(specs) do
    specs |> Bunch.Map.move!(:caps, :accepted_caps)
  end

  @spec add_private_pads([{Pad.name_t(), Pad.description_t()}]) :: [
          {Pad.name_t(), Pad.description_t()}
        ]
  def add_private_pads(module_pads) do
    Enum.flat_map(module_pads, &create_private_pad/1)
  end

  defp create_private_pad({_name, %{bin?: false}} = pad) do
    [pad]
  end

  defp create_private_pad({name, spec}) do
    priv_bin_name = Pad.create_private_name(name)

    public_spec = filter_opts(spec)

    priv_spec = filter_opts(%{spec | direction: Pad.opposite_direction(spec.direction)})

    [{name, public_spec}, {priv_bin_name, priv_spec}]
  end

  defp filter_opts(%{direction: :input} = spec), do: spec

  defp filter_opts(%{direction: :output} = spec),
    do: Map.drop(spec, @private_input_pad_spec_keys)
end
