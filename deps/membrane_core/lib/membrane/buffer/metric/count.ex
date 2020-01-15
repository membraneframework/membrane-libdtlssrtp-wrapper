defmodule Membrane.Buffer.Metric.Count do
  @moduledoc """
    Implementation of `Membrane.Buffer.Metric` for the `:buffers` unit
  """

  alias Membrane.Buffer
  @behaviour Buffer.Metric

  @impl true
  def input_buf_preferred_size, do: 10

  @impl true
  def buffers_size(buffers), do: length(buffers)

  @impl true
  def split_buffers(buffers, count), do: buffers |> Enum.split(count)
end
