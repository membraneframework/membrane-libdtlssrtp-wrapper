defmodule Membrane.Core.InputBuffer do
  @moduledoc """
  Buffer that is attached to the `:input` pad when working in a `:pull` mode.

  It stores `Membrane.Buffer`, `Membrane.Event` and `Membrane.Caps` structs and
  prevents the situation where the data in a stream contains the discontinuities.
  It also guarantees that element won't be flooded with the incoming data.
  """
  alias Membrane.Buffer
  alias Membrane.Core.Message
  alias Membrane.Element
  alias Membrane.Pad
  require Message
  use Bunch
  use Membrane.Log, tags: :core

  @qe Qex

  @non_buf_types [:event, :caps]

  @type output_value_t :: {:event | :caps, any} | {:buffers, list, pos_integer}
  @type output_t :: {:empty | :value, [output_value_t]}

  @type t :: %__MODULE__{
          name: Element.name_t(),
          q: @qe.t(),
          preferred_size: pos_integer(),
          current_size: non_neg_integer(),
          demand: non_neg_integer(),
          min_demand: pos_integer(),
          metric: module(),
          toilet?: boolean(),
          toilet_props: %{:warn => pos_integer, :fail => pos_integer}
        }

  defstruct name: :input_buf,
            q: nil,
            preferred_size: 100,
            current_size: 0,
            demand: nil,
            min_demand: nil,
            metric: nil,
            toilet?: false,
            toilet_props: nil

  @typedoc """
  Properties that can be passed when creating new InputBuffer

  Available options are:
    * `:preffered_size` - size which will be the 'target' for InputBuffer - it will make demands
      trying to grow to this size. Its default value depends on the set `#{inspect(Buffer.Metric)}` and is
      obtained via `c:#{inspect(Buffer.Metric)}.input_buf_preferred_size/0`
    * `:min_demand` - the minimal size of a demand that can be sent to the linked output pad.
      This prevents from excessive message passing between elements. Defaults to a quarter of
      preferred size.
    * `warn_size` - in toilet mode (connecting push output to pull input pad), receiving more data
      than this size triggers a warning. By default it is equal to twice the preffered size.
    * `fail_size` - in toilet mode (connecting push output to pull input pad), receiving more data
      than this results in an element failure. By default, it is four times the preffered size.
  """
  @type props_t :: [
          {:preferred_size, pos_integer()}
          | {:min_demand, pos_integer()}
          | {:warn_size, pos_integer()}
          | {:fail_size, pos_integer()}
        ]

  @spec parse_props(keyword()) :: {:error, reason :: any()} | {:ok, props_t()}
  def parse_props(input) do
    with {:ok, parsed} <-
           input
           |> List.wrap()
           |> Bunch.Config.parse(
             preferred_size: [default: nil],
             min_demand: [default: nil],
             warn_size: [default: nil],
             fail_size: [default: nil]
           ) do
      {:ok, Enum.to_list(parsed)}
    end
  end

  @spec init(
          Element.name_t(),
          Buffer.Metric.unit_t(),
          pid(),
          Pad.ref_t(),
          props_t
        ) :: t()
  def init(name, demand_unit, demand_pid, demand_pad, props) do
    metric = Buffer.Metric.from_unit(demand_unit)
    preferred_size = props[:preferred_size] || metric.input_buf_preferred_size
    min_demand = props[:min_demand] || preferred_size |> div(4)

    %__MODULE__{
      name: name,
      q: @qe.new(),
      preferred_size: preferred_size,
      min_demand: min_demand,
      demand: preferred_size,
      metric: metric,
      toilet?: false,
      toilet_props: %{
        warn: props[:warn_size] || preferred_size * 2,
        fail: props[:fail_size] || preferred_size * 4
      }
    }
    |> send_demands(demand_pid, demand_pad)
  end

  @spec enable_toilet(t()) :: t()
  def enable_toilet(buf), do: %__MODULE__{buf | toilet?: true}

  @spec store(t(), atom(), any()) :: {:ok, t()} | {:error, any()}
  def store(input_buf, type \\ :buffers, v)

  def store(
        %__MODULE__{current_size: size, preferred_size: pref_size, toilet?: false} = input_buf,
        :buffers,
        v
      )
      when is_list(v) do
    if size >= pref_size do
      debug("""
      InputBuffer #{inspect(input_buf.name)}: received buffers despite not requesting them.
      It is probably caused by overestimating demand by previous element.
      """)
    end

    {:ok, do_store_buffers(input_buf, v)}
  end

  def store(
        %__MODULE__{toilet?: true, toilet_props: %{warn: warn_lvl, fail: fail_lvl}} = input_buf,
        :buffers,
        v
      )
      when is_list(v) do
    %__MODULE__{current_size: size} = input_buf = do_store_buffers(input_buf, v)

    if size >= warn_lvl do
      above_level =
        if size < fail_lvl do
          "warn level"
        else
          "fail level"
        end

      warn([
        """
        InputBuffer #{inspect(input_buf.name)} (toilet) has buffers of size #{inspect(size)},
        which is above #{above_level}, from output working in push mode.
        To have control over amount of buffers being produced, consider using pull mode.
        If this is a normal situation, increase warn/fail size in buffer options.
        """
      ])
    end

    if size >= fail_lvl do
      warn_error(
        "InputBuffer #{inspect(input_buf.name)} (toilet): failing: too much data",
        {:input_buf, toilet: :too_many_buffers}
      )
    else
      {:ok, input_buf}
    end
  end

  def store(input_buf, :buffer, v), do: store(input_buf, :buffers, [v])

  def store(%__MODULE__{q: q} = input_buf, type, v) when type in @non_buf_types do
    report("Storing #{type}", input_buf)
    {:ok, %__MODULE__{input_buf | q: q |> @qe.push({:non_buffer, type, v})}}
  end

  defp do_store_buffers(%__MODULE__{q: q, current_size: size, metric: metric} = input_buf, v) do
    buf_cnt = v |> metric.buffers_size
    report("Storing #{inspect(buf_cnt)} buffers", input_buf)

    %__MODULE__{
      input_buf
      | q: q |> @qe.push({:buffers, v, buf_cnt}),
        current_size: size + buf_cnt
    }
  end

  @spec take_and_demand(t(), non_neg_integer(), pid(), Pad.ref_t()) :: {{:ok, output_t()}, t()}
  def take_and_demand(%__MODULE__{current_size: size} = input_buf, count, demand_pid, demand_pad)
      when count >= 0 do
    report("Taking #{inspect(count)} buffers", input_buf)
    {out, %__MODULE__{current_size: new_size} = input_buf} = do_take(input_buf, count)

    input_buf =
      input_buf
      |> Bunch.Struct.update_in(:demand, &(&1 + size - new_size))
      |> send_demands(demand_pid, demand_pad)

    {{:ok, out}, input_buf}
  end

  defp do_take(%__MODULE__{q: q, current_size: size, metric: metric} = input_buf, count) do
    {out, nq} = q |> q_pop(count, metric)
    {out, %__MODULE__{input_buf | q: nq, current_size: max(0, size - count)}}
  end

  defp q_pop(q, count, metric, acc \\ [])

  defp q_pop(q, count, metric, acc) when count > 0 do
    q
    |> @qe.pop
    |> case do
      {{:value, {:buffers, b, buf_cnt}}, nq} when count >= buf_cnt ->
        q_pop(nq, count - buf_cnt, metric, [{:buffers, b, buf_cnt} | acc])

      {{:value, {:buffers, b, buf_cnt}}, nq} when count < buf_cnt ->
        {b, back} = b |> metric.split_buffers(count)
        nq = nq |> @qe.push_front({:buffers, back, buf_cnt - count})
        {{:value, [{:buffers, b, count} | acc] |> Enum.reverse()}, nq}

      {:empty, nq} ->
        {{:empty, acc |> Enum.reverse()}, nq}

      {{:value, {:non_buffer, type, e}}, nq} ->
        q_pop(nq, count, metric, [{type, e} | acc])
    end
  end

  defp q_pop(q, 0, metric, acc) do
    q
    |> @qe.pop
    |> case do
      {{:value, {:non_buffer, type, e}}, nq} -> q_pop(nq, 0, metric, [{type, e} | acc])
      _ -> {{:value, acc |> Enum.reverse()}, q}
    end
  end

  @spec send_demands(t(), pid(), Pad.ref_t()) :: t()
  defp send_demands(
         %__MODULE__{
           toilet?: false,
           current_size: size,
           preferred_size: pref_size,
           demand: demand,
           min_demand: min_demand
         } = input_buf,
         demand_pid,
         linked_output_ref
       )
       when size < pref_size and demand > 0 do
    to_demand = max(demand, min_demand)

    report(
      """
      Sending demand of size #{inspect(to_demand)}
      to input #{inspect(linked_output_ref)}
      """,
      input_buf
    )

    Message.send(demand_pid, :demand, to_demand, for_pad: linked_output_ref)
    %__MODULE__{input_buf | demand: demand - to_demand}
  end

  defp send_demands(input_buf, _demand_pid, _linked_output_ref) do
    input_buf
  end

  defp report(msg, %__MODULE__{
         name: name,
         current_size: size,
         preferred_size: pref_size,
         toilet?: toilet
       }) do
    name_str =
      if toilet do
        "#{inspect(name)} (toilet)"
      else
        inspect(name)
      end

    debug([
      "InputBuffer #{name_str}: ",
      msg,
      "\n",
      "InputBuffer size: #{inspect(size)}, ",
      if toilet do
        "toilet limits: #{inspect(toilet)}"
      else
        "preferred size: #{inspect(pref_size)}"
      end
    ])
  end

  @spec empty?(t()) :: boolean()
  def empty?(%__MODULE__{current_size: size}), do: size == 0
end
