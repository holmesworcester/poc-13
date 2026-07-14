defmodule TinyP2P.LanguageLab.Runtime do
  alias TinyP2P.LanguageLab.{Atom, Kernel, Node}

  @bound 64

  @spec cycle(Node.t(), [binary()], non_neg_integer(), [binary()], non_neg_integer()) :: Node.t()
  def cycle(node, inbox, now_ms, shipped \\ [], bound \\ @bound) do
    node =
      Enum.reduce(inbox, node, fn data, acc ->
        {next, _owner} = Kernel.admit(acc, data)
        next
      end)

    Kernel.turn(node, now_ms, shipped, bound)
  end

  @spec outbox(Node.t()) :: [TinyP2P.LanguageLab.Row.t()]
  def outbox(node) do
    Kernel.watched(node, "send", "outbox") ++ Kernel.watched(node, "ship", "outbox")
  end

  @spec pump(Node.t(), function(), function(), MapSet.t(binary()), map()) ::
          {MapSet.t(binary()), map()}
  def pump(node, route, deliver, shipped, sent \\ %{}) do
    grouped =
      node
      |> outbox()
      |> Enum.reject(&MapSet.member?(shipped, &1.owner))
      |> Enum.group_by(& &1.owner, & &1.atom)
      |> Enum.sort_by(fn {owner, _atoms} -> owner end)

    Enum.reduce(grouped, {MapSet.new(), sent}, fn {owner, atoms}, {fired, sent_acc} ->
      cid = atoms |> hd() |> Map.fetch!(:target) |> target_low()

      case route.(cid) do
        nil ->
          {fired, sent_acc}

        {address, secret} ->
          seen = Map.get(sent_acc, cid, MapSet.new())
          candidates = shipment_candidates(atoms, node.durable, seen)
          inners = Enum.map(candidates, &elem(&1, 0))
          keys = Enum.map(candidates, &elem(&1, 1))

          delivered =
            if inners == [] do
              0
            else
              inners
              |> then(&deliver.(cid, address, secret, &1))
              |> max(0)
              |> min(length(inners))
            end

          seen =
            keys
            |> Enum.take(delivered)
            |> Enum.reject(&is_nil/1)
            |> Enum.reduce(seen, &MapSet.put(&2, &1))

          {MapSet.put(fired, owner), Map.put(sent_acc, cid, seen)}
      end
    end)
  end

  @spec wire_message(0..255, binary()) :: binary()
  def wire_message(kind, body) when kind in 0..255 and is_binary(body) do
    payload = <<kind, body::binary>>

    if byte_size(payload) >= 4_294_967_296 do
      raise ArgumentError, "wire payload must be shorter than 2^32 bytes"
    end

    <<byte_size(payload)::unsigned-big-32, payload::binary>>
  end

  defp shipment_candidates(atoms, durable, seen) do
    atoms
    |> Enum.sort_by(fn atom -> {atom.role, atom.value || <<>>} end)
    |> Enum.flat_map(fn
      %Atom{role: "send", value: value} when is_binary(value) ->
        [{value, nil}]

      %Atom{role: "ship", value: value} when is_binary(value) ->
        case Kernel.unframe(value) do
          {:ok, fact_ids} ->
            for fact_id <- fact_ids,
                Map.has_key?(durable, fact_id),
                not MapSet.member?(seen, fact_id) do
              {Map.fetch!(durable, fact_id), fact_id}
            end

          {:error, reason} ->
            raise ArgumentError, "invalid ship id framing: #{inspect(reason)}"
        end

      _other ->
        []
    end)
  end

  defp target_low({:exact, value}), do: value
  defp target_low({:range, low, _high}), do: low
end

defmodule TinyP2P.LanguageLab.WireDecoder do
  alias TinyP2P.LanguageLab.WireDecoder

  defstruct buffer: <<>>

  @type t :: %__MODULE__{buffer: binary()}

  @spec feed(t(), binary()) :: {[{0..255, binary()}], t()}
  def feed(%__MODULE__{} = decoder, data) when is_binary(data) do
    {messages, buffer} = decode(decoder.buffer <> data, [])
    {messages, %WireDecoder{buffer: buffer}}
  end

  defp decode(<<size::unsigned-big-32, rest::binary>>, messages)
       when byte_size(rest) >= size do
    <<payload::binary-size(size), tail::binary>> = rest

    case payload do
      <<>> -> decode(tail, messages)
      <<kind, body::binary>> -> decode(tail, [{kind, body} | messages])
    end
  end

  defp decode(buffer, messages), do: {Enum.reverse(messages), buffer}
end

defmodule TinyP2P.LanguageLab.OutLink do
  alias TinyP2P.LanguageLab.Runtime

  @enforce_keys [:capacity, :chunks]
  defstruct [:capacity, :chunks, head_offset: 0, pending: 0]

  @type t :: %__MODULE__{
          capacity: non_neg_integer(),
          chunks: :queue.queue(binary()),
          head_offset: non_neg_integer(),
          pending: non_neg_integer()
        }

  @spec new(non_neg_integer()) :: t()
  def new(capacity) when is_integer(capacity) and capacity >= 0 do
    %__MODULE__{capacity: capacity, chunks: :queue.new()}
  end

  @spec enqueue(t(), 0..255, binary()) :: {:ok, t()} | {:error, :full, t()}
  def enqueue(%__MODULE__{} = link, kind, body) do
    message = Runtime.wire_message(kind, body)

    if link.pending + byte_size(message) > link.capacity do
      {:error, :full, link}
    else
      {:ok,
       %{
         link
         | chunks: :queue.in(message, link.chunks),
           pending: link.pending + byte_size(message)
       }}
    end
  end

  @spec take(t(), integer()) :: {binary(), t()}
  def take(%__MODULE__{} = link, size) when is_integer(size) and size <= 0, do: {<<>>, link}

  def take(%__MODULE__{} = link, size) when is_integer(size) do
    wanted = min(size, link.pending)

    {chunks, head_offset, pieces, consumed} =
      take_chunks(link.chunks, link.head_offset, wanted, [], 0)

    data = pieces |> Enum.reverse() |> IO.iodata_to_binary()

    {data,
     %{
       link
       | chunks: chunks,
         head_offset: head_offset,
         pending: link.pending - consumed
     }}
  end

  defp take_chunks(chunks, head_offset, 0, pieces, consumed) do
    {chunks, head_offset, pieces, consumed}
  end

  defp take_chunks(chunks, head_offset, wanted, pieces, consumed) do
    case :queue.out(chunks) do
      {:empty, _chunks} ->
        {chunks, 0, pieces, consumed}

      {{:value, chunk}, tail} ->
        available = byte_size(chunk) - head_offset
        amount = min(available, wanted)
        piece = binary_part(chunk, head_offset, amount)

        if amount == available do
          take_chunks(tail, 0, wanted - amount, [piece | pieces], consumed + amount)
        else
          {chunks, head_offset + amount, [piece | pieces], consumed + amount}
        end
    end
  end
end
