defmodule TinyP2P.LanguageLab.Atom do
  @enforce_keys [:kind, :role, :scope, :target]
  defstruct [:kind, :role, :scope, :target, value: nil, effect: :none]

  @type target :: :self | {:exact, binary()} | {:range, binary(), binary()}
  @type t :: %__MODULE__{
          kind: :need | :offer,
          role: binary(),
          scope: binary(),
          target: target(),
          value: binary() | nil,
          effect: :none | :require | :watch | :suppress
        }
end

defmodule TinyP2P.LanguageLab.Fact do
  alias TinyP2P.LanguageLab.Atom

  @enforce_keys [:tag, :atoms]
  defstruct [:tag, :atoms]

  @type t :: %__MODULE__{tag: binary(), atoms: [Atom.t()]}
end

defmodule TinyP2P.LanguageLab.Row do
  alias TinyP2P.LanguageLab.Atom

  @enforce_keys [:owner, :timestamp, :atom]
  defstruct [:owner, :timestamp, :atom]

  @type t :: %__MODULE__{owner: binary(), timestamp: non_neg_integer(), atom: Atom.t()}
end

defmodule TinyP2P.LanguageLab.Out do
  alias TinyP2P.LanguageLab.Atom

  defstruct verdict: :valid, offers: []

  @type verdict :: :unknown | :valid | :invalid | :parked | :suppressed | :reap
  @type t :: %__MODULE__{verdict: verdict(), offers: [Atom.t()]}
end

defmodule TinyP2P.LanguageLab.Root do
  alias TinyP2P.LanguageLab.{Fact, Out}

  @callback extract(Fact.t()) :: boolean()
  @callback project(Fact.t(), list()) :: Out.t() | nil
end

defmodule TinyP2P.LanguageLab.Bucket do
  alias TinyP2P.LanguageLab.Row

  defstruct exact: %{}, ranges: []

  @type t :: %__MODULE__{exact: %{binary() => [Row.t()]}, ranges: [Row.t()]}

  @spec add(t(), Row.t()) :: t()
  def add(%__MODULE__{} = bucket, %Row{atom: %{target: {:exact, point}}} = row) do
    exact = Map.update(bucket.exact, point, [row], &[row | &1])
    %{bucket | exact: exact}
  end

  def add(%__MODULE__{} = bucket, %Row{atom: %{target: {:range, _, _}}} = row) do
    %{bucket | ranges: [row | bucket.ranges]}
  end

  @spec remove(t(), Row.t()) :: t()
  def remove(%__MODULE__{} = bucket, %Row{atom: %{target: {:exact, point}}} = row) do
    rows = bucket.exact |> Map.get(point, []) |> List.delete(row)

    exact =
      if rows == [] do
        Map.delete(bucket.exact, point)
      else
        Map.put(bucket.exact, point, rows)
      end

    %{bucket | exact: exact}
  end

  def remove(%__MODULE__{} = bucket, %Row{atom: %{target: {:range, _, _}}} = row) do
    %{bucket | ranges: List.delete(bucket.ranges, row)}
  end

  @spec matching(t(), TinyP2P.LanguageLab.Atom.target()) :: [Row.t()]
  def matching(%__MODULE__{} = bucket, {:exact, point}) do
    Map.get(bucket.exact, point, []) ++
      Enum.filter(bucket.ranges, fn %Row{atom: %{target: {:range, low, high}}} ->
        low <= point and point <= high
      end)
  end

  def matching(%__MODULE__{} = bucket, {:range, low, high}) do
    bucket.exact
    |> Enum.flat_map(fn
      {point, rows} when low <= point and point <= high -> rows
      _ -> []
    end)
  end

  @spec all(t()) :: [Row.t()]
  def all(%__MODULE__{} = bucket) do
    exact = Enum.flat_map(bucket.exact, fn {_point, rows} -> rows end)

    exact ++ bucket.ranges
  end
end

defmodule TinyP2P.LanguageLab.Node do
  defstruct root: nil,
            durable: %{},
            facts: %{},
            rows: %{},
            memo: %{},
            clean: %{},
            owned: %{},
            frontier: nil,
            queued: nil

  @type t :: %__MODULE__{
          root: module(),
          durable: %{binary() => binary()},
          facts: map(),
          rows: map(),
          memo: map(),
          clean: map(),
          owned: map(),
          frontier: :queue.queue(binary()),
          queued: MapSet.t(binary())
        }
end

defmodule TinyP2P.LanguageLab.Kernel do
  alias TinyP2P.LanguageLab.{Atom, Bucket, Fact, Node, Out, Row}

  @domain "tinyp2p.language-lab.v1"
  @max_frame_size 4_294_967_296
  @now_role "now"
  @now_scope "clock"
  @shipped_role "shipped"
  @shipped_scope "wire"
  @now_owner <<0, "now">>
  @shipped_owner <<0, "shipped">>

  @spec exact(binary()) :: Atom.target()
  def exact(value) when is_binary(value), do: {:exact, value}

  @spec span(binary(), binary()) :: Atom.target()
  def span(value, value) when is_binary(value), do: exact(value)
  def span(low, high) when is_binary(low) and is_binary(high), do: {:range, low, high}

  @spec frame([binary()]) :: binary()
  def frame(parts) when is_list(parts) do
    if Enum.any?(parts, &(not is_binary(&1) or byte_size(&1) >= @max_frame_size)) do
      raise ArgumentError, "frame part must be a binary shorter than 2^32 bytes"
    end

    parts
    |> Enum.map(fn part -> [<<byte_size(part)::little-unsigned-32>>, part] end)
    |> IO.iodata_to_binary()
  end

  @spec unframe(binary()) :: {:ok, [binary()]} | {:error, :truncated}
  def unframe(data) when is_binary(data), do: do_unframe(data, [])

  defp do_unframe(<<>>, parts), do: {:ok, Enum.reverse(parts)}

  defp do_unframe(<<size::little-unsigned-32, rest::binary>>, parts)
       when byte_size(rest) >= size do
    <<part::binary-size(size), tail::binary>> = rest
    do_unframe(tail, [part | parts])
  end

  defp do_unframe(_data, _parts), do: {:error, :truncated}

  @spec encode_atom(Atom.t()) :: binary()
  def encode_atom(%Atom{} = atom) do
    {target_tag, target_parts} = encode_target(atom.target)
    value_parts = if is_nil(atom.value), do: [], else: [atom.value]

    frame([
      <<kind_code(atom.kind), effect_code(atom.effect), target_tag>>,
      atom.role,
      atom.scope
      | target_parts ++ value_parts
    ])
  end

  @spec decode_atom(binary()) :: {:ok, Atom.t()} | {:error, :invalid_atom}
  def decode_atom(data) when is_binary(data) do
    with {:ok, [header, role, scope | rest]} <- unframe(data),
         {:ok, kind, effect, target_tag} <- decode_header(header),
         :ok <- validate_atom(kind, effect, role),
         {:ok, target, value} <- decode_target(target_tag, rest) do
      atom = %Atom{
        kind: kind,
        effect: effect,
        role: role,
        scope: scope,
        target: target,
        value: value
      }

      if encode_atom(atom) == data, do: {:ok, atom}, else: {:error, :invalid_atom}
    else
      _ -> {:error, :invalid_atom}
    end
  end

  @spec make_fact(binary(), [Atom.t()]) :: Fact.t()
  def make_fact(tag, atoms) when is_binary(tag) and is_list(atoms) do
    canonical =
      atoms
      |> Enum.map(&encode_atom/1)
      |> Enum.uniq()
      |> Enum.sort()
      |> Enum.map(&decode_atom!/1)

    %Fact{tag: tag, atoms: canonical}
  end

  @spec encode(Fact.t()) :: binary()
  def encode(%Fact{} = fact), do: frame([fact.tag]) <> atom_blob(fact)

  @spec decode(binary()) :: {:ok, Fact.t()} | {:error, :invalid_fact}
  def decode(data) when is_binary(data) do
    with {:ok, [tag | encoded_atoms]} <- unframe(data),
         true <- strictly_increasing?(encoded_atoms),
         {:ok, atoms} <- decode_atoms(encoded_atoms) do
      fact = %Fact{tag: tag, atoms: atoms}
      if encode(fact) == data, do: {:ok, fact}, else: {:error, :invalid_fact}
    else
      _ -> {:error, :invalid_fact}
    end
  end

  @spec fact_id(Fact.t()) :: binary()
  def fact_id(%Fact{} = fact) do
    :crypto.hash(:sha256, frame([@domain, fact.tag, atom_blob(fact)]))
  end

  @spec covers(Atom.target(), Atom.target()) :: boolean()
  def covers(:self, _need), do: false
  def covers(_offer, :self), do: false
  def covers({:exact, offer}, {:exact, need}), do: offer == need

  def covers({:range, low, high}, {:exact, need}) do
    low <= need and need <= high
  end

  def covers({:exact, offer}, {:range, low, high}) do
    low <= offer and offer <= high
  end

  def covers({:range, _, _}, {:range, _, _}), do: false

  @spec materialize(Atom.t(), binary()) :: Atom.t()
  def materialize(%Atom{target: :self} = atom, owner), do: %{atom | target: exact(owner)}
  def materialize(%Atom{} = atom, _owner), do: atom

  @spec by(list(), binary()) :: [Row.t()]
  def by(context, role) do
    for {%Atom{role: ^role}, rows} <- context, row <- rows, do: row
  end

  @spec new(module()) :: Node.t()
  def new(root) when is_atom(root) do
    %Node{root: root, frontier: :queue.new(), queued: MapSet.new()}
  end

  @spec admit(Node.t(), binary()) :: {Node.t(), binary() | nil}
  def admit(%Node{} = node, data) when is_binary(data) do
    case decode(data) do
      {:ok, fact} -> admit_fact(node, fact, data)
      {:error, _reason} -> {node, nil}
    end
  end

  @spec offers_for(Node.t(), Atom.t()) :: [Row.t()]
  def offers_for(%Node{} = node, %Atom{} = need) do
    matching(node.rows, {:offer, need.role, need.scope}, need.target)
  end

  @spec needs_for(Node.t(), Atom.t()) :: [Row.t()]
  def needs_for(%Node{} = node, %Atom{} = offer) do
    matching(node.rows, {:need, offer.role, offer.scope}, offer.target)
  end

  @spec valid_offers(Node.t(), Atom.t()) :: [Row.t()]
  def valid_offers(%Node{} = node, %Atom{} = need) do
    matching(node.clean, {need.role, need.scope}, need.target)
  end

  @spec watched(Node.t(), binary(), binary()) :: [Row.t()]
  def watched(%Node{} = node, role, scope) do
    node.clean
    |> Map.get({role, scope}, %Bucket{})
    |> Bucket.all()
  end

  @spec turn(Node.t(), non_neg_integer() | nil, [binary()], integer()) :: Node.t()
  def turn(%Node{} = node, now_ms \\ nil, shipped \\ [], bound \\ 64) do
    node = if is_nil(now_ms), do: node, else: present_now(node, now_ms)

    shipped_rows =
      Enum.map(shipped, fn owner ->
        %Row{
          owner: @shipped_owner,
          timestamp: 0,
          atom: %Atom{
            kind: :offer,
            role: @shipped_role,
            scope: @shipped_scope,
            target: exact(owner)
          }
        }
      end)

    node = present(node, @shipped_role, @shipped_scope, shipped_rows)
    steps = min(max(bound, 0), :queue.len(node.frontier))
    drain(node, steps)
  end

  @spec run(Node.t()) :: Node.t()
  def run(%Node{} = node), do: run(node, 100_000)

  defp run(%Node{} = node, 0) do
    if :queue.is_empty(node.frontier), do: node, else: raise("no quiescence")
  end

  defp run(%Node{} = node, turns_left) do
    if :queue.is_empty(node.frontier) do
      node
    else
      node |> turn() |> run(turns_left - 1)
    end
  end

  defp decode_atom!(data) do
    case decode_atom(data) do
      {:ok, atom} -> atom
      {:error, _reason} -> raise ArgumentError, "invalid atom"
    end
  end

  defp atom_blob(%Fact{} = fact) do
    fact.atoms
    |> Enum.map(fn atom -> frame([encode_atom(atom)]) end)
    |> IO.iodata_to_binary()
  end

  defp decode_atoms(encoded_atoms) do
    encoded_atoms
    |> Enum.reduce_while({:ok, []}, fn encoded, {:ok, atoms} ->
      case decode_atom(encoded) do
        {:ok, atom} -> {:cont, {:ok, [atom | atoms]}}
        {:error, _reason} -> {:halt, {:error, :invalid_fact}}
      end
    end)
    |> case do
      {:ok, atoms} -> {:ok, Enum.reverse(atoms)}
      error -> error
    end
  end

  defp strictly_increasing?([]), do: true
  defp strictly_increasing?([_one]), do: true

  defp strictly_increasing?([left, right | rest]) do
    left < right and strictly_increasing?([right | rest])
  end

  defp encode_target({:exact, value}), do: {0, [value]}
  defp encode_target(:self), do: {1, []}
  defp encode_target({:range, value, value}), do: {0, [value]}
  defp encode_target({:range, low, high}), do: {2, [low, high]}

  defp decode_target(:exact, [point]), do: {:ok, exact(point), nil}
  defp decode_target(:exact, [point, value]), do: {:ok, exact(point), value}
  defp decode_target(:self, []), do: {:ok, :self, nil}
  defp decode_target(:self, [value]), do: {:ok, :self, value}
  defp decode_target(:range, [low, high]), do: {:ok, span(low, high), nil}
  defp decode_target(:range, [low, high, value]), do: {:ok, span(low, high), value}
  defp decode_target(_target_tag, _rest), do: {:error, :invalid_atom}

  defp decode_header(<<kind, effect, target_tag>>) do
    with {:ok, decoded_kind} <- decode_kind(kind),
         {:ok, decoded_effect} <- decode_effect(effect),
         {:ok, decoded_target} <- decode_target_tag(target_tag) do
      {:ok, decoded_kind, decoded_effect, decoded_target}
    end
  end

  defp decode_header(_header), do: {:error, :invalid_atom}

  defp validate_atom(:offer, effect, _role) when effect != :none,
    do: {:error, :invalid_atom}

  defp validate_atom(kind, effect, <<0, _rest::binary>>) do
    if kind == :need and effect == :watch, do: :ok, else: {:error, :invalid_atom}
  end

  defp validate_atom(_kind, _effect, _role), do: :ok

  defp kind_code(:need), do: 0
  defp kind_code(:offer), do: 1
  defp effect_code(:none), do: 0
  defp effect_code(:require), do: 1
  defp effect_code(:watch), do: 2
  defp effect_code(:suppress), do: 3

  defp decode_kind(0), do: {:ok, :need}
  defp decode_kind(1), do: {:ok, :offer}
  defp decode_kind(_kind), do: {:error, :invalid_atom}
  defp decode_effect(0), do: {:ok, :none}
  defp decode_effect(1), do: {:ok, :require}
  defp decode_effect(2), do: {:ok, :watch}
  defp decode_effect(3), do: {:ok, :suppress}
  defp decode_effect(_effect), do: {:error, :invalid_atom}
  defp decode_target_tag(0), do: {:ok, :exact}
  defp decode_target_tag(1), do: {:ok, :self}
  defp decode_target_tag(2), do: {:ok, :range}
  defp decode_target_tag(_target_tag), do: {:error, :invalid_atom}

  defp admit_fact(%Node{} = node, %Fact{} = fact, data) do
    owner = fact_id(fact)

    if Map.has_key?(node.facts, owner) do
      {node, owner}
    else
      node = %{
        node
        | facts: Map.put(node.facts, owner, fact),
          memo: Map.put(node.memo, owner, :unknown)
      }

      node =
        if apply(node.root, :extract, [fact]) do
          %{node | durable: Map.put(node.durable, owner, data)}
        else
          node
        end

      node =
        Enum.reduce(fact.atoms, node, fn atom, acc ->
          row = %Row{owner: owner, timestamp: 0, atom: materialize(atom, owner)}
          key = {atom.kind, atom.role, atom.scope}
          %{acc | rows: add_to_index(acc.rows, key, row)}
        end)

      {enqueue(node, owner), owner}
    end
  end

  defp matching(index, key, target) do
    index
    |> Map.get(key, %Bucket{})
    |> Bucket.matching(target)
  end

  defp add_to_index(index, key, row) do
    bucket = index |> Map.get(key, %Bucket{}) |> Bucket.add(row)
    Map.put(index, key, bucket)
  end

  defp remove_from_index(index, key, row) do
    case Map.fetch(index, key) do
      {:ok, bucket} -> Map.put(index, key, Bucket.remove(bucket, row))
      :error -> index
    end
  end

  defp present_now(node, now_ms) when is_integer(now_ms) and now_ms >= 0 do
    encoded_now = <<now_ms::unsigned-big-64>>

    row = %Row{
      owner: @now_owner,
      timestamp: now_ms,
      atom: %Atom{
        kind: :offer,
        role: @now_role,
        scope: @now_scope,
        target: exact(encoded_now)
      }
    }

    present(node, @now_role, @now_scope, [row])
  end

  defp present(node, role, scope, rows) do
    bucket = Enum.reduce(rows, %Bucket{}, fn row, acc -> Bucket.add(acc, row) end)
    node = %{node | clean: Map.put(node.clean, {role, scope}, bucket)}
    Enum.reduce(rows, node, fn row, acc -> wake(acc, row.atom) end)
  end

  defp drain(node, 0), do: node

  defp drain(node, remaining) do
    {{:value, owner}, frontier} = :queue.out(node.frontier)
    node = %{node | frontier: frontier, queued: MapSet.delete(node.queued, owner)}
    node |> step(owner) |> drain(remaining - 1)
  end

  defp step(node, owner) do
    case Map.fetch(node.facts, owner) do
      :error -> node
      {:ok, fact} -> evaluate(node, owner, fact)
    end
  end

  defp evaluate(node, owner, fact) do
    needs =
      for %Atom{kind: :need} = atom <- fact.atoms do
        materialize(atom, owner)
      end

    output =
      cond do
        Enum.any?(needs, fn need ->
          need.effect == :suppress and valid_offers(node, need) != []
        end) ->
          %Out{verdict: :suppressed}

        Enum.any?(needs, fn need ->
          need.effect == :require and valid_offers(node, need) == []
        end) ->
          %Out{verdict: :parked}

        true ->
          context =
            for need <- needs, need.effect in [:require, :watch] do
              {need, valid_offers(node, need)}
            end

          apply(node.root, :project, [fact, context]) || %Out{verdict: :parked}
      end

    settle(node, owner, fact, output)
  end

  defp settle(node, owner, fact, %Out{} = output) do
    {old, owned} = Map.pop(node.owned, owner, [])
    node = %{node | memo: Map.put(node.memo, owner, output.verdict), owned: owned}

    node =
      Enum.reduce(old, node, fn row, acc ->
        key = {row.atom.role, row.atom.scope}
        %{acc | clean: remove_from_index(acc.clean, key, row)}
      end)

    new =
      if output.verdict == :valid do
        Enum.map(output.offers, fn atom ->
          %Row{owner: owner, timestamp: 0, atom: materialize(atom, owner)}
        end)
      else
        []
      end

    node =
      Enum.reduce(new, node, fn row, acc ->
        key = {row.atom.role, row.atom.scope}
        %{acc | clean: add_to_index(acc.clean, key, row)}
      end)

    node = if new == [], do: node, else: %{node | owned: Map.put(node.owned, owner, new)}

    changed = MapSet.symmetric_difference(MapSet.new(old), MapSet.new(new))
    node = Enum.reduce(changed, node, fn row, acc -> wake(acc, row.atom, owner) end)

    if output.verdict in [:reap, :suppressed], do: evict(node, owner, fact), else: node
  end

  defp evict(node, owner, fact) do
    rows =
      Enum.reduce(fact.atoms, node.rows, fn atom, index ->
        row = %Row{owner: owner, timestamp: 0, atom: materialize(atom, owner)}
        remove_from_index(index, {atom.kind, atom.role, atom.scope}, row)
      end)

    %{
      node
      | facts: Map.delete(node.facts, owner),
        memo: Map.delete(node.memo, owner),
        owned: Map.delete(node.owned, owner),
        durable: Map.delete(node.durable, owner),
        rows: rows
    }
  end

  defp wake(node, offer, skip \\ nil) do
    Enum.reduce(needs_for(node, offer), node, fn row, acc ->
      if row.owner == skip, do: acc, else: enqueue(acc, row.owner)
    end)
  end

  defp enqueue(node, owner) do
    if MapSet.member?(node.queued, owner) do
      node
    else
      %{
        node
        | frontier: :queue.in(owner, node.frontier),
          queued: MapSet.put(node.queued, owner)
      }
    end
  end
end
