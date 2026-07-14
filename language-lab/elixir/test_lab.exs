Code.require_file("kernel.exs", __DIR__)
Code.require_file("runtime.exs", __DIR__)

ExUnit.start()

defmodule TinyP2P.LanguageLab.DemoRoot do
  @behaviour TinyP2P.LanguageLab.Root

  alias TinyP2P.LanguageLab.{Kernel, Out}

  @impl true
  def extract(fact), do: fact.tag != "courier"

  @impl true
  def project(fact, context) do
    cond do
      fact.tag == "invalid" ->
        %Out{verdict: :invalid}

      fact.tag == "courier" and Kernel.by(context, "shipped") != [] ->
        %Out{verdict: :reap}

      fact.tag == "clock" and Kernel.by(context, "now") == [] ->
        %Out{}

      fact.tag in ["pass", "courier", "clock"] ->
        %Out{offers: Enum.filter(fact.atoms, &(&1.kind == :offer))}

      true ->
        nil
    end
  end
end

defmodule TinyP2P.LanguageLabTest do
  use ExUnit.Case, async: true

  alias TinyP2P.LanguageLab.{Atom, Bucket, Kernel, OutLink, Row, Runtime, WireDecoder}
  alias TinyP2P.LanguageLab.DemoRoot

  test "canonical construction, strict round trip, golden id, and malformed rejection" do
    result = offer("result", "s", :self, "ok")
    dependency = need("dep", "s", Kernel.exact("key"), :require)
    fact = Kernel.make_fact("pass", [result, dependency, result])
    reordered = Kernel.make_fact("pass", [dependency, result])

    assert fact == reordered
    assert length(fact.atoms) == 2

    blob = Kernel.encode(fact)
    assert {:ok, ^fact} = Kernel.decode(blob)

    assert fact |> Kernel.fact_id() |> Base.encode16(case: :lower) ==
             "33a234f18d975af511b7648e6199ac1db55521a60b811e1478e57fe16943b8c7"

    node = Kernel.new(DemoRoot)
    assert {^node, nil} = Kernel.admit(node, binary_part(blob, 0, byte_size(blob) - 1))

    reversed =
      Kernel.frame([fact.tag]) <>
        (fact.atoms
         |> Enum.reverse()
         |> Enum.map(fn atom -> Kernel.frame([Kernel.encode_atom(atom)]) end)
         |> IO.iodata_to_binary())

    assert {^node, nil} = Kernel.admit(node, reversed)

    duplicate =
      Kernel.frame([fact.tag]) <>
        Kernel.frame([Kernel.encode_atom(hd(fact.atoms))]) <>
        Kernel.frame([Kernel.encode_atom(hd(fact.atoms))])

    assert {^node, nil} = Kernel.admit(node, duplicate)

    degenerate_range = Kernel.frame([<<0, 2, 2>>, "r", "s", "x", "x"])
    malformed = Kernel.frame(["pass"]) <> Kernel.frame([degenerate_range])
    assert {:error, :invalid_fact} = Kernel.decode(malformed)

    extra_part = Kernel.frame([<<0, 2, 0>>, "r", "s", "x", "value", "extra"])
    assert {:error, :invalid_atom} = Kernel.decode_atom(extra_part)

    reserved_offer = Kernel.frame([<<1, 0, 0>>, <<0, "private">>, "s", "x"])
    assert {:error, :invalid_atom} = Kernel.decode_atom(reserved_offer)
  end

  test "exact and range buckets match in both point/range directions" do
    point = %Row{
      owner: "p",
      timestamp: 0,
      atom: offer("r", "s", Kernel.exact("m"))
    }

    ranged = %Row{
      owner: "r",
      timestamp: 0,
      atom: offer("r", "s", Kernel.span("a", "z"))
    }

    bucket = %Bucket{} |> Bucket.add(point) |> Bucket.add(ranged)

    assert MapSet.new(Bucket.matching(bucket, Kernel.exact("m"))) ==
             MapSet.new([point, ranged])

    assert Bucket.matching(bucket, Kernel.span("l", "n")) == [point]
    assert Bucket.matching(bucket, Kernel.span("a", "z")) == [point]
    refute Kernel.covers(Kernel.span("a", "z"), Kernel.span("l", "n"))
  end

  test "Require parks, then a matching validated offer wakes and promotes" do
    dependent =
      Kernel.make_fact("pass", [
        need("dep", "s", Kernel.exact("key"), :require),
        offer("result", "s", :self, "yes")
      ])

    {node, dependent_id} = Kernel.admit(Kernel.new(DemoRoot), Kernel.encode(dependent))
    node = Kernel.run(node)

    assert node.memo[dependent_id] == :parked
    assert Kernel.watched(node, "result", "s") == []

    provider =
      Kernel.make_fact("pass", [offer("dep", "s", Kernel.exact("key"), "ready")])

    {node, _provider_id} = Kernel.admit(node, Kernel.encode(provider))
    node = Kernel.run(node)

    assert node.memo[dependent_id] == :valid
    assert Enum.map(Kernel.watched(node, "result", "s"), & &1.owner) == [dependent_id]
  end

  test "Suppress wins over a missing Require after withdrawal and evicts the whole owner" do
    provider =
      Kernel.make_fact("pass", [
        need("gone", "s", :self, :suppress),
        offer("dep", "s", Kernel.exact("key"), "ready")
      ])

    provider_id = Kernel.fact_id(provider)

    victim =
      Kernel.make_fact("pass", [
        need("dep", "s", Kernel.exact("key"), :require),
        need("dead", "s", :self, :suppress),
        offer("live", "s", :self)
      ])

    victim_id = Kernel.fact_id(victim)
    {node, ^provider_id} = Kernel.admit(Kernel.new(DemoRoot), Kernel.encode(provider))
    {node, ^victim_id} = Kernel.admit(node, Kernel.encode(victim))
    node = Kernel.run(node)

    assert Enum.map(Kernel.watched(node, "live", "s"), & &1.owner) == [victim_id]

    provider_killer =
      Kernel.make_fact("pass", [offer("gone", "s", Kernel.exact(provider_id))])

    {node, _killer_id} = Kernel.admit(node, Kernel.encode(provider_killer))
    node = Kernel.run(node)

    refute Map.has_key?(node.facts, provider_id)
    assert node.memo[victim_id] == :parked
    assert Kernel.watched(node, "live", "s") == []

    victim_killer = Kernel.make_fact("pass", [offer("dead", "s", Kernel.exact(victim_id))])
    {node, _killer_id} = Kernel.admit(node, Kernel.encode(victim_killer))
    node = Kernel.run(node)

    refute Map.has_key?(node.facts, victim_id)
    refute Map.has_key?(node.memo, victim_id)
    refute Map.has_key?(node.durable, victim_id)
    assert Kernel.watched(node, "live", "s") == []
  end

  test "Watch reprojects from clock signals and turns leave bounded work queued" do
    clocked =
      Kernel.make_fact("clock", [
        need(
          "now",
          "clock",
          Kernel.span(<<100::unsigned-big-64>>, :binary.copy(<<255>>, 8)),
          :watch
        ),
        offer("ready", "s", :self)
      ])

    {node, _clocked_id} = Kernel.admit(Kernel.new(DemoRoot), Kernel.encode(clocked))
    node = Kernel.turn(node, 99, [], 1)
    assert Kernel.watched(node, "ready", "s") == []

    node = Kernel.turn(node, 100, [], 1)
    assert length(Kernel.watched(node, "ready", "s")) == 1

    first = Kernel.make_fact("pass", [offer("a", "s", :self)])
    second = Kernel.make_fact("pass", [offer("b", "s", :self)])
    {node, _first_id} = Kernel.admit(node, Kernel.encode(first))
    {node, _second_id} = Kernel.admit(node, Kernel.encode(second))
    node = Kernel.turn(node, nil, [], 1)

    assert :queue.len(node.frontier) == 1
  end

  test "inline courier pump fires, then the shipped signal Reaps it" do
    courier =
      Kernel.make_fact("courier", [
        offer("send", "outbox", Kernel.exact("peer"), "hello"),
        need("shipped", "wire", :self, :watch)
      ])

    courier_id = Kernel.fact_id(courier)
    node = Runtime.cycle(Kernel.new(DemoRoot), [Kernel.encode(courier)], 1)
    parent = self()

    route = fn
      "peer" -> {"127.0.0.1:9", "secret"}
      _other -> nil
    end

    deliver = fn cid, address, secret, inners ->
      send(parent, {:delivered, cid, address, secret, inners})
      length(inners)
    end

    {fired, _sent} = Runtime.pump(node, route, deliver, MapSet.new())

    assert fired == MapSet.new([courier_id])
    assert_receive {:delivered, "peer", "127.0.0.1:9", "secret", ["hello"]}

    node = Runtime.cycle(node, [], 2, MapSet.to_list(fired))
    refute Map.has_key?(node.facts, courier_id)
    assert Runtime.outbox(node) == []
  end

  test "by-reference pump deduplicates the delivered prefix and retries its tail" do
    first = Kernel.make_fact("pass", [offer("data", "s", :self, "one")])
    second = Kernel.make_fact("pass", [offer("data", "s", :self, "two")])
    first_id = Kernel.fact_id(first)
    second_id = Kernel.fact_id(second)

    {node, ^first_id} = Kernel.admit(Kernel.new(DemoRoot), Kernel.encode(first))
    {node, ^second_id} = Kernel.admit(node, Kernel.encode(second))
    node = Kernel.run(node)

    shipper =
      Kernel.make_fact("courier", [
        offer("ship", "outbox", Kernel.exact("peer"), Kernel.frame([first_id, second_id])),
        need("shipped", "wire", :self, :watch)
      ])

    shipper_id = Kernel.fact_id(shipper)
    node = Runtime.cycle(node, [Kernel.encode(shipper)], 1)
    parent = self()

    deliver_one = fn _cid, _address, _secret, inners ->
      send(parent, {:first_batch, Enum.take(inners, 1)})
      1
    end

    {fired, sent} =
      Runtime.pump(node, fn _cid -> {"a", nil} end, deliver_one, MapSet.new(), %{})

    assert fired == MapSet.new([shipper_id])
    assert_receive {:first_batch, [first_blob]}
    assert first_blob == Kernel.encode(first)
    assert sent["peer"] == MapSet.new([first_id])

    deliver_rest = fn _cid, _address, _secret, inners ->
      send(parent, {:second_batch, inners})
      length(inners)
    end

    {_fired, sent} =
      Runtime.pump(node, fn _cid -> {"a", nil} end, deliver_rest, MapSet.new(), sent)

    assert_receive {:second_batch, [second_blob]}
    assert second_blob == Kernel.encode(second)
    assert sent["peer"] == MapSet.new([first_id, second_id])
  end

  test "wire input is incremental and bounded output drains partially without prefix copies" do
    wire = Runtime.wire_message(0, "hello") <> Runtime.wire_message(1, "world")
    decoder = %WireDecoder{}

    {messages, decoder} = WireDecoder.feed(decoder, binary_part(wire, 0, 3))
    assert messages == []

    {messages, decoder} = WireDecoder.feed(decoder, binary_part(wire, 3, 5))
    assert messages == []

    {messages, decoder} =
      WireDecoder.feed(decoder, binary_part(wire, 8, byte_size(wire) - 8))

    assert messages == [{0, "hello"}, {1, "world"}]
    assert decoder.buffer == <<>>

    link = OutLink.new(byte_size(wire))
    {:ok, link} = OutLink.enqueue(link, 0, "hello")
    {:ok, link} = OutLink.enqueue(link, 1, "world")
    assert {:error, :full, ^link} = OutLink.enqueue(link, 1, "overflow")

    {prefix, link} = OutLink.take(link, 3)
    assert link.pending == byte_size(wire) - 3
    {tail, link} = OutLink.take(link, 10_000)

    assert prefix <> tail == wire
    assert link.pending == 0
    assert :queue.is_empty(link.chunks)
  end

  defp offer(role, scope, target, value \\ nil) do
    %Atom{kind: :offer, role: role, scope: scope, target: target, value: value}
  end

  defp need(role, scope, target, effect) do
    %Atom{kind: :need, role: role, scope: scope, target: target, effect: effect}
  end
end
