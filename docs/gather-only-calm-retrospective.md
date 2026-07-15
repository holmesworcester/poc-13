# Gather-only relationships: a CALM boundary retrospective

Status: experiment completed on `codex/projector-owned-gathers` at `a4a3ab3`;
not merged. The four-relationship design remains on `main`.

## TL;DR

Collapsing `Require`, `SuppressIf`, and `Gather` into one `Gather` worked as a
language simplification and cost almost nothing in ordinary projection time. It
also opened a can of consistency and CALM-theorem-violation worms.

More precisely, the experiment did not disprove or violate CALM. It crossed the
boundary CALM predicts: once projectors may interpret missing or newly arriving
matches as reasons to retract output or physically delete facts, the program is
non-monotone. A generic engine can no longer obtain deterministic results from
arrival-independent set growth alone. It needs a closed-world boundary,
stratification, coordination, or conservative rejection.

The old relationships were not extra matching power. They were declarations of
monotonicity and effect. Removing them made the atom vocabulary smaller while
moving their proof obligations into a much larger consistency protocol.

## The question

The starting design has four relationships over the same matching operation:

- `Provide`: declare a candidate output;
- `Gather`: observe every match, including the empty set;
- `Require`: the same matches, but park while empty;
- `SuppressIf`: the same matches, but evict while nonempty.

That invites an obvious simplification. `Require` and `SuppressIf` do not add
expressive power: a total projector can inspect an ordinary Gather context,
return no output while authority is absent, and request deletion when a
tombstone is present. The proposed algebra was therefore just:

```text
Provide | Gather

project(fact, partial_context) -> tuple[Provide, ...] | DROP
```

Every Gather would receive all currently projected matches. Projectors would
own readiness, authorization, optional observation, and deletion.

The hypothesis was that this would remove kernel modes without materially
changing performance or behavior.

## What worked

The syntactic and local execution parts worked well.

- Facts need only two relationship tags.
- Every consumer uses one matching and wake path.
- Projectors are total over empty and partial context.
- Readiness becomes a cheap family preflight.
- `DROP` is an uncombinable result, so a handler cannot publish and delete in
  one outcome.
- A returned Provide must fit a declared output capability, so a projector may
  derive values or narrow a Range but cannot mint an undiscoverable address.
- Cold matching works in both directions: a resident Gather faults cold
  potential providers, and a stable new Provide faults old cold Gather owners.
- Every Gather match can be treated conservatively as windowed-sync closure.

The ordinary replay cost was small. With ten dependencies, the measured cost
was about 171 µs with engine-owned `Require` versus 175 µs with projector-owned
Gather when dependencies settled together: roughly 2%. Ten separate arrival
waves measured about 256 µs versus 284 µs: roughly 11%, or 28 µs total. Facts
were not re-decoded, re-hashed, or re-verified; the additional work was the
projector's partial-context preflight.

The completed branch passed 214 tests and every performance budget. This was
not a failed implementation. It was a successful experiment that exposed where
the semantic complexity had been hiding.

## Where the worms came from

### Absence stopped being local information

A Gather returning no rows means only “no projected resident match has been
found yet.” It does not mean that no matching durable fact exists. The provider
may be cold, its authority may be cold, or a fact that will derive the provider
may not have projected yet.

`Require` made this less dangerous by treating presence as a positive gate.
`SuppressIf` paired its negative effect with an exhaustive cold lookup. Once
both became opaque projector branches, the kernel could no longer tell which
empty or nonempty observations would become irreversible decisions.

The experiment therefore needed quiescent evaluation and symmetric cold
faulting before it could trust a deletion result.

### Retraction is non-monotone

Adding a match can cause a projector to publish more output, which is monotone.
But it can also cause a projector to retract existing output or return `DROP`.
Conversely, removing one owner's standing can make another projector publish a
rescue. These results do not commute with arbitrary evaluation order.

Immediate deletion was unsafe. An ordinary `DROP` had to become provisional:
keep the fact and its current standing, drain resident and cold consequences,
then ask the projector again at quiescence. Only a repeated `DROP` could purge.

### Structural dependency no longer carried polarity

With `Require` and `SuppressIf`, a dependency graph says which edges are
positive and which are negative. The engine can state a stratification rule:
no fact may depend on its own validity through a negative path.

With Gather alone, the same edge might mean:

- authority that enables output;
- optional context that changes nothing;
- evidence that retracts one output and publishes another;
- a tombstone that requests physical deletion.

The kernel cannot recover that polarity by inspecting atoms. Static structure
is necessarily an over-approximation of arbitrary projector code.

### FactId order threatened to become semantics

Suppose two owners are both pending deletion. Withdrawing A may wake a projector
that rescues B; withdrawing B first may instead rescue A. Deleting both as a
batch skips the rescue. Choosing the lower FactId gives a deterministic
implementation but not a content-independent meaning: changing unrelated fact
bytes can change which valid state survives.

The experiment refused that shortcut. Structurally upstream deletions could
proceed directly, but a remaining cycle required a semantic counterfactual for
each possible first choice.

### Final rows were not the whole observable result

Two deletion orders can end with the same facts and projected rows while
producing different intermediate pulses. A pulse may latch another fact or be
folded by a family observer into a register such as the sync treap. A
simultaneous deletion can also erase a pulse that every legal sequential
execution would expose.

Consequently, confluence had to include the sequential event trace and ordered
observer-visible deltas, not merely the final clean set.

### Latent output needed a declaration after all

Cold lookup and deletion analysis must discover output before running a cold
projector. Once arbitrary projectors could derive Provides, asserted Provides
had to become output capabilities. A projector could select a capability,
derive its value, or narrow its target, but not publish a new address.

This restored discoverability, but it is instructive: removing semantic
relationships immediately required adding another declaration that constrains
projector behavior. The system cannot safely make every relevant property
implicit in code and still reason about cold state without executing that code.

## The safety protocol the collapse required

The resulting deletion path was roughly:

```text
DROP
  -> retain current standing and mark pending
  -> drain resident consequences
  -> fault stable cold matches in both directions
  -> re-judge at quiescence
  -> confirm structurally upstream owners
  -> for a remaining cycle:
       clone resident state behind a non-destructive Store view
       hold one candidate standing
       settle competitors one at a time
       re-project every affected intermediate
       explore relevant cold closure
       compare complete continuations
  -> replay a confluent continuation, or reject the cycle
  -> withdraw standing and physically purge the owner
```

The cold portion needed its own discipline. A new Provide can expose an old
cold Gather owner that rescues a pending deletion, but a Provide causally
dependent on pending standing may itself be transient. Such edges were first
probed for existence and then explored in a private twin. They could enter the
real node only after their pending causes were proven stable. Speculative twins
were forbidden from confirming their own deletions, lest a read-only cold probe
mutate state or fail on an unrelated negative cycle.

This protocol is conservative. A cycle with no independently valid first
choice, or with valid first choices that produce different pulse-preserving
normal forms, fails closed as unstratified. The dynamic check handles useful
cases, but it is not a static proof of arbitrary projector programs.

## The CALM reading

CALM says, in practical terms, that monotone distributed computations can be
made eventually consistent without coordination, while non-monotone decisions
require coordination or equivalent knowledge that the relevant input is
complete.

The important distinction is between the durable fact substrate and its
materialized interpretation:

- Adding immutable facts is monotone.
- Adding a durable tombstone fact can also be monotone at the fact-set level.
- Hiding or physically deleting the tombstone's target is a retraction in the
  materialized view.
- Treating the current absence of authority or evidence as final is
  non-monotone unless a closed-world boundary establishes completeness.

The experiment kept the replicated cause monotone—a tombstone survives and can
delete a re-shipped target—but allowed local projectors to make non-monotone
materialization decisions. Quiescence, cold-closure exploration,
stratification checks, and continuation comparison became the local
coordination machinery needed to make those decisions independent of scheduler
and FactId order.

So “CALM violation” is useful shorthand for the smell, but the theorem behaved
exactly as advertised. We erased the syntax that identified monotone and
non-monotone edges, then paid to rediscover enough consistency at runtime.

## Quantitative result

The surface became smaller; the safe implementation did not.

| Measure | Four relationships on `main` | Gather-only experiment |
|---|---:|---:|
| Relationship variants | 4 | 2 |
| `kernel.py` | 687 lines | 1,148 lines |
| `bin/runtime.py` | 121 lines | 119 lines |
| Ten dependencies, one settlement | ~171 µs | ~175 µs |
| Ten dependencies, ten waves | ~256 µs | ~284 µs |

Kernel size increased by 461 lines, about 67%. The removed relationship
dispatch, parking, validity memo, and reap path were outweighed by output
capabilities, reverse cold faulting, provisional deletion, causal influence,
non-destructive semantic twins, cold-rescue logic, confluence comparison, and
physical purge bookkeeping.

Approximately 300 lines belonged to the DROP/cold-counterfactual safety path.
Those lines could disappear only by trusting projector deletion order, adopting
a stronger restricted language, or accepting accidental deletion.

## What the original relationships were buying

The experiment changed the interpretation of the four-relationship design.
`Require` and `SuppressIf` are not redundant matching operators; they are
compact declarations used by the generic engine:

- `Require` identifies a positive dependency and a readiness boundary.
- `SuppressIf` identifies a negative edge, gives it precedence, and makes its
  cold lookup explicit.
- Their distinction exposes stratification structure without inspecting
  projector code.
- Their asserted matches define conservative sync closure and hydration.
- `Gather` remains available for observations whose polarity belongs entirely
  to the projector.

In other words, four relationships encode proof-relevant information. The
two-relationship form is expressively complete, but loses information the
engine needs for simple, generic safety.

## Better directions if this is revisited

There are three coherent choices.

1. **Keep the four relationships.** This is the pragmatic result of the
   experiment. Matching remains unified while polarity and effect remain
   declarative.
2. **Define a genuinely monotone Gather-only sublanguage.** Projectors may add
   derived output but never retract or inspect absence as final. Deletion stays
   as an immutable tombstone in the fact set and is interpreted at a separate,
   explicitly non-monotone boundary.
3. **Keep Gather-only and declare effects elsewhere.** For example, annotate
   projector inputs as positive, negative, or observational and compile strata.
   This may be a good language design, but it recreates the semantic information
   removed from the atom relationships.

The tempting fourth choice—arbitrary total projectors plus immediate `DROP`—is
short, fast, and underspecified. Its meaning depends on arrival, residency, and
FactId order. It is not an acceptable deletion model.

## Conclusion

The experiment's useful result is not that Gather-only cannot work. It can, and
its steady-state performance is fine. The result is that relationship count was
the wrong complexity metric.

The hard semantics were positive dependence, negative dependence, absence,
retraction, cold completeness, and physical deletion. Removing their names did
not remove them. It moved them from a small declarative algebra into a dynamic
consistency protocol that was harder to explain, test, and trust.

Fewer nouns gave us more machinery. CALM told us why.
