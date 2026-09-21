"""Strategy base class.

A `Strategy` transforms a generated attack prompt to probe whether a target's
defences can be bypassed by framing or obfuscation. It sits between plugin
generation and target execution.

Each strategy produces new TestCases (metadata["strategy"] set to the strategy
id) rather than modifying the originals — the unmodified baseline is always
graded alongside augmented cases.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from plugins.base import TestCase

if TYPE_CHECKING:
    from plugins.base import Generator


class Strategy(ABC):
    """Transforms a generated attack prompt to probe defence bypasses.

    Subclass and implement `apply()`. `apply_to_cases()` handles TestCase
    bookkeeping so concrete strategies only need to transform text.
    """

    id: str = ""

    #: One-line summary of what this strategy does and what it probes for.
    #: Surfaced in the UI next to the strategy's checkbox.
    description: str = ""

    #: True when apply() calls the generation model, so callers know this
    #: strategy costs one API call per prompt and is worth parallelising.
    uses_llm: bool = False

    #: True when the strategy needs the target's responses to decide its next
    #: move. apply() cannot express that, so the runner drives these at
    #: evaluation time via run_conversation() instead of the strategy phase.
    interactive: bool = False

    #: True when this strategy is an *amplifier* rather than a peer framing: it
    #: is orthogonal to what the attack asks for, so instead of being applied
    #: beside the other strategies it is composed as the OUTER layer over each
    #: of them. Only a no-LLM strategy should carry this — an amplifier runs on
    #: every variant, so an API call here multiplies across the whole run.
    amplifier: bool = False

    #: False when wrapping this strategy's output in an amplifier would change
    #: what it probes. Composition is otherwise on wherever an amplifier is
    #: configured, because it costs no extra call and measures stronger.
    composable: bool = True

    def amplified_by(self, amplifier: "Strategy | None") -> bool:
        """True when `amplifier` should wrap this strategy's output.

        An interactive strategy is never amplified: its apply() is a pass-through
        that seeds a conversation, and wrapping that seed would change what the
        refinement loop starts from without changing any later turn.
        """
        return (
            amplifier is not None
            and amplifier is not self
            and self.composable
            and not self.interactive
        )

    @abstractmethod
    def apply(
        self,
        prompt: str,
        *,
        purpose: str = "",
        generator: "Generator | None" = None,
    ) -> str:
        """Return a transformed version of `prompt`."""
        raise NotImplementedError

    def apply_to_cases(
        self,
        cases: list[TestCase],
        *,
        generator: "Generator | None" = None,
        amplifier: "Strategy | None" = None,
    ) -> list[TestCase]:
        """Apply this strategy to every case, returning new transformed TestCases.

        Original cases are not modified. Each new case records the strategy id
        and original prompt in its metadata.

        When `amplifier` is given it wraps this strategy's output as the outer
        layer, so the variant is "framed, then stripped of hedging" rather than
        one or the other. The variant count per case is unchanged — the
        amplifier rides along with each framing instead of taking a slot of its
        own — so composition costs nothing and measures stronger.

        The recorded strategy id stays this strategy's own ("fiction", never
        "fiction+refusal-suppression"): amplification is a property of the run,
        not of the variant, so it is reported once in the run header rather than
        smuggled into every id that downstream code has to parse back apart.
        """
        wrap = self.amplified_by(amplifier)
        result: list[TestCase] = []
        for case in cases:
            purpose = case.metadata.get("purpose", "")
            transformed = self.apply(
                case.prompt,
                purpose=purpose,
                generator=generator,
            )
            if wrap:
                transformed = amplifier.apply(
                    transformed, purpose=purpose, generator=generator
                )
            result.append(
                TestCase(
                    prompt=transformed,
                    plugin_id=case.plugin_id,
                    detector_id=case.detector_id,
                    metadata={
                        **case.metadata,
                        "strategy": self.id,
                        "original_prompt": case.prompt,
                    },
                    severity=case.severity,
                    frameworks=case.frameworks,
                    controls=case.controls,
                )
            )
        return result
