"""
Base classes for the extensible constraint system.

To add a new constraint type:
1. Create a new Constraint subclass implementing `matches(value) -> bool`.
2. Create a ConstraintParser subclass implementing `parse(annotation_value) -> ConstraintSet`.
3. Register the parser in registry.py.

Negation
--------
Any constraint token may be prefixed with ``!`` to negate it.  A negated
constraint is satisfied when the inner constraint does **not** match.

Within a :class:`ConstraintSet`:

* **Positive** constraints use OR semantics (at least one must match).
* **Negated** constraints use AND semantics (all must be satisfied).
* When both are present, **both** conditions must hold.

Examples::

    "1000,2000"        → value == 1000 OR value == 2000
    "!3000"            → value != 3000
    "1000,2000,!3000"  → (value == 1000 OR value == 2000) AND value != 3000
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Constraint(ABC):
    """A single parsed constraint token.

    A value satisfies the constraint if ``matches`` returns True.
    Subclasses should be immutable and implement ``__repr__`` for error messages.
    """

    @abstractmethod
    def matches(self, value: Any) -> bool:
        """Return True if *value* satisfies this constraint."""

    @abstractmethod
    def __repr__(self) -> str:
        """Human-readable description used in rejection messages."""


class NegatedConstraint(Constraint):
    """Wrapper that inverts a constraint's match result.

    ``NegatedConstraint(c).matches(v)`` is ``not c.matches(v)``.
    """

    def __init__(self, inner: Constraint) -> None:
        self.inner = inner

    def matches(self, value: Any) -> bool:
        return not self.inner.matches(value)

    def __repr__(self) -> str:
        return f"NOT {self.inner!r}"


class ConstraintSet:
    """An ordered collection of constraints parsed from one annotation value.

    Positive constraints are OR-ed; negated constraints are AND-ed.
    When both kinds are present, both conditions must hold.

    Example:  "1000,2000-3000,!5000"  →  (exact(1000) OR range(2000-3000)) AND NOT exact(5000)
    """

    def __init__(self, constraints: list[Constraint]) -> None:
        if not constraints:
            raise ValueError("ConstraintSet must contain at least one Constraint")
        self.constraints = constraints
        self._positive = [c for c in constraints if not isinstance(c, NegatedConstraint)]
        self._negated = [c for c in constraints if isinstance(c, NegatedConstraint)]

    def matches(self, value: Any) -> bool:
        # All negated constraints must be satisfied (AND)
        if not all(c.matches(value) for c in self._negated):
            return False
        # If positive constraints exist, at least one must match (OR)
        if self._positive and not any(c.matches(value) for c in self._positive):
            return False
        return True

    def description(self) -> str:
        parts: list[str] = []
        if self._positive:
            parts.append(" OR ".join(repr(c) for c in self._positive))
        if self._negated:
            parts.append(" AND ".join(repr(c) for c in self._negated))
        return "; ".join(parts)

    def __repr__(self) -> str:
        return f"ConstraintSet([{self.description()}])"


class ConstraintParser(ABC):
    """Parses a raw annotation string into a :class:`ConstraintSet`."""

    @abstractmethod
    def parse(self, annotation_value: str) -> ConstraintSet:
        """Parse *annotation_value* and return the corresponding ConstraintSet.

        Raises ``ValueError`` if the annotation value is malformed.
        """
