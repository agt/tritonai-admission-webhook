"""
Core pod mutation logic for the MutatingAdmissionWebhook.

For each active constraint annotation on the namespace, the mutator:

1. Reads the corresponding default annotation (sc.dsmlp.ucsd.edu/default.<field>).
2. Parses and validates the default value against the same constraint.
   If the default is absent or fails validation, a warning is logged and that
   field is skipped (other fields are still remediated).
3. Applies the minimum mutations needed so the pod will pass the downstream
   ValidatingAdmissionWebhook:

   REQUIRED_SCALAR fields (runAsUser, runAsGroup, allowPrivilegeEscalation)
     a. Container/initContainer securityContexts that carry the field with a
        non-conforming value are updated in-place.
     b. The pod-level securityContext is patched (or created from scratch) to
        supply a conforming default for any container that does not carry the
        field itself.

   OPTIONAL_SCALAR fields (fsGroup)
     If the pod-level securityContext carries the field with a non-conforming
     value, it is replaced with the default.  Absent → no change.

   OPTIONAL_LIST fields (supplementalGroups)
     If the pod-level securityContext carries the list and any entry is
     non-conforming, the entire list is replaced with [default].

   NODE_SELECTOR (nodeLabel)
     • pod.spec.nodeName is removed unconditionally (it bypasses nodeSelector).
     • If nodeSelector does not already satisfy the constraint, the default
       key=value label is injected into (or used to create) nodeSelector.

Returns a (possibly empty) list of RFC 6902 JSON Patch operations.  The
caller base64-encodes the JSON-serialised list and returns it to the API
server.  The API server then re-runs the mutated pod through all registered
ValidatingAdmissionWebhooks, which will block any pod that still fails.
"""
from __future__ import annotations

import copy
import logging
from typing import Any

from .constraints.base import ConstraintSet
from .constraints.registry import parse_annotation
from .validator import FieldBehavior, _FIELD_SPECS

logger = logging.getLogger(__name__)

DEFAULT_ANNOTATION_PREFIX = "sc.dsmlp.ucsd.edu/default."


# ---------------------------------------------------------------------------
# JSON Pointer helpers (RFC 6901)
# ---------------------------------------------------------------------------


def _escape_ptr_segment(segment: str) -> str:
    """Escape a single JSON Pointer path segment."""
    return segment.replace("~", "~0").replace("/", "~1")


def _ptr(*segments: str) -> str:
    """Build a JSON Pointer string from path segments."""
    return "/" + "/".join(_escape_ptr_segment(s) for s in segments)


# ---------------------------------------------------------------------------
# Default value parsing and validation
# ---------------------------------------------------------------------------


def _parse_and_validate_default(
    field_name: str,
    annotation_key: str,
    ns_annotations: dict[str, str],
    constraint_set: ConstraintSet,
) -> Any:
    """Return the parsed, constraint-validated default value for *field_name*.

    Returns None (and logs a warning) if:
    - the default annotation is absent from the namespace,
    - the raw string cannot be parsed for the field type, or
    - the parsed value does not satisfy the active constraint.
    """
    default_key = f"{DEFAULT_ANNOTATION_PREFIX}{field_name}"

    if default_key not in ns_annotations:
        logger.warning(
            "Constraint annotation %r is active but default annotation %r is absent "
            "from the namespace; cannot auto-remediate %r violations.",
            annotation_key, default_key, field_name,
        )
        return None

    raw = ns_annotations[default_key].strip()

    # --- parse ---
    try:
        if field_name in ("runAsUser", "runAsGroup", "fsGroup", "supplementalGroups"):
            parsed: Any = int(raw)
            test_value: Any = parsed
        elif field_name == "allowPrivilegeEscalation":
            if raw.lower() == "true":
                parsed, test_value = True, True
            elif raw.lower() == "false":
                parsed, test_value = False, False
            else:
                raise ValueError(f"expected 'true' or 'false', got {raw!r}")
        elif field_name == "nodeLabel":
            if "=" not in raw:
                raise ValueError(f"expected 'key=value' format, got {raw!r}")
            key, val = raw.split("=", 1)
            parsed = (key.strip(), val.strip())   # store as (key, value) tuple
            test_value = {key.strip(): val.strip()}
        else:
            logger.warning("No default parser registered for field %r; skipping.", field_name)
            return None
    except (ValueError, TypeError) as exc:
        logger.warning(
            "Cannot parse default annotation %r=%r: %s; skipping auto-remediation for %r.",
            default_key, raw, exc, field_name,
        )
        return None

    # --- validate against the active constraint ---
    if not constraint_set.matches(test_value):
        logger.warning(
            "Default annotation %r=%r does not satisfy constraint [%s]; "
            "skipping auto-remediation for %r.",
            default_key, raw, constraint_set.description(), field_name,
        )
        return None

    return parsed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _any_container_missing_field(pod: dict[str, Any], field_name: str) -> bool:
    """Return True if any container or initContainer is missing *field_name*
    in its securityContext (or has no securityContext at all)."""
    for kind in ("containers", "initContainers"):
        for container in pod.get(kind) or []:
            sc = container.get("securityContext")
            if sc is None or field_name not in sc:
                return True
    return False


# ---------------------------------------------------------------------------
# Per-behavior mutators
# ---------------------------------------------------------------------------


def _mutate_required_scalar(
    field_name: str,
    pod: dict[str, Any],
    constraint_set: ConstraintSet,
    default_value: Any,
    patches: list[dict[str, Any]],
) -> None:
    """Mutate a REQUIRED_SCALAR field (runAsUser, runAsGroup, allowPrivilegeEscalation).

    Step 1 – fix non-conforming values in existing container/initContainer SCs.
    Step 2 – ensure the pod-level SC carries the field for any container that
             does not set it itself; create the pod-level SC if necessary.
    """
    # Step 1: fix container-level overrides with wrong values
    for kind in ("containers", "initContainers"):
        for i, container in enumerate(pod.get(kind) or []):
            sc = container.get("securityContext")
            if sc is None:
                continue
            value = sc.get(field_name)
            if value is not None and not constraint_set.matches(value):
                sc[field_name] = default_value
                patches.append({
                    "op": "replace",
                    "path": _ptr("spec", kind, str(i), "securityContext", field_name),
                    "value": default_value,
                })

    # Step 2: ensure pod-level SC provides coverage
    pod_sc: dict[str, Any] | None = pod.get("securityContext")

    if pod_sc is not None:
        pod_value = pod_sc.get(field_name)
        if pod_value is not None and not constraint_set.matches(pod_value):
            # Pod SC carries wrong value → replace
            pod_sc[field_name] = default_value
            patches.append({
                "op": "replace",
                "path": _ptr("spec", "securityContext", field_name),
                "value": default_value,
            })
        elif pod_value is None and _any_container_missing_field(pod, field_name):
            # Pod SC exists but doesn't set the field, yet some container needs coverage
            pod_sc[field_name] = default_value
            patches.append({
                "op": "add",
                "path": _ptr("spec", "securityContext", field_name),
                "value": default_value,
            })
    else:
        # No pod-level SC: create one if any container still lacks the field
        if _any_container_missing_field(pod, field_name):
            pod["securityContext"] = {field_name: default_value}
            patches.append({
                "op": "add",
                "path": "/spec/securityContext",
                "value": {field_name: default_value},
            })


def _mutate_optional_scalar(
    field_name: str,
    pod: dict[str, Any],
    constraint_set: ConstraintSet,
    default_value: Any,
    patches: list[dict[str, Any]],
) -> None:
    """Mutate an OPTIONAL_SCALAR field (fsGroup).

    Absent → constraint satisfied, no change.
    Present with wrong value → replace with default.
    """
    pod_sc = pod.get("securityContext")
    if pod_sc is None:
        return
    pod_value = pod_sc.get(field_name)
    if pod_value is None:
        return  # absent is always OK for optional fields
    if not constraint_set.matches(pod_value):
        pod_sc[field_name] = default_value
        patches.append({
            "op": "replace",
            "path": _ptr("spec", "securityContext", field_name),
            "value": default_value,
        })


def _mutate_optional_list(
    field_name: str,
    pod: dict[str, Any],
    constraint_set: ConstraintSet,
    default_value: Any,
    patches: list[dict[str, Any]],
) -> None:
    """Mutate an OPTIONAL_LIST field (supplementalGroups).

    Absent/empty → constraint satisfied, no change.
    Any non-conforming entry → replace the entire list with [default].
    """
    pod_sc = pod.get("securityContext")
    if pod_sc is None:
        return
    values = pod_sc.get(field_name)
    if not values:
        return
    if any(not constraint_set.matches(v) for v in values):
        new_list = [default_value]
        pod_sc[field_name] = new_list
        patches.append({
            "op": "replace",
            "path": _ptr("spec", "securityContext", field_name),
            "value": new_list,
        })


def _mutate_node_selector(
    pod: dict[str, Any],
    constraint_set: ConstraintSet | None,
    default_label: tuple[str, str] | None,
    patches: list[dict[str, Any]],
) -> None:
    """Mutate pod scheduling fields when sc.dsmlp.ucsd.edu/nodeLabel is active.

    • nodeName is always removed — it unconditionally bypasses nodeSelector.
    • If nodeSelector does not already satisfy the constraint, the default
      key=value label is injected.  If no valid default is available, the
      nodeSelector gap is logged and left for the validator to reject.
    """
    if pod.get("nodeName"):
        del pod["nodeName"]
        patches.append({"op": "remove", "path": "/spec/nodeName"})

    if constraint_set is None:
        return

    node_selector: dict[str, str] = pod.get("nodeSelector") or {}
    if constraint_set.matches(node_selector):
        return  # already satisfied

    if default_label is None:
        logger.warning(
            "sc.dsmlp.ucsd.edu/nodeLabel constraint is active but no valid default label "
            "is available; nodeSelector cannot be auto-remediated."
        )
        return

    key, value = default_label
    if "nodeSelector" not in pod:
        pod["nodeSelector"] = {key: value}
        patches.append({
            "op": "add",
            "path": "/spec/nodeSelector",
            "value": {key: value},
        })
    else:
        pod["nodeSelector"][key] = value
        patches.append({
            "op": "add",     # "add" creates-or-replaces in a JSON object
            "path": _ptr("spec", "nodeSelector", key),
            "value": value,
        })


# Dispatch table: FieldBehavior → mutator function (excludes NODE_SELECTOR)
_SC_MUTATORS = {
    FieldBehavior.REQUIRED_SCALAR: _mutate_required_scalar,
    FieldBehavior.OPTIONAL_SCALAR: _mutate_optional_scalar,
    FieldBehavior.OPTIONAL_LIST: _mutate_optional_list,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def mutate_pod(
    namespace_annotations: dict[str, str],
    pod_spec: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compute RFC 6902 JSON Patch operations to bring *pod_spec* into compliance.

    Parameters
    ----------
    namespace_annotations:
        All ``sc.dsmlp.ucsd.edu/*`` annotations scraped from the pod's namespace,
        including both constraint annotations and ``default.*`` annotations.
    pod_spec:
        The ``spec`` sub-dict from the Pod's AdmissionRequest object.

    Returns
    -------
    A (possibly empty) list of JSON Patch operation dicts.  Returns an empty
    list when no constraint annotations are active or no mutations are needed.
    The caller is responsible for JSON-serialising and base64-encoding the list.
    """
    pod = copy.deepcopy(pod_spec)
    patches: list[dict[str, Any]] = []

    # --- securityContext fields (all behaviors except NODE_SELECTOR) ---
    for field_suffix, field_spec in _FIELD_SPECS.items():
        if field_spec.behavior == FieldBehavior.NODE_SELECTOR:
            continue  # handled separately below

        annotation_key = f"sc.dsmlp.ucsd.edu/{field_suffix}"
        if annotation_key not in namespace_annotations:
            continue

        try:
            constraint_set = parse_annotation(
                annotation_key, namespace_annotations[annotation_key]
            )
        except ValueError as exc:
            logger.warning(
                "Skipping mutation for malformed annotation %r: %s", annotation_key, exc
            )
            continue

        default_value = _parse_and_validate_default(
            field_suffix, annotation_key, namespace_annotations, constraint_set
        )
        if default_value is None:
            continue  # warning already logged

        mutator = _SC_MUTATORS[field_spec.behavior]
        mutator(field_suffix, pod, constraint_set, default_value, patches)

    # --- nodeLabel (NODE_SELECTOR) ---
    node_label_key = "sc.dsmlp.ucsd.edu/nodeLabel"
    if node_label_key in namespace_annotations:
        nl_constraint: ConstraintSet | None = None
        try:
            nl_constraint = parse_annotation(
                node_label_key, namespace_annotations[node_label_key]
            )
        except ValueError as exc:
            logger.warning(
                "Skipping nodeLabel mutation for malformed annotation: %s", exc
            )

        nl_default: tuple[str, str] | None = None
        if nl_constraint is not None:
            nl_default = _parse_and_validate_default(
                "nodeLabel", node_label_key, namespace_annotations, nl_constraint
            )

        _mutate_node_selector(pod, nl_constraint, nl_default, patches)

    return patches
