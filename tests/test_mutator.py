"""Tests for the pod mutation logic."""
import base64
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.mutator import mutate_pod

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers (mirrors test_validator.py helpers)
# ---------------------------------------------------------------------------


def _pod(
    pod_sc: dict | None = None,
    containers: list[dict] | None = None,
    init_containers: list[dict] | None = None,
) -> dict:
    spec: dict = {}
    if pod_sc is not None:
        spec["securityContext"] = pod_sc
    spec["containers"] = containers or [{"name": "app"}]
    if init_containers:
        spec["initContainers"] = init_containers
    return spec


def _container(name: str = "app", sc: dict | None = None) -> dict:
    c: dict = {"name": name}
    if sc is not None:
        c["securityContext"] = sc
    return c


def _ops(patches: list[dict], op: str) -> list[dict]:
    return [p for p in patches if p["op"] == op]


def _patch_at(patches: list[dict], path: str) -> dict | None:
    return next((p for p in patches if p["path"] == path), None)


# ---------------------------------------------------------------------------
# No activity when no namespace annotations
# ---------------------------------------------------------------------------


def test_no_patches_when_no_annotations():
    spec = _pod(containers=[_container(sc={"runAsUser": 999})])
    assert mutate_pod({}, spec) == []


def test_no_patches_when_no_constraint_annotation():
    # default annotation present but no matching constraint annotation
    annotations = {"sc.dsmlp.ucsd.edu/default.runAsUser": "1000"}
    spec = _pod(containers=[_container(sc={"runAsUser": 999})])
    assert mutate_pod(annotations, spec) == []


# ---------------------------------------------------------------------------
# Default annotation validation
# ---------------------------------------------------------------------------


def test_no_patches_when_default_annotation_absent(caplog):
    annotations = {"sc.dsmlp.ucsd.edu/runAsUser": "1000"}
    spec = _pod(containers=[_container(sc={"runAsUser": 999})])
    patches = mutate_pod(annotations, spec)
    assert patches == []
    assert "default" in caplog.text.lower()


def test_no_patches_when_default_fails_constraint(caplog):
    annotations = {
        "sc.dsmlp.ucsd.edu/runAsUser": "1000",
        "sc.dsmlp.ucsd.edu/default.runAsUser": "999",   # fails constraint
    }
    spec = _pod(containers=[_container(sc={"runAsUser": 888})])
    patches = mutate_pod(annotations, spec)
    assert patches == []
    assert "does not satisfy" in caplog.text


def test_no_patches_when_default_unparseable(caplog):
    annotations = {
        "sc.dsmlp.ucsd.edu/runAsUser": "1000",
        "sc.dsmlp.ucsd.edu/default.runAsUser": "not-a-number",
    }
    spec = _pod(containers=[_container(sc={"runAsUser": 999})])
    patches = mutate_pod(annotations, spec)
    assert patches == []
    assert "cannot parse" in caplog.text.lower()


# ---------------------------------------------------------------------------
# runAsUser — REQUIRED_SCALAR mutations
# ---------------------------------------------------------------------------


RUNASUSER_ANNOTATIONS = {
    "sc.dsmlp.ucsd.edu/runAsUser": "1000",
    "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
}


class TestMutateRunAsUser:

    def test_no_patches_when_already_conforming_pod_sc(self):
        spec = _pod(pod_sc={"runAsUser": 1000})
        assert mutate_pod(RUNASUSER_ANNOTATIONS, spec) == []

    def test_no_patches_when_already_conforming_container_sc(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 1000})])
        assert mutate_pod(RUNASUSER_ANNOTATIONS, spec) == []

    def test_fixes_wrong_value_in_container_sc(self):
        spec = _pod(containers=[_container(sc={"runAsUser": 999})])
        patches = mutate_pod(RUNASUSER_ANNOTATIONS, spec)
        assert len(patches) == 1
        p = patches[0]
        assert p["op"] == "replace"
        assert "containers/0/securityContext/runAsUser" in p["path"]
        assert p["value"] == 1000

    def test_fixes_wrong_value_in_pod_sc(self):
        spec = _pod(pod_sc={"runAsUser": 999}, containers=[_container(sc={"runAsUser": 1000})])
        patches = mutate_pod(RUNASUSER_ANNOTATIONS, spec)
        assert len(patches) == 1
        assert patches[0]["path"] == "/spec/securityContext/runAsUser"
        assert patches[0]["op"] == "replace"
        assert patches[0]["value"] == 1000

    def test_creates_pod_sc_when_container_has_no_sc(self):
        spec = _pod(containers=[_container(sc=None)])
        patches = mutate_pod(RUNASUSER_ANNOTATIONS, spec)
        assert len(patches) == 1
        p = patches[0]
        assert p["op"] == "add"
        assert p["path"] == "/spec/securityContext"
        assert p["value"] == {"runAsUser": 1000}

    def test_creates_pod_sc_when_container_sc_lacks_field(self):
        spec = _pod(containers=[_container(sc={})])
        patches = mutate_pod(RUNASUSER_ANNOTATIONS, spec)
        assert len(patches) == 1
        assert patches[0]["path"] == "/spec/securityContext"
        assert patches[0]["value"] == {"runAsUser": 1000}

    def test_adds_field_to_existing_pod_sc_when_container_lacks_it(self):
        # Pod SC exists (with other fields) but lacks runAsUser; container also lacks it
        spec = _pod(pod_sc={"runAsGroup": 2000}, containers=[_container(sc={})])
        patches = mutate_pod(RUNASUSER_ANNOTATIONS, spec)
        assert len(patches) == 1
        assert patches[0]["op"] == "add"
        assert patches[0]["path"] == "/spec/securityContext/runAsUser"
        assert patches[0]["value"] == 1000

    def test_no_pod_sc_creation_when_all_containers_have_field(self):
        # All containers supply runAsUser correctly; pod SC not needed
        spec = _pod(containers=[
            _container("c1", sc={"runAsUser": 1000}),
            _container("c2", sc={"runAsUser": 1000}),
        ])
        patches = mutate_pod(RUNASUSER_ANNOTATIONS, spec)
        assert patches == []

    def test_fixes_wrong_container_and_skips_correct_one(self):
        spec = _pod(containers=[
            _container("good", sc={"runAsUser": 1000}),
            _container("bad", sc={"runAsUser": 999}),
        ])
        patches = mutate_pod(RUNASUSER_ANNOTATIONS, spec)
        assert len(patches) == 1
        assert "containers/1" in patches[0]["path"]

    def test_fixes_init_container(self):
        spec = _pod(
            containers=[_container(sc={"runAsUser": 1000})],
            init_containers=[_container("init", sc={"runAsUser": 999})],
        )
        patches = mutate_pod(RUNASUSER_ANNOTATIONS, spec)
        assert len(patches) == 1
        assert "initContainers/0" in patches[0]["path"]

    def test_range_default_applied(self):
        annotations = {
            "sc.dsmlp.ucsd.edu/runAsUser": "1000,2000-3000",
            "sc.dsmlp.ucsd.edu/default.runAsUser": "2500",
        }
        spec = _pod(containers=[_container(sc={"runAsUser": 999})])
        patches = mutate_pod(annotations, spec)
        assert patches[0]["value"] == 2500

    def test_pod_sc_field_not_updated_if_already_correct_and_container_covered(self):
        # Pod SC has correct value; container also has correct value → no patches
        spec = _pod(
            pod_sc={"runAsUser": 1000},
            containers=[_container(sc={"runAsUser": 1000})],
        )
        assert mutate_pod(RUNASUSER_ANNOTATIONS, spec) == []


# ---------------------------------------------------------------------------
# fsGroup — OPTIONAL_SCALAR
# ---------------------------------------------------------------------------


FSGROUP_ANNOTATIONS = {
    "sc.dsmlp.ucsd.edu/fsGroup": "1000",
    "sc.dsmlp.ucsd.edu/default.fsGroup": "1000",
}


class TestMutateFsGroup:

    def test_no_patches_when_absent(self):
        spec = _pod(pod_sc={})
        assert mutate_pod(FSGROUP_ANNOTATIONS, spec) == []

    def test_no_patches_when_no_pod_sc(self):
        spec = _pod()
        assert mutate_pod(FSGROUP_ANNOTATIONS, spec) == []

    def test_fixes_wrong_value(self):
        spec = _pod(pod_sc={"fsGroup": 999})
        patches = mutate_pod(FSGROUP_ANNOTATIONS, spec)
        assert len(patches) == 1
        assert patches[0]["op"] == "replace"
        assert patches[0]["path"] == "/spec/securityContext/fsGroup"
        assert patches[0]["value"] == 1000

    def test_no_patches_when_correct(self):
        spec = _pod(pod_sc={"fsGroup": 1000})
        assert mutate_pod(FSGROUP_ANNOTATIONS, spec) == []


# ---------------------------------------------------------------------------
# supplementalGroups — OPTIONAL_LIST
# ---------------------------------------------------------------------------


SG_ANNOTATIONS = {
    "sc.dsmlp.ucsd.edu/supplementalGroups": "1000,2000-3000",
    "sc.dsmlp.ucsd.edu/default.supplementalGroups": "1000",
}


class TestMutateSupplementalGroups:

    def test_no_patches_when_absent(self):
        spec = _pod(pod_sc={})
        assert mutate_pod(SG_ANNOTATIONS, spec) == []

    def test_no_patches_when_empty_list(self):
        spec = _pod(pod_sc={"supplementalGroups": []})
        assert mutate_pod(SG_ANNOTATIONS, spec) == []

    def test_no_patches_when_all_conforming(self):
        spec = _pod(pod_sc={"supplementalGroups": [1000, 2500]})
        assert mutate_pod(SG_ANNOTATIONS, spec) == []

    def test_replaces_list_when_one_entry_fails(self):
        spec = _pod(pod_sc={"supplementalGroups": [1000, 9999]})
        patches = mutate_pod(SG_ANNOTATIONS, spec)
        assert len(patches) == 1
        assert patches[0]["op"] == "replace"
        assert patches[0]["path"] == "/spec/securityContext/supplementalGroups"
        assert patches[0]["value"] == [1000]

    def test_replaces_list_when_all_entries_fail(self):
        spec = _pod(pod_sc={"supplementalGroups": [9998, 9999]})
        patches = mutate_pod(SG_ANNOTATIONS, spec)
        assert patches[0]["value"] == [1000]


# ---------------------------------------------------------------------------
# nodeLabel — NODE_SELECTOR
# ---------------------------------------------------------------------------


NL_ANNOTATIONS = {
    "sc.dsmlp.ucsd.edu/nodeLabel": "partition=gpu",
    "sc.dsmlp.ucsd.edu/default.nodeLabel": "partition=gpu",
}


class TestMutateNodeLabel:

    def test_no_patches_when_nodeselector_already_matches(self):
        spec = _pod()
        spec["nodeSelector"] = {"partition": "gpu"}
        assert mutate_pod(NL_ANNOTATIONS, spec) == []

    def test_creates_nodeselector_when_absent(self):
        spec = _pod()
        patches = mutate_pod(NL_ANNOTATIONS, spec)
        p = _patch_at(patches, "/spec/nodeSelector")
        assert p is not None
        assert p["op"] == "add"
        assert p["value"] == {"partition": "gpu"}

    def test_adds_key_to_existing_nodeselector(self):
        spec = _pod()
        spec["nodeSelector"] = {"zone": "us-west-2"}
        patches = mutate_pod(NL_ANNOTATIONS, spec)
        p = _patch_at(patches, "/spec/nodeSelector/partition")
        assert p is not None
        assert p["value"] == "gpu"

    def test_replaces_wrong_value_in_existing_nodeselector(self):
        spec = _pod()
        spec["nodeSelector"] = {"partition": "cpu"}   # wrong value
        patches = mutate_pod(NL_ANNOTATIONS, spec)
        p = _patch_at(patches, "/spec/nodeSelector/partition")
        assert p is not None
        assert p["value"] == "gpu"

    def test_removes_nodename_unconditionally(self):
        spec = _pod()
        spec["nodeName"] = "node-42"
        spec["nodeSelector"] = {"partition": "gpu"}   # nodeSelector already correct
        patches = mutate_pod(NL_ANNOTATIONS, spec)
        removes = _ops(patches, "remove")
        assert any(p["path"] == "/spec/nodeName" for p in removes)

    def test_removes_nodename_and_fixes_nodeselector(self):
        spec = _pod()
        spec["nodeName"] = "node-42"
        # nodeSelector missing → both nodeName removal + nodeSelector add
        patches = mutate_pod(NL_ANNOTATIONS, spec)
        assert any(p["op"] == "remove" and p["path"] == "/spec/nodeName" for p in patches)
        assert any(p["path"] == "/spec/nodeSelector" for p in patches)

    def test_nodename_removed_even_without_valid_default(self, caplog):
        annotations = {"sc.dsmlp.ucsd.edu/nodeLabel": "partition=gpu"}  # no default
        spec = _pod()
        spec["nodeName"] = "node-42"
        patches = mutate_pod(annotations, spec)
        # nodeName removed despite no default available for nodeSelector
        assert any(p["op"] == "remove" and p["path"] == "/spec/nodeName" for p in patches)
        assert "cannot" in caplog.text.lower() or "absent" in caplog.text.lower()

    def test_nodeselector_key_with_slash_escaped_in_pointer(self):
        annotations = {
            "sc.dsmlp.ucsd.edu/nodeLabel": "kubernetes.io/hostname=node-1",
            "sc.dsmlp.ucsd.edu/default.nodeLabel": "kubernetes.io/hostname=node-1",
        }
        spec = _pod()
        spec["nodeSelector"] = {"zone": "us"}
        patches = mutate_pod(annotations, spec)
        # The JSON Pointer must escape / in the key
        p = next(p for p in patches if "hostname" in p["path"])
        assert "kubernetes.io~1hostname" in p["path"]

    def test_multi_token_constraint_satisfied_by_nodeselector(self):
        annotations = {
            "sc.dsmlp.ucsd.edu/nodeLabel": "rack=a,rack=b",
            "sc.dsmlp.ucsd.edu/default.nodeLabel": "rack=a",
        }
        spec = _pod()
        spec["nodeSelector"] = {"rack": "b"}   # satisfies second token
        assert mutate_pod(annotations, spec) == []


# ---------------------------------------------------------------------------
# Multiple constraints — patches combined correctly
# ---------------------------------------------------------------------------


class TestMultipleConstraintMutations:

    def test_all_fields_patched(self):
        annotations = {
            "sc.dsmlp.ucsd.edu/runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/runAsGroup": "2000",
            "sc.dsmlp.ucsd.edu/default.runAsGroup": "2000",
            "sc.dsmlp.ucsd.edu/nodeLabel": "partition=gpu",
            "sc.dsmlp.ucsd.edu/default.nodeLabel": "partition=gpu",
        }
        # Pod with no SC and wrong nodeName
        spec = _pod(containers=[_container(sc=None)])
        spec["nodeName"] = "node-1"

        patches = mutate_pod(annotations, spec)
        paths = {p["path"] for p in patches}

        # Should create pod SC covering runAsUser, runAsGroup
        assert any("/spec/securityContext" in path for path in paths)
        # nodeName removed
        assert "/spec/nodeName" in paths
        # nodeSelector added
        assert "/spec/nodeSelector" in paths

    def test_partial_remediation_when_one_default_missing(self, caplog):
        annotations = {
            "sc.dsmlp.ucsd.edu/runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
            "sc.dsmlp.ucsd.edu/runAsGroup": "2000",
            # no default for runAsGroup
        }
        spec = _pod(containers=[_container(sc={"runAsUser": 999, "runAsGroup": 999})])
        patches = mutate_pod(annotations, spec)
        # runAsUser fixed, runAsGroup not (no default)
        assert any("runAsUser" in p["path"] for p in patches)
        assert not any("runAsGroup" in p["path"] for p in patches)
        assert "default" in caplog.text.lower()


# ---------------------------------------------------------------------------
# /mutate HTTP endpoint
# ---------------------------------------------------------------------------


def _review(
    uid: str = "test-uid",
    kind: str = "Pod",
    namespace: str = "default",
    pod_spec: dict | None = None,
) -> dict:
    pod_spec = pod_spec or {"containers": [{"name": "app"}]}
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": uid,
            "kind": {"group": "", "version": "v1", "kind": kind},
            "namespace": namespace,
            "operation": "CREATE",
            "object": {"spec": pod_spec},
        },
    }


NS_WITH_DEFAULTS = {
    "sc.dsmlp.ucsd.edu/runAsUser": "1000",
    "sc.dsmlp.ucsd.edu/default.runAsUser": "1000",
}


def test_mutate_endpoint_returns_allowed_true():
    with patch("app.main.get_namespace_security_annotations", return_value={}):
        resp = client.post("/mutate", json=_review())
    assert resp.status_code == 200
    assert resp.json()["response"]["allowed"] is True


def test_mutate_endpoint_passes_through_non_pod():
    resp = client.post("/mutate", json=_review(kind="Deployment"))
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"]["allowed"] is True
    assert "patch" not in data["response"]


def test_mutate_endpoint_returns_patch_when_needed():
    with patch(
        "app.main.get_namespace_security_annotations", return_value=NS_WITH_DEFAULTS
    ):
        spec = {"containers": [{"name": "app", "securityContext": {"runAsUser": 999}}]}
        resp = client.post("/mutate", json=_review(pod_spec=spec))
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"]["allowed"] is True
    assert data["response"]["patchType"] == "JSONPatch"
    # Decode and verify patch content
    raw = base64.b64decode(data["response"]["patch"])
    ops = json.loads(raw)
    assert any("runAsUser" in op["path"] for op in ops)


def test_mutate_endpoint_no_patch_when_already_compliant():
    with patch(
        "app.main.get_namespace_security_annotations", return_value=NS_WITH_DEFAULTS
    ):
        spec = {"containers": [{"name": "app", "securityContext": {"runAsUser": 1000}}]}
        resp = client.post("/mutate", json=_review(pod_spec=spec))
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"]["allowed"] is True
    assert "patch" not in data["response"]


def test_mutate_endpoint_preserves_uid():
    with patch("app.main.get_namespace_security_annotations", return_value={}):
        resp = client.post("/mutate", json=_review(uid="unique-xyz"))
    assert resp.json()["response"]["uid"] == "unique-xyz"


def test_mutate_endpoint_bad_json_returns_400():
    resp = client.post(
        "/mutate", content=b"not json", headers={"content-type": "application/json"}
    )
    assert resp.status_code == 400
