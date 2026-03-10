import os

ANNOTATION_PREFIX: str = os.environ.get("ANNOTATION_PREFIX", "tritonai-admission-webhook")
ANNOTATION_NS: str = f"{ANNOTATION_PREFIX}/"
POLICY_PREFIX: str = f"{ANNOTATION_NS}policy."
DEFAULT_PREFIX: str = f"{ANNOTATION_NS}default."
