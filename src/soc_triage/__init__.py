"""SOC blue-team email triage agent.

Analysis logic lives in this package; the notebook is only a trigger and a
rendering surface. That split is deliberate — it keeps the notebook readable
and lets the same triage path be driven from a timer/webhook later without a
rewrite.
"""

from soc_triage.config import Settings, load_settings
from soc_triage.models import Severity, TriageResult, TriageVerdict

__all__ = ["Settings", "load_settings", "Severity", "TriageResult", "TriageVerdict"]
