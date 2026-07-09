"""Scanner registry source: instantiate every scanner exactly once here."""

from __future__ import annotations

from .ai_analysis import AiAnalysis
from .analysis import Analysis
from .base import ScanContext, Scanner, ScannerSkipped
from .betterleaks import Betterleaks
from .checkov import Checkov
from .cisco_ai_skill_scanner import CiscoAiSkillScanner
from .clamav import Clamav
from .codeql import CodeQL
from .gitleaks import Gitleaks
from .kingfisher import Kingfisher
from .mcp_threats import McpThreats
from .nosey_parker import NoseyParker
from .nuclei import Nuclei
from .opengrep import Opengrep
from .osv_scanner import OsvScanner
from .plumber import Plumber
from .reachable_deps import ReachableDeps
from .titus import Titus
from .trivy import TrivyLicense, TrivyMisconfig, TrivySca
from .trufflehog import Trufflehog
from .yara_scan import Yara
from .zap import Zap

ALL_SCANNERS: list[Scanner] = [
    TrivySca(),
    TrivyMisconfig(),
    Checkov(),  # IaC; on by default but skips until `deepscan tools install checkov`; disable with CHECKOV=false
    TrivyLicense(),
    OsvScanner(),
    Gitleaks(),
    Trufflehog(),
    NoseyParker(),
    Titus(),
    Betterleaks(),
    Kingfisher(),
    Opengrep(),
    Plumber(),
    Nuclei(),
    Zap(),
    Clamav(),  # on by default but skips until `deepscan tools install clamav`; disable with CLAMAV=false
    CiscoAiSkillScanner(),  # on by default but skips until `deepscan tools install cisco-ai-skill-scanner`; disable with CISCO_AI_SKILL_SCANNER=false
    Yara(),  # malicious-intent YARA signatures (vendored rules); disable with YARA=false
    McpThreats(),  # malicious-intent text/unicode patterns; disable with MCP_THREATS=false
    Analysis(),
    CodeQL(),  # on by default but skips until `deepscan tools install codeql`; disable with CODEQL=false
    ReachableDeps(),  # consumer: correlates SCA findings with the import graph
    AiAnalysis(),  # off by default; opt in with `--scanner ai-analysis` or AI_ANALYSIS=true
]

__all__ = ["ALL_SCANNERS", "ScanContext", "Scanner", "ScannerSkipped"]
