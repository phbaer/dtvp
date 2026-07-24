from pathlib import Path

from pytm import TM

from threatmodel.dtvp import build_model


ROOT = Path(__file__).resolve().parents[1]
MODEL_ROOT = ROOT / "threatmodel"


def _processed_model():
    model = build_model()
    assert model.check() is True
    model.resolve()
    return model


def test_pytm_model_covers_dtvp_agentyzer_and_vscorer():
    model = _processed_model()
    element_names = {element.name for element in TM._elements}
    flow_names = {flow.name for flow in TM._flows}

    assert {
        "DTVP API",
        "Agentyzer API",
        "Agentyzer assessment pipeline",
        "Configured LLM provider",
        "DTVP durable state",
        "Disposable Agentyzer repository and job state",
        "vscorer threat-rescoring service",
    } <= element_names
    assert {
        "Submit threat model and SBOM for rescoring",
        "Return immediate result or asynchronous task reference",
        "Poll asynchronous vscorer task",
        "Return vscorer task status or completed assessment",
        "Submit scoped code-analysis job",
        "Submit source-derived model prompt",
    } <= flow_names

    vscorer_flows = [
        flow
        for flow in TM._flows
        if "vscorer" in flow.source.name.casefold()
        or "vscorer" in flow.sink.name.casefold()
    ]
    assert len(vscorer_flows) == 4
    assert all(flow.protocol == "HTTPS" for flow in vscorer_flows)

    finding_ids = {finding.threat_id for finding in model.findings}
    assert {"LLM01", "LLM03", "LLM07", "LLM08"} <= finding_ids


def test_pytm_sources_and_report_template_remain_valid():
    model = _processed_model()

    for element in TM._elements:
        for source_file in element.sourceFiles:
            assert (MODEL_ROOT / source_file).resolve().exists(), (
                f"{element.name} references missing source file {source_file}"
            )

    report = model.report(MODEL_ROOT / "report-template.md")
    assert "# DTVP and Agentyzer OWASP pytm Analysis" in report
    assert "Submit threat model and SBOM for rescoring" in report
    assert "Generated findings are review inputs" in report
