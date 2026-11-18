"""Dependency-Track is one implementation of the source and sink ports."""

import inspect

from dtvp.dt_client import DTClient
from dtvp.ports import AssessmentSink, SourceAndSink, VulnerabilitySource


def test_the_dependency_track_client_is_a_source_and_a_sink():
    client = DTClient("http://dependency-track.invalid", api_key="k")
    assert isinstance(client, VulnerabilitySource)
    assert isinstance(client, AssessmentSink)
    assert isinstance(client, SourceAndSink)


def test_port_methods_match_the_client_signatures():
    for port in (VulnerabilitySource, AssessmentSink):
        for name, declared in inspect.getmembers(port, inspect.isfunction):
            if name.startswith("_"):
                continue
            implemented = inspect.signature(getattr(DTClient, name))
            assert list(inspect.signature(declared).parameters) == list(
                implemented.parameters
            ), name


def test_an_object_missing_a_method_is_not_a_sink():
    class ReadOnly:
        async def get_analysis(self, project_uuid, component_uuid, vulnerability_uuid):
            return None

    assert not isinstance(ReadOnly(), AssessmentSink)
