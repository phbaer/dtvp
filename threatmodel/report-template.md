# DTVP and Agentyzer OWASP pytm Analysis

> Generated from `threatmodel/dtvp.py`. Generated findings are review inputs,
> not accepted-risk decisions. The curated decisions and residual-risk register
> remain in `docs/threat-model.md`.

## System Description

{tm.description}

## Assumptions

{tm.assumptions:repeat:- **{{item.name}}** — {{item.description}}
}

## Trust Boundaries

{boundaries:repeat:- **{{item.name}}** — {{item.description}}
}

## Components

{assets:repeat:- **{{item.name}}** (`{{item:call:getElementType}}`) — {{item.description}}
}

## Data Flows

Name | From | To | Data | Protocol | Port
--- | --- | --- | --- | --- | ---
{dataflows:repeat:{{item.name}} | {{item.source.name}} | {{item.sink.name}} | {{item.data}} | {{item.protocol}} | {{item.dstPort}}
}

## Generated Findings

{findings:repeat:
### {{item.threat_id}} — {{item.description}}

- Target: **{{item.target}}**
- Severity: **{{item.severity}}**
- Likelihood: {{item.likelihood}}

{{item.details}}

Suggested mitigations: {{item.mitigations}}

References: {{item.references}}

}
