import mermaid from "mermaid";

mermaid.initialize({
  startOnLoad: false,
  theme: "default",
});

const diagram = `
flowchart LR
  subgraph G["GOVERNANCE — when the line changes"]
    direction TB
    P["A change would move the line"]
    D["Declared constraints"]
    E{"Evaluate the change"}
    OK["COMPLIANT"]
    NO["VIOLATION"]
    MOVE["The line moves"]
    KEEP["The line stays"]
    RECORD["Signed record either way"]

    P --> D --> E
    E -->|compliant| OK --> MOVE
    E -->|violation| NO --> KEEP
    MOVE --> RECORD
    KEEP --> RECORD
  end

  subgraph C["CONTAINMENT — while the agent runs"]
    direction LR
    AGENT["AI agent"]
    BOUNDARY{"Within the line?"}
    ALLOW["Action proceeds"]
    STOP["Stop the agent from crossing the line"]

    AGENT --> BOUNDARY
    BOUNDARY -->|yes| ALLOW
    BOUNDARY -->|no| STOP
  end

  MOVE -->|approved boundary| BOUNDARY
  KEEP -->|existing boundary| BOUNDARY

  RECORD --> PRINCIPLE["A sandbox enforces whatever line it is given."]
  PRINCIPLE --> CONCLUSION["Enforceability proves who drew the line — and who moved it."]
`;

const { svg } = await mermaid.render("containmentVsGovernance", diagram);
document.querySelector("#diagram").innerHTML = svg;
