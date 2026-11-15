---
title: Containment keeps the agent in. Who moves the line?
---
flowchart LR
    subgraph GOV["GOVERNANCE — when the line changes"]
        direction LR
        CHANGE["A change that<br/>would move the line"]
        CONSTRAINTS["✓ ───<br/>✓ ───<br/>✓ ───<br/>Declared constraints"]
        GATE["The gate"]
        VIOLATION["VIOLATION ✗"]
        COMPLIANT["COMPLIANT ✓"]
        RECORD["◯ A signed record,<br/>either way"]
        STAY[" "]

        CHANGE ==> GATE
        CONSTRAINTS --> GATE
        GATE --> VIOLATION
        GATE --> COMPLIANT
        VIOLATION -- "the line stays" --- STAY
        VIOLATION -.- RECORD
    end

    subgraph CONT["CONTAINMENT — while the agent runs"]
        direction LR
        subgraph LINE["the line"]
            direction LR
            AGENT["AI agent"]
            STOP[" "]
            AGENT -- "stops the agent<br/>crossing the line" --> STOP
        end
    end

    COMPLIANT -- "the line moves" --> LINE

    FOOTER["A sandbox enforces whatever line it is given.<br/>Enforceability proves who drew the line, and who moved it."]
    LINE ~~~ FOOTER

    classDef ink fill:#fdfcf8,stroke:#1d1d1b,stroke-width:2px,color:#1d1d1b
    classDef accent fill:#fdfcf8,stroke:#e8862a,stroke-width:3px,color:#1d1d1b
    classDef gate fill:#1d1d1b,stroke:#1d1d1b,color:#fdfcf8
    classDef bar fill:#1d1d1b,stroke:#1d1d1b

    class VIOLATION,COMPLIANT,RECORD,CONSTRAINTS,AGENT ink
    class CHANGE,FOOTER accent
    class GATE gate
    class STAY,STOP bar

    style GOV fill:transparent,stroke:transparent,color:#e8862a
    style CONT fill:transparent,stroke:transparent,color:#e8862a
    style LINE fill:transparent,stroke:#e8862a,stroke-width:3px,stroke-dasharray:10 6,color:#e8862a
    linkStyle 0 stroke:#e8862a,stroke-width:4px
