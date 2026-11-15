
---
config:
  look: handDrawn
  theme: neutral
---
flowchart TD
    Title["Containment keeps the agent in. Who moves the line?"]

    subgraph Governance ["GOVERNANCE (when the line changes)"]
        Change["A change that would move the line"] --> Gate["The Gate"]
        
        Gate --> Compliant["COMPLIANT"]
        Gate --> Violation["VIOLATION"]
        
        Compliant --> MoveLine["The line moves"]
        Violation --> StayLine["The line stays"]
        
        Compliant --> Record["A signed record, either way"]
        Violation --> Record
    end

    subgraph Containment ["CONTAINMENT (while the agent runs)"]
        Agent["AI agent"] --> Wall["Stops the agent crossing the line"]
    end

    Sandbox["A sandbox enforces whatever line it is given. \nEnforceability proves who drew the line, and who moved it."]
