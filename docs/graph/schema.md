# Graph Schema - NetworkX Unified Security Knowledge Graph

## Purpose

This document defines the graph schema used by the analysis engine.

The platform is built around a collection of directed graphs implemented with NetworkX.

Goals:

* Program understanding
* Application security analysis
* Architecture discovery
* Dependency analysis
* Vulnerability detection
* Impact analysis
* Attack path discovery

---

# 1. Graph Architecture

## Graph Types

The platform maintains several specialized graphs.

```text
AST Graph
CFG Graph
DFG Graph
Call Graph
Type Graph
Dependency Graph
Security Graph
Trust Boundary Graph
Attack Graph
```

Each graph references the same node identifiers.

Example:

```python
node_id = "function:auth.login"
```

The same node may appear in:

* AST
* Call Graph
* DFG
* Security Graph

---

# 2. Base Graph Type

All graphs use:

```python
nx.MultiDiGraph()
```

Reason:

* Directed relationships
* Multiple edge types
* Edge attributes
* Flexible metadata

Example:

```python
graph = nx.MultiDiGraph()
```

---

# 3. Node Schema

## Required Fields

```python
{
    "id": str,
    "type": str,
    "name": str
}
```

---

## Common Fields

```python
{
    "id": str,
    "type": str,
    "name": str,

    "language": str,

    "tags": list,

    "file": str,
    "line": int,

    "visibility": str,

    "properties": dict,

    "metrics": dict
}
```

---

## Example

```python
{
    "id": "function:db.executeQuery",

    "type": "Function",

    "name": "executeQuery",

    "language": "cpp",

    "file": "db.cpp",

    "line": 42,

    "tags": [
        "SINK",
        "DATABASE"
    ],

    "metrics": {
        "fan_in": 18,
        "fan_out": 4
    }
}
```

---

# 4. Node Categories

## Structural Nodes

```text
Project
Repository
Module
Package
Namespace
File
Folder
```

---

## Type Nodes

```text
Class
Interface
Trait
Struct
Enum
Template
Generic
```

---

## Executable Nodes

```text
Function
Method
Constructor
Destructor
Lambda
Endpoint
```

---

## Data Nodes

```text
Variable
Field
Property
Parameter
Constant
```

---

## Resource Nodes

```text
Database
Table
Collection
Queue
Cache
FileSystem
Secret
Certificate
```

---

## Security Nodes

```text
Source
Sink
Sanitizer
Validator
TrustBoundary
```

---

## Dependency Nodes

```text
Package
Library
Framework
Container
Service
```

---

# 5. Edge Schema

## Required Fields

```python
{
    "type": str
}
```

---

## Common Fields

```python
{
    "type": str,

    "weight": float,

    "confidence": float,

    "properties": dict
}
```

---

# 6. Structural Edges

```text
CONTAINS
DECLARES
IMPORTS
USES
EXTENDS
IMPLEMENTS
DEPENDS_ON
OWNS
```

Example:

```python
graph.add_edge(
    class_id,
    method_id,
    type="CONTAINS"
)
```

---

# 7. Call Graph Edges

```text
CALLS
RETURNS
THROWS
OVERRIDES
```

Example:

```python
CALLS
```

```text
login()
  |
CALLS
  |
validatePassword()
```

---

# 8. Data Flow Edges

```text
READS
WRITES
FLOWS_TO
PROPAGATES_TO
DERIVES_FROM
```

Example:

```text
request.body
     |
FLOWS_TO
     |
sqlQuery
```

---

# 9. Security Edges

```text
TAINTS
SANITIZES
VALIDATES
REACHES
TRUSTS
CROSSES_BOUNDARY
```

---

# 10. Security Tags

## Node Tags

```text
SOURCE
SINK
SANITIZER
VALIDATOR
TAINTED
SECRET
DATABASE
NETWORK
FILESYSTEM
AUTH
CRYPTO
```

---

## Risk Tags

```text
CRITICAL
HIGH_RISK
MEDIUM_RISK
LOW_RISK
```

---

# 11. Security Sources

## User Controlled

```text
HTTP_REQUEST
COOKIE
HEADER
BODY
QUERY_PARAMETER
PATH_PARAMETER
FORM_INPUT
FILE_UPLOAD
```

---

## External Inputs

```text
SOCKET
QUEUE
DATABASE
CLI_ARGUMENT
ENVIRONMENT_VARIABLE
```

---

# 12. Security Sinks

## SQL

```text
SQL_EXECUTE
SQL_QUERY
```

---

## Command Execution

```text
SYSTEM
EXEC
SPAWN
POWERSHELL
BASH
```

---

## File System

```text
FILE_READ
FILE_WRITE
FILE_DELETE
```

---

## Network

```text
HTTP_REQUEST
TCP_SEND
UDP_SEND
```

---

## Dynamic Evaluation

```text
EVAL
REFLECTION
DYNAMIC_IMPORT
```

---

# 13. Trust Boundaries

Examples:

```text
Internet
Frontend
API
Backend
Database
ThirdPartyAPI
CloudService
```

Relationship:

```text
CROSSES_BOUNDARY
```

---

# 14. Metrics

Stored inside node.metrics

---

## Complexity

```python
cyclomatic_complexity

npath_complexity

cognitive_complexity
```

---

## Dependency Metrics

```python
fan_in

fan_out

dependency_count
```

---

## Security Metrics

```python
taint_paths

reachable_sinks

reachable_sources

attack_surface_score
```

---

## Graph Metrics

```python
pagerank

betweenness

closeness

eigenvector
```

---

# 15. Hotspot Scoring

## Function Hotness

```python
score =
(
    fan_in * 3
) +
(
    cyclomatic_complexity * 2
) +
(
    reachable_sinks * 5
)
```

Tag:

```text
HOT_FUNCTION
```

---

## Class Hotness

```python
score =
(
    methods_count
) +
(
    fan_in * 2
) +
(
    dependency_count
)
```

Tag:

```text
HOT_CLASS
```

---

# 16. Taint Analysis Model

## States

```text
UNKNOWN

CLEAN

TAINTED

SANITIZED
```

---

## Propagation

```text
SOURCE
   |
TAINTS
   |
VARIABLE
   |
PROPAGATES_TO
   |
FUNCTION
   |
REACHES
   |
SINK
```

---

# 17. Attack Graph

Specialized graph.

Node types:

```text
Source
Sink
Secret
Endpoint
Database
AdminFunction
```

Edge types:

```text
CAN_REACH
CAN_EXPLOIT
CAN_ACCESS
CAN_DISCOVER
CAN_ESCALATE
```

Purpose:

* Attack path discovery
* Privilege escalation detection
* Lateral movement analysis

---

# 18. Recommended NetworkX Algorithms

## Reachability

```python
nx.has_path()
```

---

## Shortest Path

```python
nx.shortest_path()
```

---

## All Attack Paths

```python
nx.all_simple_paths()
```

---

## Cycle Detection

```python
nx.simple_cycles()
```

---

## Strongly Connected Components

```python
nx.strongly_connected_components()
```

---

## PageRank

```python
nx.pagerank()
```

---

## Betweenness

```python
nx.betweenness_centrality()
```

---

## Closeness

```python
nx.closeness_centrality()
```

---

## Community Detection

```python
networkx.algorithms.community
```

---

# 19. Core Security Queries

## Source To Sink

Find:

```text
SOURCE
 →
SINK
```

Used for:

* SQL Injection
* XSS
* SSRF
* Command Injection

---

## Reachable Vulnerability

Find:

```text
APPLICATION
 →
DEPENDENCY
 →
VULNERABLE_FUNCTION
```

---

## Secret Exposure

Find:

```text
SECRET
 →
LOG
 →
NETWORK
```

---

## Privilege Escalation

Find:

```text
USER
 →
SENSITIVE_FUNCTION
```

Without:

```text
AUTHORIZATION_CHECK
```

---

## Trust Boundary Crossing

Find:

```text
Internet
 →
Backend
 →
Database
```

Without:

```text
VALIDATION
```

---

# 20. Long-Term Vision

The final platform should expose a unified query layer capable of answering:


* Which sources are unsanitized?
* Which functions are the most critical?
* Which endpoints reach a sink?
* Which endpoints reach a taint?
* What are the shortests paths that access a critical function ? 
* What are all the possible paths to reach critical functions ?
* What are the external dependencies used in the application ?
* Which external dependencies, if vulnerability, could reach critical function?
* Which attack paths could impact hard ?
* What is the blast radius of a compromised component?

This architecture forms the foundation of an AppSec and Program Analysis platform inspired by CodeQL, Joern, Semgrep, and modern Code Property Graph systems.
