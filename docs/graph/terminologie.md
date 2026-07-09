# Terminology Reference - Source Code Analysis and Application Security Platform

## Purpose

This document defines the terminology, concepts, graph models, metrics, and algorithms used by a source code analysis platform focused on:

* Program Understanding
* Software Architecture Analysis
* Application Security (AppSec)
* Security Auditing
* Impact Analysis
* Reverse Engineering
* Supply Chain Security

---

# 1. Core Concepts

## Entity

Any object represented within the graph.

Examples:

* Project
* Module
* File
* Class
* Function
* Variable
* Endpoint
* Dependency
* Sink
* Source

---

## Node

A graph representation of an entity.

Example:

```json
{
  "id": "function_123",
  "type": "Function",
  "name": "executeQuery"
}
```

---

## Edge

A relationship between two nodes.

Example:

```text
executeQuery CALLS openConnection
```

---

## Property

Metadata associated with a node or edge.

Example:

```json
{
  "complexity": 12,
  "language": "cpp"
}
```

---

# 2. Graph Types

## Abstract Syntax Tree (AST)

Represents the syntactic structure of source code.

Use Cases:

* Parsing
* Syntax analysis
* Pattern matching
* Static Application Security Testing (SAST)

---

## Control Flow Graph (CFG)

Represents execution paths through a program.

Use Cases:

* Reachability analysis
* Dead code detection
* Conditional flow analysis
* Dominator analysis

---

## Data Flow Graph (DFG)

Represents how data propagates through a program.

Use Cases:

* Taint analysis
* Data tracking
* Injection vulnerability detection

---

## Call Graph

Represents function and method invocations.

Use Cases:

* Impact analysis
* Hotspot detection
* Dependency analysis

---

## Dependency Graph

Represents software dependencies.

Use Cases:

* Software Bill of Materials (SBOM)
* CVE analysis
* Supply chain security

---

## Type Graph

Represents the type system and relationships.

Use Cases:

* Inheritance analysis
* Polymorphism resolution
* Dynamic dispatch resolution

---

## Security Graph

Security-focused graph representation.

Use Cases:

* Sources
* Sinks
* Sanitizers
* Trust boundaries

---

## Code Property Graph (CPG)

A unified graph combining:

* AST
* CFG
* DFG

Use Cases:

* Advanced static analysis
* Vulnerability detection
* Security queries

---

# 3. Node Types

## Application Structure

### Project

Entire software project.

### Repository

Source control repository.

### Module

Logical software module.

### Package

Package or namespace.

### File

Source file.

---

## Type System

### Class

Object-oriented class.

### Interface

Contract definition.

### Trait

Reusable behavior.

### Struct

Structured data type.

### Enum

Enumeration.

---

## Executable Elements

### Function

Standalone function.

### Method

Class method.

### Constructor

Object constructor.

### Destructor

Object destructor.

### Lambda

Anonymous function.

---

## Data Elements

### Variable

Local variable.

### Parameter

Function parameter.

### Property

Class member.

### Global Variable

Global state.

### Constant

Immutable value.

---

## Resources

### Database

Database instance.

### Table

Database table.

### Queue

Message queue.

### Cache

Caching layer.

### FileSystem

Filesystem resource.

---

## Network

### Endpoint

Public entry point.

### API

Application Programming Interface.

### Route

HTTP route.

### WebSocket

WebSocket endpoint.

### RPC

Remote Procedure Call endpoint.

---

# 4. Edge Types

## Structural Relationships

### CONTAINS

Contains another entity.

### DECLARES

Declares another entity.

### IMPLEMENTS

Implements an interface.

### EXTENDS

Inherits from another type.

### IMPORTS

Imports another module.

### DEPENDS_ON

Depends on another component.

---

## Execution Relationships

### CALLS

Invokes another function.

### RETURNS

Returns a value.

### THROWS

Throws an exception.

### OVERRIDES

Overrides inherited behavior.

---

## Data Flow Relationships

### READS

Reads data.

### WRITES

Writes data.

### FLOWS_TO

Data flows to another node.

### PROPAGATES_TO

Propagates data or state.

---

## Security Relationships

### TAINTS

Marks data as tainted.

### SANITIZES

Removes taint.

### VALIDATES

Validates input.

### REACHES

Can reach another node.

---

# 5. Security Concepts

## Source

An origin of externally controlled data.

Examples:

* HTTP Request
* Form Input
* Cookie
* Header
* Socket
* Message Queue
* Environment Variable
* File Upload
* Command Line Argument

Tag:

```text
SOURCE
```

---

## Sink

A security-sensitive operation.

Examples:

### SQL Sink

* executeQuery
* execute

### Command Sink

* system
* exec
* Runtime.exec

### File Sink

* fopen
* open
* write

### Network Sink

* HTTP Client
* Socket Send

### Template Sink

* Render
* Evaluate

Tag:

```text
SINK
```

---

## Sanitizer

A function that removes or neutralizes dangerous input.

Examples:

* escapeHtml
* sanitizeSql
* sanitizePath
* encodeUrl

Tag:

```text
SANITIZER
```

---

## Validator

A function that verifies correctness of input.

Examples:

* isValidEmail
* regexValidation
* schemaValidation

Tag:

```text
VALIDATOR
```

---

## Taint

Data that may be influenced by an attacker.

States:

* CLEAN
* TAINTED
* SANITIZED
* UNKNOWN

---

## Trust Boundary

A transition between trust levels.

Examples:

* Internet → Frontend
* Frontend → Backend
* Backend → Database
* Service → Service

Tag:

```text
TRUST_BOUNDARY
```

---

# 6. Metrics

## Fan-In

Number of incoming callers.

Use Cases:

* Critical component identification

---

## Fan-Out

Number of outgoing calls.

Use Cases:

* Coupling analysis

---

## Cyclomatic Complexity

Measures decision complexity.

Use Cases:

* Bug risk estimation
* Audit effort estimation

---

## NPath Complexity

Measures the number of execution paths.

Use Cases:

* Testability analysis

---

## Lines of Code (LOC)

Measures source code size.

---

## Depth of Inheritance

Inheritance hierarchy depth.

---

## Coupling

Degree of dependency between components.

---

## Cohesion

Degree of internal consistency within a component.

---

# 7. Hotspots

## Hot Function

A critical function.

Indicators:

* High fan-in
* High complexity
* External exposure
* Sensitive data processing

---

## Hot Class

A critical class.

Indicators:

* High usage
* High dependency count
* Business criticality

---

## Hot Package

A critical package.

Indicators:

* High incoming dependencies
* High outgoing dependencies

---

# 8. Flow Analysis

## Forward Analysis

Analysis direction:

```text
Source → Sink
```

Use Cases:

* Taint tracking

---

## Backward Analysis

Analysis direction:

```text
Sink → Source
```

Use Cases:

* Root cause analysis
* Attack path reconstruction

---

## Interprocedural Analysis

Analysis across function boundaries.

---

## Intraprocedural Analysis

Analysis within a single function.

---

# 9. Graph Algorithms

## Breadth-First Search (BFS)

Use Cases:

* Reachability analysis

---

## Depth-First Search (DFS)

Use Cases:

* Graph exploration
* Dependency traversal

---

## Dijkstra

Use Cases:

* Shortest attack path
* Dependency path analysis

---

## Tarjan Strongly Connected Components (SCC)

Use Cases:

* Cycle detection

---

## Dominator Tree

Use Cases:

* CFG analysis
* Control dependency analysis

---

## PageRank

Use Cases:

* Important function detection
* Critical component ranking

---

## Betweenness Centrality

Use Cases:

* Hub detection
* Architectural choke points

---

## Closeness Centrality

Use Cases:

* Influence analysis

---

## Community Detection

Use Cases:

* Automatic subsystem discovery
* Architecture recovery

---

# 10. Detectable Vulnerabilities

## SQL Injection

Pattern:

```text
SOURCE
 →
TAINT
 →
SQL_SINK
```

---

## Command Injection

Pattern:

```text
SOURCE
 →
COMMAND_SINK
```

---

## Path Traversal

Pattern:

```text
SOURCE
 →
FILE_SINK
```

---

## Server-Side Request Forgery (SSRF)

Pattern:

```text
SOURCE
 →
HTTP_CLIENT
```

---

## Cross-Site Scripting (XSS)

Pattern:

```text
SOURCE
 →
HTML_SINK
```

---

## LDAP Injection

Pattern:

```text
SOURCE
 →
LDAP_QUERY
```

---

## Template Injection

Pattern:

```text
SOURCE
 →
TEMPLATE_ENGINE
```

---

## Secret Leakage

Pattern:

```text
SECRET
 →
LOG
 →
NETWORK
```

---

## Authentication Bypass

Pattern:

```text
ENDPOINT
 →
SENSITIVE_ACTION
```

Without:

```text
AUTHORIZATION_CHECK
```

---

## Privilege Escalation

Pattern:

```text
USER
 →
ADMIN_ACTION
```

Without:

```text
ROLE_VALIDATION
```

---

# 11. Dependency and Supply Chain Security

## Package

External software component.

---

## Dependency

Direct dependency.

---

## Transitive Dependency

Indirect dependency.

---

## SBOM

Software Bill of Materials.

---

## CVE

Common Vulnerabilities and Exposures entry.

---

## Vulnerable Dependency

Dependency affected by one or more CVEs.

---

## Reachable Vulnerability

A vulnerable dependency that can actually be reached from application code.

---

# 12. Recommended Data Model

## Node

```json
{
  "id": "",
  "type": "",
  "name": "",
  "tags": [],
  "properties": {},
  "location": {},
  "metrics": {}
}
```

## Edge

```json
{
  "source": "",
  "target": "",
  "type": "",
  "properties": {}
}
```

---

# 13. Target Vision

Build a Unified Security Knowledge Graph capable of answering questions such as:

* Which endpoints reach the database?
* Which user-controlled inputs reach security-sensitive sinks?
* Which functions are the most critical?
* Which vulnerable dependencies are actually exploitable?
* Which attack paths can lead to privilege escalation?
* Which components would have the highest impact if compromised?

This graph should serve as the foundation of a CodeQL-, Joern-, Semgrep-, or SonarQube-like platform for advanced source code and application security analysis.
