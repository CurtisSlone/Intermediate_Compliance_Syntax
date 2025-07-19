Here is a rewritten version of the `README.md` focused purely on the Intermediate Compliance Syntax (ICS), its architecture, syntax, semantics, and usage—excluding all mentions of AI, training data, or registries:

---

# Intermediate Compliance Syntax (ICS)

## Overview

The Intermediate Compliance Syntax (ICS) is a domain-specific language that defines portable, structured compliance rules for cross-platform security evaluation. Inspired by SCAP/OVAL standards, ICS simplifies complex XML representations into a concise, human-readable, and execution-ready format.

ICS supports consistent and structured compliance definitions that can be processed by evaluation engines and executed across various platforms (Linux, Windows, macOS, network devices, cloud environments, etc.).

---

## Architecture

ICS uses a **definition-scoped architecture**, meaning all logic and data required for evaluating a compliance rule are encapsulated in a single `DEF` block. This localized design ensures high portability, modularity, and independent execution of each rule.

Each `DEF` block contains:

* Variable declarations
* Runtime operations (e.g., string manipulation, lookups)
* Set definitions (e.g., unions of object paths)
* Logical criteria trees for evaluation (CRI/CTN)

---

## Syntax Summary

ICS uses **indented, block-based syntax** with consistent token structure and explicit `*_END` block closers.

### General Syntax Form:

```
TOKEN [arguments...]
    [indented content]
TOKEN_END
```

### Indentation Rules:

* Use **4 spaces** per level
* Tabs are **not allowed**
* Indentation is semantically significant

---

## Core Elements

### DEF

Defines a complete compliance rule.

```
DEF
    VAR ...
    RUN ...
    SET ...
    CRI ...
DEF_END
```

---

### VAR

Declares a variable.

```
VAR var_100 string
VAR directories string ['/bin','/usr/bin']
```

---

### RUN

Performs a runtime operation.

```
RUN var_100 CONCAT
    literal "/etc/"
    VAR config_filename
RUN_END
```

Supported operations: `CONCAT`, `SPLIT`, `ARITHMETIC`, `COUNT`, `UNIQUE`, etc.

---

### SET

Defines a set operation (union, intersection, complement) over OBJECTs or nested SETs.

```
SET obj_100 union
    OBJECT
        path "/etc"
        filename "passwd"
    OBJECT_END
    OBJECT
        path "/etc"
        filename "shadow"
    OBJECT_END
SET_END
```

---

### CRI

Defines logical grouping (AND/OR) of criteria.

```
CRI AND
    CTN registry
        TEST all
        OBJECT ...
        STATE ...
    CTN_END
    CTN file
        TEST all
        OBJECT ...
        STATE ...
    CTN_END
CRI_END
```

---

### CTN

A criterion block. Represents a single condition.

```
CTN file
    TEST all
    OBJECT
        path "/etc"
        filename "passwd"
    OBJECT_END
    STATE
        value string "pattern match" "root.*"
    STATE_END
CTN_END
```

---

### OBJECT

Defines the data to inspect.

```
OBJECT
    path "/etc"
    filename "shadow"
OBJECT_END
```

Supports `BEHAVIOR` tokens (e.g., recursion depth, symbolic link handling) and `FILTER`s.

---

### STATE

Defines expected values or constraints.

```
STATE
    value string equals "enabled"
STATE_END
```

---

### TEST

Defines how multiple objects and states are evaluated.

```
TEST all at_least_one_exists
```

---

### FILTER

Adds filter conditions on OBJECTs.

```
FILTER exclude "exclude symlinks"
    type string not_equal "symbolic_link"
FILTER_END
```

---

### BEHAVIOR

Modifies object collection behavior.

```
BEHAVIOR recurse_down_local_d -1 ignore_case
```

---

## Semantics

ICS semantics are centered around:

* **Data Resolution**: Constants, runtime-extracted values, and derived paths
* **Set Evaluation**: SET blocks define reusable object groups
* **Criteria Trees**: Logical AND/OR branching of multiple conditions
* **Modularity**: Each `DEF` is an independent evaluation unit

ICS definitions are evaluated in two phases:

1. **Resolution Phase**:

   * Variables and runtime operations are processed
   * SET operations are resolved
   * All references are validated and inlined

2. **Evaluation Phase**:

   * Objects are collected
   * States are evaluated
   * Criteria trees are executed and results returned

---

## Example

```
DEF
    VAR timeout_threshold int 600

    SET obj_100 union
        OBJECT
            path "/etc/profile.d"
            filename "timeout.sh"
        OBJECT_END
    SET_END

    RUN timeout_values SPLIT " "
        filepath "/etc/profile.d/timeout.sh"
        pattern "TMOUT=(\\d+)"
        instance int 1
    RUN_END

    CRI AND
        CTN file
            TEST all
            OBJECT
                SET_REF obj_100
            OBJECT_END
            STATE "Timeout configuration"
                timeout_value int RUN timeout_values
                threshold int greater_than VAR timeout_threshold
            STATE_END
        CTN_END
    CRI_END
DEF_END
```

---

## Supported Data Types

* `string`
* `int`
* `boolean`
* `record`
* `float`

---

## Supported Operations

* `equals`, `not_equal`, `greater_than`, `less_than`
* `"pattern match"`, `"case insensitive equals"`
* `contains`, `matches`, `subset_of`, `superset_of`

---

## Summary

ICS enables structured, declarative compliance definitions that are portable, modular, and semantically rich. Its domain-specific syntax is expressive enough to handle complex compliance logic, yet simple enough to write and review manually. ICS is suitable for integration into compliance pipelines, scanners, and orchestration tools across diverse platforms.
