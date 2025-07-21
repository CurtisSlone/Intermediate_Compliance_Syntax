# Intermediate Compliance Syntax (ICS) - Complete Specification

## Overview

The Intermediate Compliance Syntax (ICS) is a domain-specific language that defines portable, structured compliance rules for cross-platform security evaluation. Inspired by SCAP/OVAL standards, ICS simplifies complex XML representations into a concise, human-readable, and execution-ready format.

ICS supports consistent and structured compliance definitions that can be processed by evaluation engines and executed across various platforms (Linux, Windows, macOS, network devices, cloud environments, etc.).

---

## Architecture

ICS uses a **definition-scoped architecture**, meaning all logic and data required for evaluating a compliance rule are encapsulated in a single `DEF` block. This localized design ensures high portability, modularity, and independent execution of each rule.

Each `DEF` block contains:

* Variable declarations (`VAR`)
* Runtime operations (`RUN`)
* Set definitions (`SET`) 
* Logical criteria trees for evaluation (`CRI`/`CTN`)

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

## Content Handling

### Single-Line Content

Use regular double quotes for single-line content:

```ics
filepath "/etc/passwd"
pattern "^root:.*"
```

### Multiline Content

Use **triple quotes** (`"""`) for content that spans multiple lines:

```ics
sql """SELECT 
  name as linked_server,
  provider,
  data_source
FROM sys.servers
WHERE is_linked = 1;"""
```

**Rules for Triple Quotes:**
- Use for any content containing actual newline characters
- Content between triple quotes preserves all formatting and whitespace  
- No escape sequences needed within triple quotes
- Preferred over escaped newlines (`\\n`) for readability

**Comparison of Approaches:**

❌ **Problematic - Raw Multiline:**
```ics
sql "SELECT name
FROM table"  # Parser error - line breaks not allowed
```

❌ **Discouraged - Escape Sequences:**  
```ics
sql "SELECT\\n  name\\nFROM table"  # Hard to read and maintain
```

✅ **Recommended - Triple Quotes:**
```ics
sql """SELECT
  name
FROM table"""  # Clean, readable, maintainable
```

---

## Core Elements

### DEF

Defines a complete compliance rule.

```ics
DEF
    VAR ...
    RUN ...
    SET ...
    CRI ...
DEF_END
```

---

### VAR

Declares a variable with optional initial values.

```ics
VAR timeout_threshold int 600
VAR directories string ['/bin','/usr/bin']
VAR sql_version string ""  # External variable placeholder
```

**Variable Types:**
- **Constant variables**: Have fixed values
- **External variables**: Placeholders for runtime input
- **Runtime variables**: Computed by `RUN` blocks

---

### RUN

Performs runtime operations to compute variable values. All local_variable operations from OVAL are supported.

#### Basic Operations

**CONCAT** - Concatenate multiple components:
```ics
RUN full_path CONCAT
    literal "/etc/"
    VAR config_filename
RUN_END
```

**SPLIT** - Split strings on delimiter:
```ics
RUN path_parts SPLIT ":"
    object_component "path_obj" "value"
RUN_END
```

**ARITHMETIC** - Mathematical operations:
```ics
RUN total ARITHMETIC add
    VAR value1
    VAR value2
RUN_END
```

#### Advanced Operations

**SUBSTRING** - Extract substring from source:
```ics
RUN first_digit SUBSTRING 1 1
    VAR umask_string
RUN_END
```
- Parameters: `start length` (1-based indexing)

**REGEX_CAPTURE** - Extract regex groups:
```ics
RUN captured_path REGEX_CAPTURE "^(.*)$"
    object_component "registry_obj" "value"
RUN_END
```

**UNIQUE** - Remove duplicates:
```ics
RUN unique_ports UNIQUE
    object_component "firewall_rules" "port"
RUN_END
```

**COUNT** - Count elements:
```ics
RUN total_files COUNT
    object_component "file_search" "filepath"
RUN_END
```

**END** - Ensure string ends with character:
```ics
RUN path_with_slash END "\"
    VAR base_path
RUN_END
```

#### Complex Nested Arithmetic

```ics
RUN umask_decimal ARITHMETIC add
    arithmetic multiply
        literal "64"
        VAR digit1
    arithmetic multiply
        literal "8"
        VAR digit2
    VAR digit3
RUN_END
```

**RUN Components:**
- `literal "value"` - Static text/numbers
- `VAR variable_name` - Variable references  
- `object_component "obj_id" "field"` - Extract from object results
- `arithmetic operation` - Nested arithmetic operations

---

### SET

Defines set operations (union, intersection, complement) over objects.

```ics
SET filtered_objects complement
    OBJECT
        path "/usr/bin"
        filename ".*"
    OBJECT_END
    SET excluded_files union
        OBJECT
            filename "temp.*"
        OBJECT_END
        OBJECT
            filename "*.log"
        OBJECT_END
    SET_END
SET_END
```

**Set Operations:**
- `union` - Combine all objects
- `intersection` - Objects present in all sets
- `complement` - Objects in first set but not others

---

### CRI

Defines logical grouping (AND/OR) of criteria.

```ics
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

**Logical Operators:**
- `AND` - All criteria must pass
- `OR` - Any criteria must pass
- Optional `true` flag for negation: `CRI AND true`

---

### CTN

A criterion block representing a single condition.

```ics
CTN sqlext
    TEST any_exist all
    OBJECT
        engine VAR db_engine
        sql """SELECT * FROM users 
WHERE active = 1"""
    OBJECT_END
    STATE "Active users found"
        result
            field "username" string "pattern match" "admin.*"
    STATE_END
CTN_END
```

**CTN Types:**
- `file`, `registry`, `textfilecontent54`
- `sqlext`, `wmi`, `xmlfilecontent`
- `variable`, `process`, `package`
- `shadow`, `password`, `shellcommand`
- And all other OVAL test types

---

### OBJECT

Defines the data to inspect.

```ics
OBJECT
    BEHAVIOR recurse_down_local_d -1 ignore_case
    filepath string equals VAR computed_path "at least one" 
    pattern "pattern match" """^[\s]*UMASK[\s]+([^#\s]*)"""
OBJECT_END
```

**Object Features:**
- **BEHAVIOR** tokens for collection behavior
- **Variable references** with `VAR variable_name`
- **Variable checks** (`"at least one"`, `"all"`, etc.)
- **Multiline patterns** with triple quotes
- **FILTER** blocks for additional constraints

**Variable Reference Syntax:**
```ics
field datatype operation VAR variable_name [var_check]
```

---

### STATE

Defines expected values or constraints.

```ics
STATE "Configuration must be enabled"
    value string equals "true"
    timeout int "greater than" VAR timeout_threshold
STATE_END
```

**Complex States with Fields:**
```ics
STATE "Database query results"
    result
        field "linked_server" string "case insensitive equals" VAR approved_servers "at least one"
        field "provider" string equals "SQLNCLI11"
STATE_END
```

---

### TEST

Defines how objects and states are evaluated.

```ics
TEST "at least one exists" all AND
```

**Check Existence Values:**
- `"at least one exists"`, `"all exist"`, `"any exist"`
- `"none exist"`, `"only one exists"`

**Check Values:**
- `all` - All collected items must satisfy states
- `"at least one"` - One or more items must satisfy states

**State Operators:**
- `AND` - All states must be satisfied (default)
- `OR` - Any state must be satisfied

---

### FILTER

Adds filtering conditions to objects.

```ics
FILTER exclude "Exclude temporary files"
    filename string "pattern match" "temp.*"
FILTER_END
```

**Filter Actions:**
- `include` - Include matching items
- `exclude` - Exclude matching items

---

### BEHAVIOR

Modifies object collection behavior.

```ics
BEHAVIOR recurse_down_local_d -1 ignore_case multiline
```

**Common Behaviors:**
- `recurse_down_local_d depth` - Recursive directory traversal
- `ignore_case` - Case-insensitive matching
- `multiline` - Multi-line pattern matching
- `context="instance"` - Database instance context

---

## Variable Dependency Resolution

ICS automatically resolves variable dependencies in correct order:

1. **External/Constant Variables** - Declared first
2. **Object-Dependent Variables** - Variables using `object_component`  
3. **Variable-Dependent Variables** - Variables referencing other variables
4. **Complex Computations** - Nested arithmetic and transformations

**Example Dependency Chain:**
```ics
DEF
    # 1. External input
    VAR umask_input string ""
    
    # 2. Extract components  
    RUN digit1 SUBSTRING 1 1
        VAR umask_input
    RUN_END
    
    # 3. Compute result
    RUN umask_decimal ARITHMETIC add
        arithmetic multiply
            literal "64"
            VAR digit1
        # ... more operations
    RUN_END
    
    # 4. Use in criteria
    CRI AND
        CTN variable
            TEST "at least one exists" all
            OBJECT
                var_ref VAR umask_decimal
            OBJECT_END
        CTN_END  
    CRI_END
DEF_END
```

---

## Supported Data Types

* `string` - Text values
* `int` - Integer numbers  
* `float` - Floating point numbers
* `boolean` - True/false values
* `record` - Complex structured data

---

## Supported Operations

**Comparison Operations:**
* `equals`, `not_equal`  
* `greater_than`, `less_than`
* `"greater than or equal"`, `"less than or equal"`

**String Operations:**
* `"pattern match"` - Regular expression matching
* `"case insensitive equals"` - Case-insensitive comparison
* `contains`, `"starts with"`, `"ends with"`

**Set Operations:**
* `subset_of`, `superset_of`
* `matches` - Pattern-based matching

---

## Complete Example

```ics
DEF
    # External configuration
    VAR required_umask string "027"
    
    # Extract individual digits
    RUN digit1 SUBSTRING 1 1
        VAR required_umask  
    RUN_END
    
    RUN digit2 SUBSTRING 2 1
        VAR required_umask
    RUN_END
    
    RUN digit3 SUBSTRING 3 1
        VAR required_umask
    RUN_END
    
    # Convert to decimal for comparison
    RUN umask_decimal ARITHMETIC add
        arithmetic multiply
            literal "64"
            VAR digit1
        arithmetic multiply  
            literal "8"
            VAR digit2
        VAR digit3
    RUN_END
    
    # Extract actual system umask
    RUN system_digit1 SUBSTRING 1 1
        object_component "login_defs" "subexpression"
    RUN_END
    
    RUN system_umask ARITHMETIC add
        arithmetic multiply
            literal "64"
            VAR system_digit1
        # ... similar pattern
    RUN_END
    
    # Compliance check
    CRI AND
        # Verify umask exists in /etc/login.defs
        CTN textfilecontent54
            TEST "at least one exists" all
            OBJECT
                filepath "/etc/login.defs"
                pattern """^[\s]*UMASK[\s]+([^#\s]*)"""
                instance int "greater than or equal" "1"
            OBJECT_END
        CTN_END
        
        # Verify umask value matches requirement
        CTN variable
            TEST "at least one exists" all  
            OBJECT
                var_ref VAR system_umask
            OBJECT_END
            STATE "Umask must match required value"
                value int VAR umask_decimal
            STATE_END
        CTN_END
    CRI_END
DEF_END
```

---

## Best Practices

### Content Formatting
- **Use triple quotes** for SQL, scripts, and multiline content
- **Use regular quotes** for simple strings and paths
- **Preserve formatting** in complex queries and configurations

### Variable Management  
- **Declare external variables** with appropriate placeholder values
- **Use descriptive variable names** that indicate their purpose
- **Let dependency analysis** handle variable ordering automatically

### Object References
- **Use `SET_REF`** for complex set operations
- **Include `var_check`** specifications for variable-dependent objects
- **Add meaningful comments** to complex object configurations

### State Definitions
- **Use field specifications** for complex database/API results  
- **Include descriptive comments** explaining compliance requirements
- **Group related checks** using appropriate logical operators

---

## Migration from OVAL

The ICS transpiler automatically converts:
- **local_variable** → `RUN` blocks with appropriate operations
- **constant_variable** → `VAR` declarations  
- **external_variable** → `VAR` declarations with placeholders
- **Complex XML** → Clean, readable ICS syntax
- **Multiline content** → Triple-quoted strings
- **Variable references** → `VAR variable_name` syntax
- **Set operations** → `SET` blocks with `SET_REF` usage

This ensures complete compatibility with existing OVAL content while providing a more maintainable and human-readable format.

---

## Summary

ICS enables structured, declarative compliance definitions that are portable, modular, and semantically rich. Its domain-specific syntax handles complex compliance logic including variable computations, multiline content, set operations, and dependency resolution, making it suitable for integration into compliance pipelines, scanners, and orchestration tools across diverse platforms.
