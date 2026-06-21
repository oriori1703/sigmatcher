# Macros reference

Macros let one definition reference properties from another matched result.
They use the format:

```
${<result_name>.<property>}
```

The dependency resolver automatically sorts definitions so that referenced
results are analyzed first — definition order in the YAML file doesn't matter.

## Available properties

### Class

| Property | Description | Example |
|----------|-------------|---------|
| `name` | Short class name | `NetworkManager` |
| `package` | Package name | `com.example` |
| `full_name` | Package + name | `com.example.NetworkManager` |
| `java` | Full Java representation (includes `L` and `;`) | `Lcom/example/NetworkManager;` |
| `fields.<name>` | Matched field object | — |
| `methods.<name>` | Matched method object | — |
| `exports.<name>` | Matched export object | — |

### Method

| Property | Description | Example |
|----------|-------------|---------|
| `name` | Method name | `openConnection` |
| `argument_types` | Argument types string | `Ljava/lang/String;` |
| `return_type` | Return type | `V` |
| `java` | Full Java representation | `openConnection(Ljava/lang/String;)V` |

### Field

| Property | Description | Example |
|----------|-------------|---------|
| `name` | Field name | `socket` |
| `type` | Field type | `Ljava/net/Socket;` |
| `java` | Full Java representation | `socket:Ljava/net/Socket;` |

### Export

| Property | Description |
|----------|-------------|
| `value` | The captured string value |

## Examples

```yaml
# Reference a class's Java representation
signature: 'new-instance v\d+, ${ConnectionManager.java}'

# Reference a field using dotted path
signature: 'iget-object v\d+, v\d+, ${ConnectionManager.fields.socket.java}'

# Reference an export value
signature: '^\.class public L${HelperWithRef.exports.targetRef.value};$'
```

## Important notes

- Definition order in the YAML file doesn't matter — sigmatcher sorts the
  dependency graph automatically
- Macros are resolved at analysis time after the dependency graph is sorted
- If a macro references a result that cannot be matched, the signature will
  fail to match
- Use the `java` property when you need the complete Java/Smali representation
- Macros work with both `regex` and `glob` signature types
