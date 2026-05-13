# sigmatcher

[![PyPI - Version](https://img.shields.io/pypi/v/sigmatcher.svg)](https://pypi.org/project/sigmatcher)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/sigmatcher.svg)](https://pypi.org/project/sigmatcher)

-----

Sigmatcher is a powerful tool designed to automate the process of matching Java classes and methods across different
versions of an application.
It leverages signature on the smali (disassembled java code) to identify and correlate code elements, making it an
invaluable resource for long-running reverse engineering projects.

## Table of Contents

- [Installation](#installation)
- [Quick Usage](#quick-usage)
- [Creating Signature Files](#creating-signature-files)
  - [Signature File JSON Schema](#signature-file-json-schema)
  - [Structure of a Signature File](#structure-of-a-signature-file)
  - [Using Macros in Signatures](#using-macros-in-signatures)
  - [Dynamic Class Names](#dynamic-class-names)
- [License](#license)

## Installation

Before installing `sigmatcher`, ensure you have the following prerequisites installed:

- `ripgrep`: A command-line search tool that recursively searches your current directory for a regex pattern.
  Install `ripgrep` by following the instructions on its [GitHub page](https://github.com/BurntSushi/ripgrep).
- `apktool`: A tool for reverse engineering and disassembling Android apk files.
  Install `apktool` by following the instructions on its [official website](https://ibotpeaches.github.io/Apktool/install/).

```console
git clone https://github.com/oriori1703/sigmatcher.git
pip install ./sigmatcher
```

## Quick Usage

To get started with sigmatcher, follow these steps:

1. **Create a Signature File**: Signature files (.yaml) define the patterns and signatures that Sigmatcher will use to
   analyze the APK files.
   These files should specify the classes, methods, and fields you're interested in, along with any version-specific
   information. See the [Creating Signature Files](#creating-signature-files) section example for the format.
2. **Analyze your app package**: With your signature file ready, you can analyze different Android package inputs:
   - single APK (`.apk`)
   - bundle archive (`.apkm` / `.xapk`)
   - directory containing split APK parts (`*.apk`, searched recursively)

   Use the sigmatcher analyze command, specifying the input path and the signature file(s):

   ```shell
   sigmatcher analyze path/to/your/app.apk --signatures path/to/your/signature_file.yaml
   ```

   ```shell
   sigmatcher analyze path/to/your/app.apkm --signatures path/to/your/signature_file.yaml
   ```

   ```shell
   sigmatcher analyze path/to/your/split-apks/ --signatures path/to/your/signature_file.yaml
   ```

   This command will decode the package parts, apply the signatures, and output the analysis results, highlighting matched
   classes, methods and fields.

## Creating Signature Files

Signature files are YAML formatted documents that `sigmatcher` uses to identify and match Java classes, methods, and
fields in APK files. These files allow you to specify the elements you're interested in tracking across different
versions of an application.

### Signature File JSON Schema

To help you create a signature file `sigmatcher` provides a JSON schema that you can use to validate your signature, and
get autocompletion and intellisense from your IDE.
You can get it by running the following command:

```shell
sigmatcher schema --output definitions.schema.json
```

You can add the one of the following comments to the top of your signature file depending on your IDE:

Intellij IDEs:

```yaml
# $schema: ./definitions.schema.json
```

yaml-language-server IDEs (vs-code, neovim, etc):

```yaml
# yaml-language-server: $schema=./definitions.schema.json
```

You can also combine them to support both:

```yaml
# $schema: ./definitions.schema.json
# yaml-language-server: $schema=./definitions.schema.json
```

### Structure of a Signature File

A signature file consists of a list of definitions, where each definition represents a class, method, or field you want
to match. Each definition can include one or more signatures, which are patterns `sigmatcher` will use to find matches
in the smali code.

Here's a basic example of what a signature file looks like:

```yaml
# $schema: ./definitions.schema.json
# yaml-language-server: $schema=./definitions.schema.json

- name: "ConnectionManager"
  package: "com.example.package.network"
  signatures:
    - signature: 'ConnectionManager/openConnection: could not open connection due to a DNS error'
      type: regex
      count: 1
  methods:
    - name: "read"
      signatures:
        - signature: 'const-string v\d+, "Failed to read data from the server"'
          type: regex
          count: 1
          version_range: ">=1.0.0, <1.3.7"
        - signature: 'const-string v\d+, "Failed to read data because of a network error"'
          type: regex
          count: 1
          version_range: ">=1.3.7"
  fields:
    - name: "socket"
      signatures:
        - signature: '^\.field private final (?P<match>.+:Ljava/net/Socket;)'
          type: regex
          count: 1
```

#### Key Components

- name: The name of the class, method, or field.
- methods: A list of method definitions within a class. Follows a similar structure to the class definition.
- fields: A list of field definitions within a class. Follows a similar structure to the class definition.
- exports: A list of export definitions within a class. Exports can be any string in the code. They are mainly used in
  combination with macros to create more complex signatures.
- signatures: A list of signatures for the class, method, or field. Each signature includes:
  - type: The type of signature (for now only `regex` and `glob`).
  - signature: The pattern to match, depending on the signature type.
      For classes and methods they just need to match anywhere within the class/method. For fields and exports, they
      need to match the full field expression/export string, i.e. using the `match` capture group for regex signatures.
  - count: The number of times the signature should appear to be considered a match. Can be either an integer or a string of the form "min-max". Defaults to 1.
  - version_range: Optional. Specifies the application versions this signature applies to, using version specifiers
      like those used by pip and described in
      [PEP-440](https://packaging.python.org/en/latest/specifications/version-specifiers/#version-specifiers).
      This could also contains a list of specifiers, which act like a logical "or" operator.

Most of those fields are optional, and you can use them as needed.

### Using Macros in Signatures

Macros allow you to reference properties from other matched results within your signatures,
enabling dynamic and context-aware pattern matching.
Macros are particularly useful when you need to create signatures that depend on information
from previously matched classes, methods, fields, or exports.

#### Macro Syntax

Macros use the format `${<result_name>.<property>}`, where:

- `result_name` is the name of another definition in your signature file
- `property` is a property of the matched result object

#### Available Properties

Depending on the type of result, different properties are available:

**For Classes:**

- `name`: The class name (e.g., "ConnectionManager")
- `package`: The package name (e.g., "com.example.package.network")
- `full_name`: The complete class name with package (e.g., "com.example.package.network.ConnectionManager")
- `java`: The Java representation (e.g., "Lcom/example/package/network/ConnectionManager;")
- `fields.FieldName`: Access to specific field results (e.g., `fields.socket` returns the matched field object)
- `methods.MethodName`: Access to specific method results (e.g., `methods.read` returns the matched method object)
- `exports.ExportName`: Access to specific export results (e.g., `exports.someExport` returns the matched export object)

**For Methods:**

- `name`: The method name (e.g., "read")
- `argument_types`: The method argument types (e.g., "Ljava/lang/String;")
- `return_type`: The method return type (e.g., "V")
- `java`: The complete Java representation (e.g., "read(Ljava/lang/String;)V")

**For Fields:**

- `name`: The field name (e.g., "socket")
- `type`: The field type (e.g., "Ljava/net/Socket;")
- `java`: The complete Java representation (e.g., "socket:Ljava/net/Socket;")

**For Exports:**

- `value`: The exported string value

#### Macro Example

Here's an example showing how macros can be used to create interdependent signatures:

```yaml
# $schema: ./definitions.schema.json
# yaml-language-server: $schema=./definitions.schema.json

- name: "ConnectionManager"
package: "com.example.package.network"
signatures:
 - signature: 'ConnectionManager/openConnection: could not open connection due to a DNS error'
   type: regex
   count: 1
fields:
 - name: "socket"
   signatures:
     - signature: '^\.field private final (?P<match>.+:Ljava/net/Socket;)'
       type: regex
       count: 1

- name: "NetworkHandler"
package: "com.example.package.network"
signatures:
 - signature: 'new-instance v\d+, ${ConnectionManager.java}'
   type: regex
   count: 1
methods:
 - name: "handleConnection"
   signatures:
     - signature: 'iget-object v\d+, v\d+, ${ConnectionManager.fields.socket.java}'
       type: regex
       count: 1
```

In this example:

- The `NetworkHandler` class uses a macro to reference the Java representation of the `ConnectionManager` class
- The `handleConnection` method uses a macro to reference the socket field from the `ConnectionManager` class

#### Important Notes

- **Definition Order Doesn't Matter**: Sigmatcher automatically sorts the dependency graph, so macros can reference results that are defined later in the YAML file
- Macros are resolved at analysis time after the dependency graph is sorted
- If a macro references a result that cannot be matched, the signature will fail to match
- Use the `java` property when you need the complete Java/Smali representation of a class, method, or field
- Macros work with both `regex` and `glob` signature types

### Dynamic Class Names

Normally a `ClassDefinition` declares the human-readable class `name` up front and `sigmatcher`
finds the obfuscated class it maps to. Sometimes the readable name is not known in advance but
is embedded in the obfuscated class itself — for example, a class whose `toString()` returns
a literal containing its original name:

```smali
const-string v0, "ConnectionManager{state=connected"
```

In that case you can opt in to **dynamic class name** capture: declare a placeholder identifier
as the YAML `name`, set `dynamic_name: true`, and add a `(?P<class_name>...)` named group in one
of the signatures. The captured substring becomes the readable name in all output mapping
formats; the placeholder `name` is still used as the identifier for macro references, caching,
and the dependency graph.

```yaml
# $schema: ./definitions.schema.json
# yaml-language-server: $schema=./definitions.schema.json

- name: "UnknownToStringClass"
  dynamic_name: true
  signatures:
    - signature: '"(?P<class_name>\w+)\{state='
      type: regex
      count: 1
```

Notes:

- The placeholder `name` (`UnknownToStringClass` above) is what other definitions reference via
  macros (e.g. `${UnknownToStringClass.java}`), and what appears in error messages.
- If a `dynamic_name: true` definition's signatures match the file but no `(?P<class_name>...)`
  capture is produced, the match fails (`NoMatchesError`).
- If the capture yields multiple distinct values from the matched smali, the match fails
  (`TooManyMatchesError`). Tighten the regex to disambiguate.
- Captures are compared after `str.strip()`: leading/trailing whitespace is treated as
  insignificant, and a capture that is empty or whitespace-only is dropped. Two
  occurrences that differ only in ambient whitespace (e.g. `" Foo"` and `"Foo"`) collapse
  to one value; if you need to distinguish them, narrow the regex so the capture group
  cannot pick up surrounding whitespace.
- A `dynamic_name: true` definition must have at least one signature carrying the
  `(?P<class_name>...)` group applicable to the current app version. If a `version_range`
  filters the only capturing signature out, analysis raises a dedicated
  `MissingClassNameGroupError` pointing at the definition and version.
- The opt-in flag is required: putting a `(?P<class_name>...)` group on a class signature
  without setting `dynamic_name: true` is a validation error, to prevent silent activation.

## License

`sigmatcher` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
