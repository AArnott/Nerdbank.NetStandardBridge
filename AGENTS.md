# Copilot instructions for this repository

## High level guidance

* Review the `CONTRIBUTING.md` file for instructions to build and test the software.
* Run the `.github/Prime-ForCopilot.ps1` script (once) before running any `dotnet` or `msbuild` commands.
  If you see any build errors about not finding git objects or a shallow clone, it may be time to run this script again.

## Software Design

* Design APIs to be highly testable, and all functionality should be tested.
* Avoid introducing binary breaking changes in public APIs of projects under `src` unless their project files have `IsPackable` set to `false`.

## Testing

**IMPORTANT**: This repository uses xUnit with the VSTest runner (`Microsoft.NET.Test.Sdk` + `xunit.runner.visualstudio`), not TUnit.

* There should generally be one test project (under the `test` directory) per shipping project (under the `src` directory). Test projects are named after the project being tested with a `.Tests` suffix.
* Use standard VSTest `--filter` expressions with `dotnet test`.

### Running Tests

**Run all tests**:
```bash
dotnet test --no-build -c Release
```

**Run tests for a specific test project**:
```bash
dotnet test --project test/Nerdbank.NetStandardBridge.Tests/Nerdbank.NetStandardBridge.Tests.csproj --no-build -c Release
```

**Run a single test method**:
```bash
dotnet test --project test/Nerdbank.NetStandardBridge.Tests/Nerdbank.NetStandardBridge.Tests.csproj --no-build -c Release --filter "FullyQualifiedName~ClassName.MethodName"
```

**Run all tests in a test class**:
```bash
dotnet test --project test/Nerdbank.NetStandardBridge.Tests/Nerdbank.NetStandardBridge.Tests.csproj --no-build -c Release --filter "FullyQualifiedName~ClassName"
```

**Run tests for a specific framework only**:
```bash
dotnet test --project test/Nerdbank.NetStandardBridge.Tests/Nerdbank.NetStandardBridge.Tests.csproj --no-build -c Release --framework net8.0
```

On Windows, test TFMs also include `net472` and `net462`.


## Coding style

* Honor StyleCop rules and fix any reported build warnings *after* getting tests to pass.
* In C# files, use namespace *statements* instead of namespace *blocks* for all new files.
* Add API doc comments to all new public and internal members.
