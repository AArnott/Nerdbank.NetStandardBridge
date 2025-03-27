# Nerdbank.NetStandardBridge

***A reference + facade library to bring additional types to .NET Standard.***

[![NuGet package](https://img.shields.io/nuget/v/Nerdbank.NetStandardBridge.svg)](https://www.nuget.org/packages/Nerdbank.NetStandardBridge)
[![Build Status](https://dev.azure.com/andrewarnott/OSS/_apis/build/status/Nerdbank.NetStandardBridge/Nerdbank.NetStandardBridge?branchName=main)](https://dev.azure.com/andrewarnott/OSS/_build/latest?definitionId=36&branchName=main)

## Features

### Polyfill behavior

Defines the following types in a .NET Standard 2.0 library:

* `ImportedFromTypeLibAttribute`
* `TypeLibVersionAttribute`

These types get forwarded to the appropriate runtime types.
The assembly in the package *is* required at runtime unless all referencing projects actually target a framework that already defines the attributes.

### Additional functionality when migrating to .NET Core, .NET 5+

#### .NET Framework assembly load behavior

The `NetFrameworkAssemblyResolver` class eases migration of an extensible .NET Framework application to .NET Core / .NET 5+ by emulating assembly load behavior of the .NET Framework CLR including probing paths, codebase paths, binding redirects and honoring the full assembly name when loading assembly references.

For example:

```cs
var assemblyLoader = new NetFrameworkAssemblyResolver("myapp.exe.config");
assemblyLoader.HookupResolver(AssemblyLoadContext.Default);
```
