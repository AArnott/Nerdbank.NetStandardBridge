// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Copyright (c) Microsoft Corporation. All rights reserved.
#if NET462 || NETSTANDARD2_0_OR_GREATER || NETCOREAPP3_1_OR_GREATER
using System.Collections.Immutable;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Reflection;
#if NETCOREAPP
using System.Runtime.Loader;
#endif
using System.Xml.Linq;

namespace Nerdbank.NetStandardBridge;

/// <summary>
/// Emulates .NET Framework assembly load behavior on .NET Core and .NET 5+.
/// </summary>
public class NetFrameworkAssemblyResolver
{
    private const string Xmlns = "urn:schemas-microsoft-com:asm.v1";

    private static readonly ImmutableArray<string> AssemblyExtensions = ImmutableArray.Create(".dll", ".exe");

    /// <summary>
    /// The set of assemblies that the .config file describes codebase paths and/or binding redirects for.
    /// </summary>
    private readonly ReadOnlyDictionary<AssemblySimpleName, AssemblyLoadRules> knownAssemblies;

    private readonly object syncObject = new();

    /// <summary>
    /// A dictionary of assembly simple names (e.g. 'streamjsonrpc') to a list of lazily-constructed <see cref="AssemblyName"/> objects
    /// that <em>may</em> match the assembly whose load has been requested.
    /// Because the <see cref="AssemblyName.CodeBase"/> properties have been initialized in this collection, a matching <see cref="AssemblyName"/>
    /// can allow the user to load the assembly based on its path.
    /// </summary>
    private readonly Dictionary<string, ImmutableArray<Lazy<AssemblyName?>>> fallbackLookupPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// A set of paths that have been integrated into the <see cref="fallbackLookupPaths"/> already.
    /// </summary>
    private readonly HashSet<string> fallbackLookupPathsRecorded = new(StringComparer.OrdinalIgnoreCase);

    private readonly string[] probingPaths;
#if NETCOREAPP3_1_OR_GREATER
    private readonly Dictionary<AssemblyName, VSAssemblyLoadContext> loadContextsByAssemblyName = new(AssemblyNameEqualityComparer.Instance);
#endif

    /// <summary>
    /// Initializes a new instance of the <see cref="NetFrameworkAssemblyResolver"/> class.
    /// </summary>
    /// <param name="configFile">The path to the .exe.config file to parse for assembly load rules.</param>
    /// <param name="baseDir">The path to the directory containing the entrypoint executable. If not specified, the directory containing <paramref name="configFile"/> will be used.</param>
    /// <param name="traceSource">A <see cref="TraceSource"/> to log to.</param>
    public NetFrameworkAssemblyResolver(string configFile, string? baseDir = null, TraceSource? traceSource = null)
    {
        if (string.IsNullOrEmpty(configFile))
        {
            throw new ArgumentException($"'{nameof(configFile)}' cannot be null or empty.", nameof(configFile));
        }

        this.TraceSource = traceSource;
        this.BaseDir = baseDir ?? Path.GetDirectoryName(Path.GetFullPath(configFile)) ?? throw new ArgumentException("Unable to compute the base directory", nameof(baseDir));

        Dictionary<AssemblySimpleName, AssemblyLoadRules> knownAssemblies = new();

        XElement configXml = XElement.Load(configFile);
        XElement? assemblyBinding = configXml.Element("runtime")?.Element(XName.Get("assemblyBinding", Xmlns));
        this.probingPaths = assemblyBinding?.Element(XName.Get("probing", Xmlns))?.Attribute("privatePath")?.Value.Split(';').ToArray() ?? [];
        IEnumerable<XElement> dependentAssemblies = assemblyBinding?.Elements(XName.Get("dependentAssembly", Xmlns)) ?? [];
        foreach (XElement dependentAssembly in dependentAssemblies)
        {
            XElement? assemblyIdentity = dependentAssembly.Element(XName.Get("assemblyIdentity", Xmlns));
            XElement? codeBase = dependentAssembly.Element(XName.Get("codeBase", Xmlns));
            XElement? bindingRedirect = dependentAssembly.Element(XName.Get("bindingRedirect", Xmlns));
            if (assemblyIdentity is null)
            {
                continue;
            }

            string? assemblySimpleName = assemblyIdentity.Attribute("name")?.Value;
            if (assemblySimpleName is null)
            {
                continue;
            }

            string? publicKeyToken = assemblyIdentity.Attribute("publicKeyToken")?.Value;
            if (publicKeyToken is null)
            {
                continue;
            }

            AssemblySimpleName simpleName = new(assemblySimpleName, publicKeyToken);
            knownAssemblies.TryGetValue(simpleName, out AssemblyLoadRules metadata);

            string? culture = assemblyIdentity.Attribute("culture")?.Value;
            if (culture is null)
            {
                continue;
            }

            if (codeBase is not null)
            {
                string? version = codeBase.Attribute("version")?.Value;
                if (version is null || !Version.TryParse(version, out Version? parsedVersion))
                {
                    continue;
                }

                string? href = codeBase.Attribute("href")?.Value;
                if (href is null)
                {
                    continue;
                }

                string fullPath = Path.Combine(this.BaseDir, href);
                if (metadata.CodeBasePaths.TryGetValue(parsedVersion, out string? existingCodebase))
                {
                    if (existingCodebase != fullPath)
                    {
                        traceSource?.TraceEvent(TraceEventType.Warning, (int)TraceEvents.InvalidConfiguration, "Codebase for {0}, Version={1} given multiple times with inconsistent paths.", assemblySimpleName, version);
                    }
                }
                else
                {
                    metadata = new AssemblyLoadRules(metadata.BindingRedirects, metadata.CodeBasePaths.Add(parsedVersion, fullPath));
                }
            }

            if (bindingRedirect is not null)
            {
                string? oldVersionString = bindingRedirect.Attribute("oldVersion")?.Value;
                string? newVersionString = bindingRedirect.Attribute("newVersion")?.Value;

                if (oldVersionString is not null && newVersionString is not null)
                {
                    metadata = new AssemblyLoadRules(metadata.BindingRedirects.Add(new BindingRedirect(oldVersionString, newVersionString)), metadata.CodeBasePaths);
                }
            }

            knownAssemblies[simpleName] = metadata;
        }

        this.knownAssemblies = new ReadOnlyDictionary<AssemblySimpleName, AssemblyLoadRules>(knownAssemblies);
    }

    /// <summary>
    /// Events that may be traced to the <see cref="TraceSource"/>.
    /// </summary>
    public enum TraceEvents
    {
        /// <summary>
        /// Occurs when an invalid configuration is encountered.
        /// </summary>
        InvalidConfiguration,
    }

    /// <summary>
    /// Gets the <see cref="TraceSource"/> to use for logging.
    /// </summary>
    protected TraceSource? TraceSource { get; }

    /// <summary>
    /// Gets the list of probing paths through which a search for assemblies may be conducted.
    /// </summary>
    protected IReadOnlyList<string> ProbingPaths => this.probingPaths;

    /// <summary>
    /// Gets the fully-qualified path that serves as a base to the relative paths that may appear in <see cref="ProbingPaths"/>.
    /// </summary>
    protected string BaseDir { get; }

    /// <summary>
    /// Applies binding redirect and assembly search path policies to create an <see cref="AssemblyName"/> that is ready to load.
    /// </summary>
    /// <param name="assemblyName">The name of the requested assembly.</param>
    /// <returns>
    /// A copy of <paramref name="assemblyName"/> with binding redirect policy applied.
    /// The <see cref="AssemblyName.CodeBase"/> property will carry the path to the assembly that <em>should</em> be used if the assembly could be found
    /// or if the config file specifies a codebase path for it.
    /// The result will be <see langword="null"/> if <paramref name="assemblyName"/> does not have its <see cref="AssemblyName.Name"/> or <see cref="AssemblyName.Version"/> properties set.
    /// </returns>
    /// <remarks>
    /// The proposed assembly may not have the same name as the one requested in <paramref name="assemblyName"/> due to binding redirects.
    /// </remarks>
    /// <exception cref="InvalidOperationException">Thrown when an assembly was found but did not match the expected version or public key token.</exception>
    public AssemblyName? GetAssemblyNameByPolicy(AssemblyName assemblyName)
    {
        if (assemblyName is null)
        {
            throw new ArgumentNullException(nameof(assemblyName));
        }

        if (assemblyName.Name is null || assemblyName.Version is null)
        {
            return default;
        }

        var simpleName = new AssemblySimpleName(assemblyName.Name, assemblyName.GetPublicKeyToken());
        this.knownAssemblies.TryGetValue(simpleName, out AssemblyLoadRules metadata);
        metadata.TryGetMatch(assemblyName.Version, out Version matchingAssemblyVersion, out string? assemblyFile);
        AssemblyName redirectedAssemblyName = matchingAssemblyVersion != assemblyName.Version
            ? new AssemblyName(assemblyName.FullName) { Version = matchingAssemblyVersion }
            : new AssemblyName(assemblyName.FullName);

        // If a codebase path from the .config file specifies where to find the assembly, only consider that location.
        if (assemblyFile is not null)
        {
            if (this.FileExists(assemblyFile))
            {
                AssemblyName actualAssemblyName = VerifyAssemblyMatch(assemblyFile, requireVersionMatch: false);
                if (actualAssemblyName.Version != matchingAssemblyVersion)
                {
                    throw new InvalidOperationException($"Assembly with matching name \"{assemblyName.Name}\" found but non-matching version. Expected {assemblyName.Version} but found {actualAssemblyName.Version}.");
                }
            }

            redirectedAssemblyName.CodeBase = assemblyFile;
            return redirectedAssemblyName;
        }

        // Fallback to searching for the assembly.
        string candidatePath = Path.Combine(this.BaseDir, assemblyName.Name + ".dll");
        if (this.FileExists(candidatePath))
        {
            VerifyAssemblyMatch(candidatePath, requireVersionMatch: true);
            redirectedAssemblyName.CodeBase = candidatePath;
            return redirectedAssemblyName;
        }

        foreach (string probingPath in this.probingPaths)
        {
            candidatePath = Path.Combine(this.BaseDir, probingPath, assemblyName.Name + ".dll");
            if (this.FileExists(candidatePath))
            {
                VerifyAssemblyMatch(candidatePath, requireVersionMatch: true);
                redirectedAssemblyName.CodeBase = candidatePath;
                return redirectedAssemblyName;
            }
        }

        // Return the best we have, although it won't have CodeBase on it.
        return redirectedAssemblyName;

        AssemblyName VerifyAssemblyMatch(string assemblyFile, bool requireVersionMatch)
        {
            AssemblyName actualAssemblyName = this.GetAssemblyName(assemblyFile);
            if (requireVersionMatch && actualAssemblyName.Version != matchingAssemblyVersion)
            {
                throw new InvalidOperationException($"Assembly with matching name \"{assemblyName.Name}\" found but non-matching version. Expected {matchingAssemblyVersion} but found {actualAssemblyName.Version}.");
            }

            byte[]? actualPublicKeyToken = actualAssemblyName.GetPublicKeyToken();
            byte[]? expectedPublicKeyToken = assemblyName.GetPublicKeyToken();
            if (actualPublicKeyToken != expectedPublicKeyToken)
            {
                bool mismatch = false;
                if (actualPublicKeyToken is null || expectedPublicKeyToken is null)
                {
                    mismatch = true;
                }
                else
                {
                    for (int i = 0; i < actualPublicKeyToken.Length; i++)
                    {
                        mismatch |= actualPublicKeyToken[i] != expectedPublicKeyToken[i];
                    }
                }

                if (mismatch)
                {
                    throw new InvalidOperationException($"Assembly with matching name \"{assemblyName.Name}\" found but non-matching public key token.");
                }
            }

            return actualAssemblyName;
        }
    }

    /// <summary>
    /// Suggests a path for an assembly that might be loaded later.
    /// </summary>
    /// <param name="assemblyPath">The path to the assembly. May be relative to <see cref="Environment.CurrentDirectory"/> or absolute.</param>
    /// <remarks>
    /// <para>
    /// The assembly is not loaded by this call. Rather, it is put into a lookup table so that if the assembly is loaded later
    /// via <see cref="Assembly.Load(AssemblyName)"/> it may be found.
    /// This is useful in .NET because .NET tends to drop the value in <see cref="AssemblyName.CodeBase"/> in assembly load stacks
    /// before the assembly load context has a chance to read it to find the suggested location.
    /// </para>
    /// <para>
    /// The path alone does not provide the full <see cref="AssemblyName"/> to match on, and the file at the provided path is not
    /// read at the time of this call and in fact may not even exist.
    /// But when an assembly whose simple name matches the file name (without extension) given in <paramref name="assemblyPath"/>,
    /// the <see cref="AssemblyName"/> will be lazily retrieved from this path and tested against the assembly whose load is requested.
    /// If it matches, it will be loaded from this path.
    /// </para>
    /// <para>
    /// All assembly paths provided via this API take fallback position in the priority list when loading an assembly.
    /// In other words, if the .config file provides a binding redirect or a codebase path for the assembly, these will be considered
    /// or applied first before attempting to use these lookups.
    /// </para>
    /// <para>
    /// Calling this repeatedly with the same <paramref name="assemblyPath"/> will safely no-op.
    /// </para>
    /// </remarks>
    public void ProvideAssemblyPath(string assemblyPath)
    {
        if (assemblyPath is null)
        {
            throw new ArgumentNullException(nameof(assemblyPath));
        }

        assemblyPath = Path.GetFullPath(assemblyPath);
        lock (this.syncObject)
        {
            if (!this.fallbackLookupPathsRecorded.Add(assemblyPath))
            {
                // We've already processed this path.
                return;
            }

            string simpleName = Path.GetFileNameWithoutExtension(assemblyPath);
            if (!this.fallbackLookupPaths.TryGetValue(simpleName, out ImmutableArray<Lazy<AssemblyName?>> list))
            {
                list = ImmutableArray<Lazy<AssemblyName?>>.Empty;
            }

            list = list.Add(new Lazy<AssemblyName?>(delegate
            {
                if (!this.FileExists(assemblyPath))
                {
                    return null;
                }

                try
                {
                    return this.GetAssemblyName(assemblyPath);
                }
                catch
                {
                    return null;
                }
            }));

            this.fallbackLookupPaths[simpleName] = list;
        }
    }

#if NETCOREAPP3_1_OR_GREATER
    /// <summary>
    /// Loads the given assembly into the appropriate <see cref="AssemblyLoadContext"/>.
    /// </summary>
    /// <param name="assemblyName">
    /// The name of the assembly to load.
    /// If a <see cref="AssemblyName.CodeBase"/> property is provided, that will be used as a fallback after all other attempts to load the assembly have failed.
    /// </param>
    /// <returns>The assembly, if it was loaded.</returns>
    /// <inheritdoc cref="Load(AssemblyName, string, bool)" path="/exception"/>
    /// <inheritdoc cref="GetAssemblyNameByPolicy(AssemblyName)" path="/exception"/>
    public Assembly? Load(AssemblyName assemblyName)
    {
        if (assemblyName is null)
        {
            throw new ArgumentNullException(nameof(assemblyName));
        }

        return this.LoadOrLoadFrom(assemblyName, null);
    }

    /// <summary>
    /// Loads the given assembly into the appropriate <see cref="AssemblyLoadContext"/>.
    /// </summary>
    /// <param name="assemblyPath">The path of the assembly to load.</param>
    /// <returns>The assembly, if it was loaded.</returns>
    /// <remarks>
    /// This will fetch the <see cref="AssemblyName"/> from the specified <paramref name="assemblyPath"/>
    /// and first try to load the assembly using standard load rules.
    /// It will fallback to the specified path if the assembly cannot be found another way.
    /// </remarks>
    /// <inheritdoc cref="Load(AssemblyName, string, bool)" path="/exception"/>
    /// <inheritdoc cref="GetAssemblyNameByPolicy(AssemblyName)" path="/exception"/>
    public Assembly? LoadFrom(string assemblyPath)
    {
        if (assemblyPath is null)
        {
            throw new ArgumentNullException(nameof(assemblyPath));
        }

        return this.LoadOrLoadFrom(this.GetAssemblyName(assemblyPath), assemblyPath);
    }

#elif NETFRAMEWORK
    /// <summary>
    /// Loads the given assembly into the current <see cref="AppDomain"/>.
    /// </summary>
    /// <param name="assemblyName">
    /// The name of the assembly to load.
    /// If a <see cref="AssemblyName.CodeBase"/> property is provided, that will be used as a fallback after all other attempts to load the assembly have failed.
    /// </param>
    /// <returns>The assembly, if it was loaded.</returns>
    /// <inheritdoc cref="AppDomain.Load(AssemblyName)" path="/exception"/>
    /// <inheritdoc cref="GetAssemblyNameByPolicy(AssemblyName)" path="/exception"/>
    public Assembly? Load(AssemblyName assemblyName)
    {
        try
        {
            AssemblyName? redirectedAssemblyName = this.GetAssemblyNameByPolicy(assemblyName);
            if (redirectedAssemblyName is { CodeBase: not null })
            {
                return Assembly.LoadFrom(redirectedAssemblyName.CodeBase);
            }

            if (assemblyName.CodeBase is not null && this.FileExists(assemblyName.CodeBase))
            {
                return Assembly.LoadFrom(assemblyName.CodeBase);
            }

            if (this.SearchInFallbackTable(redirectedAssemblyName, assemblyName) is { CodeBase: not null } fallbackAssemblyNameWithCodebase)
            {
                return Assembly.LoadFrom(fallbackAssemblyNameWithCodebase.CodeBase);
            }

            return null;
        }
        catch (FileNotFoundException)
        {
            return null;
        }
    }
#else
    /// <summary>
    /// Loads the given assembly into the current AppDomain or appropriate AssemblyLoadContext.
    /// </summary>
    /// <param name="assemblyName">
    /// The name of the assembly to load.
    /// If a <see cref="AssemblyName.CodeBase"/> property is provided, that will be used as a fallback after all other attempts to load the assembly have failed.
    /// </param>
    /// <returns>The assembly, if it was loaded.</returns>
    public Assembly? Load(AssemblyName assemblyName)
    {
        throw new NotSupportedException("This is a reference assembly and not meant for execution.");
    }
#endif

#if NETCOREAPP
    /// <inheritdoc cref="HookupResolver(AssemblyLoadContext, bool)"/>
    public void HookupResolver(AssemblyLoadContext loadContext) => this.HookupResolver(loadContext, blockMoreResolvers: false);

    /// <summary>
    /// Adds an <see cref="AssemblyLoadContext.Resolving"/> event handler
    /// that will assist in finding and loading assemblies based on the rules in the configuration file this instance was initialized with.
    /// </summary>
    /// <param name="loadContext">The load context to add a handler to.</param>
    /// <param name="blockMoreResolvers"><see langword="true"/> to block other <see cref="AssemblyLoadContext.Resolving"/> event handlers from being effectively added.</param>
    public void HookupResolver(AssemblyLoadContext loadContext, bool blockMoreResolvers)
    {
        if (loadContext is null)
        {
            throw new ArgumentNullException(nameof(loadContext));
        }

        loadContext.Resolving += (s, assemblyName) =>
        {
            Assembly? assembly = this.Load(assemblyName);
            if (assembly is not null)
            {
                return assembly;
            }

            // Try to fallback to 'nearby' assemblies that are in the same directory as the assembly that is making the request.
            // This emulates .NET Framework behavior for assemblies in the LoadFrom context, although this logic
            // doesn't discriminate on which context the assembly was loaded from.
            if (s is VSAssemblyLoadContext { FallbackDirectorySearchPath: not null } customAlc)
            {
                foreach (string extension in AssemblyExtensions)
                {
                    string codebase = Path.Combine(customAlc.FallbackDirectorySearchPath, $"{assemblyName.Name}{extension}");
                    if (File.Exists(codebase))
                    {
                        assembly = this.Load(assemblyName, codebase, emulateLoadFrom: true);
                        if (assembly is not null)
                        {
                            return assembly;
                        }
                    }
                }
            }

            return null;
        };

        if (blockMoreResolvers)
        {
            // Add another handler that just throws. This prevents .NET Core from querying any further resolvers
            // that folks might try to add to the default context.
            loadContext.Resolving += (s, e) => throw new FileNotFoundException($"Assembly '{e}' could not be found.");
        }
    }
#elif NETFRAMEWORK
    /// <summary>
    /// Adds an <see cref="AppDomain.AssemblyResolve"/> event handler
    /// that will assist in finding and loading assemblies based on the rules in the configuration file this instance was initialized with.
    /// </summary>
    public void HookupResolver()
    {
        AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
        {
            AssemblyName? redirectedAssemblyName = this.GetAssemblyNameByPolicy(new AssemblyName(e.Name));
            if (redirectedAssemblyName is { CodeBase: not null } && this.FileExists(redirectedAssemblyName.CodeBase))
            {
                return Assembly.LoadFile(redirectedAssemblyName.CodeBase);
            }

            return null;
        };
    }
#endif

    /// <inheritdoc cref="File.Exists(string)"/>
    protected virtual bool FileExists(string path) => File.Exists(path);

    /// <inheritdoc cref="AssemblyName.GetAssemblyName(string)"/>
    protected virtual AssemblyName GetAssemblyName(string assemblyFile) => AssemblyName.GetAssemblyName(assemblyFile);

    private static bool Equal(Span<byte> buffer1, Span<byte> buffer2)
    {
        if (buffer1.Length != buffer2.Length)
        {
            return false;
        }

        for (int i = 0; i < buffer1.Length; i++)
        {
            if (buffer1[i] != buffer2[i])
            {
                return false;
            }
        }

        return true;
    }

    private AssemblyName? SearchInFallbackTable(AssemblyName? redirectedAssemblyName, AssemblyName originalAssemblyName)
    {
        // Try the fallback path, but only if no codebase was provided.
        if (redirectedAssemblyName is null or { CodeBase: null } && originalAssemblyName is { CodeBase: null, Name: not null })
        {
            AssemblyName assemblyNameToConsider = redirectedAssemblyName ?? originalAssemblyName;
            bool success;
            ImmutableArray<Lazy<AssemblyName?>> list;
            lock (this.syncObject)
            {
                success = this.fallbackLookupPaths.TryGetValue(originalAssemblyName.Name, out list);
            }

            if (success)
            {
                foreach (Lazy<AssemblyName?> lazy in list)
                {
                    if (lazy.Value is not null && AssemblyNameEqualityComparer.Instance.Equals(assemblyNameToConsider, lazy.Value))
                    {
                        // We found a match. Load it.
                        return lazy.Value;
                    }
                }
            }
        }

        return null;
    }

#if NETCOREAPP
    private Assembly? LoadOrLoadFrom(AssemblyName assemblyName, string? loadFromAssemblyPath)
    {
        bool emulateLoadFrom = loadFromAssemblyPath is not null;
        try
        {
            AssemblyName? redirectedAssemblyName = this.GetAssemblyNameByPolicy(assemblyName);
            if (redirectedAssemblyName is { CodeBase: not null })
            {
                return this.Load(redirectedAssemblyName, redirectedAssemblyName.CodeBase, emulateLoadFrom);
            }

            if (assemblyName.CodeBase is not null && this.FileExists(assemblyName.CodeBase))
            {
                return this.Load(assemblyName, assemblyName.CodeBase, emulateLoadFrom);
            }

            if (loadFromAssemblyPath is not null)
            {
                return this.Load(redirectedAssemblyName ?? assemblyName, loadFromAssemblyPath, emulateLoadFrom);
            }

            if (this.SearchInFallbackTable(redirectedAssemblyName, assemblyName) is { CodeBase: not null } fallbackAssemblyNameWithCodebase)
            {
                return this.Load(fallbackAssemblyNameWithCodebase, fallbackAssemblyNameWithCodebase.CodeBase, emulateLoadFrom: true);
            }

            return null;
        }
        catch (FileNotFoundException)
        {
            return null;
        }
    }

    /// <summary>
    /// Loads the given assembly into the appropriate <see cref="AssemblyLoadContext"/>.
    /// </summary>
    /// <param name="assemblyName">The name of the assembly to load. This is used to look up or create the per-assembly <see cref="AssemblyLoadContext"/> to load it into. All binding redirects should have already been applied.</param>
    /// <param name="codebase">The path to load the assembly from.</param>
    /// <param name="emulateLoadFrom"><see langword="true" /> to emulate <see cref="Assembly.LoadFrom(string)"/> behavior.</param>
    /// <returns>The assembly, if it was loaded.</returns>
    /// <inheritdoc cref="AssemblyLoadContext.LoadFromAssemblyPath(string)" path="/exception"/>
    private Assembly? Load(AssemblyName assemblyName, string codebase, bool emulateLoadFrom)
    {
        VSAssemblyLoadContext? loadContext;
        lock (this.syncObject)
        {
            if (!this.loadContextsByAssemblyName.TryGetValue(assemblyName, out loadContext))
            {
                string? fallbackDirectorySearchPath = emulateLoadFrom ? Path.GetDirectoryName(codebase) : null;
                loadContext = new VSAssemblyLoadContext(this, assemblyName, fallbackDirectorySearchPath);
                this.HookupResolver(loadContext, blockMoreResolvers: true);
                this.loadContextsByAssemblyName.Add(assemblyName, loadContext);
            }
            else if (emulateLoadFrom && loadContext.FallbackDirectorySearchPath is null)
            {
                // We won't fully emulate LoadFrom context (which would load the assembly *again*),
                // but we will at least activate the LoadFrom behavior that is to allow that assembly
                // to trigger resolving referenced assemblies from its same directory.
                loadContext.FallbackDirectorySearchPath = Path.GetDirectoryName(codebase);
            }
        }

        return loadContext.LoadFromAssemblyPath(codebase);
    }
#endif

    private readonly struct AssemblyLoadRules
    {
        private readonly ImmutableList<BindingRedirect>? bindingRedirects;

        private readonly ImmutableDictionary<Version, string>? codeBasePaths;

        internal AssemblyLoadRules(ImmutableList<BindingRedirect>? bindingRedirects, ImmutableDictionary<Version, string>? codebasePaths)
        {
            this.bindingRedirects = bindingRedirects;
            this.codeBasePaths = codebasePaths;
        }

        internal readonly ImmutableList<BindingRedirect> BindingRedirects => this.bindingRedirects ?? ImmutableList<BindingRedirect>.Empty;

        internal readonly ImmutableDictionary<Version, string> CodeBasePaths => this.codeBasePaths ?? ImmutableDictionary<Version, string>.Empty;

        internal readonly void TryGetMatch(Version desiredAssemblyVersion, out Version matchingAssemblyVersion, out string? assemblyFile)
        {
            matchingAssemblyVersion = desiredAssemblyVersion;

            // Search for matching binding redirect first.
            foreach (BindingRedirect redirect in this.BindingRedirects)
            {
                if (redirect.Contains(desiredAssemblyVersion))
                {
                    matchingAssemblyVersion = redirect.NewVersion;
                    break;
                }
            }

            this.CodeBasePaths.TryGetValue(matchingAssemblyVersion, out assemblyFile);
        }
    }

    [DebuggerDisplay("{" + nameof(DebuggerDisplay) + ",nq}")]
    private readonly struct BindingRedirect : IEquatable<BindingRedirect>
    {
#if NETSTANDARD2_0 || NETFRAMEWORK
        private static readonly char[] HyphenArray = ['-'];
#endif

        internal BindingRedirect(string oldVersion, string newVersion)
        {
#if NETSTANDARD2_0 || NETFRAMEWORK
            string[] oldVersions = oldVersion.Split(HyphenArray);
#else
            string[] oldVersions = oldVersion.Split('-', 2);
#endif
            this.OldVersion = oldVersions.Length switch
            {
                1 => (Version.Parse(oldVersions[0]), Version.Parse(oldVersions[0])),
                2 => (Version.Parse(oldVersions[0]), Version.Parse(oldVersions[1])),
                _ => throw new ArgumentException($"Value \"{oldVersion}\" is not a single version nor a version range.", nameof(oldVersion)),
            };

            this.NewVersion = Version.Parse(newVersion);
        }

        internal (Version Start, Version End) OldVersion { get; }

        internal Version NewVersion { get; }

        private readonly string DebuggerDisplay => $"{this.OldVersion.Start}-{this.OldVersion.End} -> {this.NewVersion}";

        public readonly bool Equals(BindingRedirect other) => this.OldVersion.Equals(other.OldVersion) && this.NewVersion == other.NewVersion;

        internal readonly bool Contains(Version version) => version >= this.OldVersion.Start && version <= this.OldVersion.End;
    }

    [DebuggerDisplay("{" + nameof(Name) + ",nq}")]
    private readonly struct AssemblySimpleName : IEquatable<AssemblySimpleName>
    {
        internal AssemblySimpleName(string name, string publicKeyToken)
        {
            this.Name = name;
            this.PublicKeyToken = publicKeyToken is null ? default : ConvertHexStringToByteArray(publicKeyToken);
        }

        internal AssemblySimpleName(string name, Memory<byte> publicKeyToken)
        {
            this.Name = name;
            this.PublicKeyToken = publicKeyToken;
        }

        internal string Name { get; }

        internal Memory<byte> PublicKeyToken { get; }

        public readonly override bool Equals(object? obj) => obj is AssemblySimpleName other && this.Equals(other);

        public readonly bool Equals(AssemblySimpleName other) => this.Name == other.Name && Equal(this.PublicKeyToken.Span, other.PublicKeyToken.Span);

        public readonly override int GetHashCode() => HashCode.Combine(this.Name, this.PublicKeyToken.Length > 0 ? this.PublicKeyToken.Span[0] : 0);

        private static byte[] ConvertHexStringToByteArray(string hex)
        {
            if (hex.Length % 2 == 1)
            {
                throw new ArgumentException("Hex must have an even number of characters.", nameof(hex));
            }

            byte[] arr = new byte[hex.Length >> 1];
            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + GetHexVal(hex[(i << 1) + 1]));
            }

            return arr;

            static int GetHexVal(char hex)
            {
                int val = (int)hex;
                return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
            }
        }
    }

    private class AssemblyNameEqualityComparer : IEqualityComparer<AssemblyName>
    {
        internal static readonly IEqualityComparer<AssemblyName> Instance = new AssemblyNameEqualityComparer();

        private AssemblyNameEqualityComparer()
        {
        }

        public bool Equals(AssemblyName? x, AssemblyName? y)
        {
            if (ReferenceEquals(x, y))
            {
                return true;
            }

            if (x is null || y is null)
            {
                return false;
            }

            return string.Equals(x.Name, y.Name, StringComparison.OrdinalIgnoreCase)
                && x.Version == y.Version
                && x.CultureName == y.CultureName
                && Equal(x.GetPublicKeyToken(), y.GetPublicKeyToken());
        }

        public int GetHashCode(AssemblyName? obj) => StringComparer.OrdinalIgnoreCase.GetHashCode(obj?.Name ?? string.Empty);

        private static bool Equal(byte[]? a, byte[]? b)
        {
            if (ReferenceEquals(a, b))
            {
                return true;
            }

            if (a is null || b is null)
            {
                return false;
            }

            if (a.Length != b.Length)
            {
                return false;
            }

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }

            return true;
        }
    }

#if NETCOREAPP
    /// <summary>
    /// The <see cref="AssemblyLoadContext"/> to use for all contexts created by <see cref="Load(AssemblyName, string, bool)"/>.
    /// </summary>
    [DebuggerDisplay("{" + nameof(DebuggerDisplay) + ",nq}")]
    private class VSAssemblyLoadContext : AssemblyLoadContext
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VSAssemblyLoadContext"/> class.
        /// </summary>
        /// <param name="owner">The creator of this instance.</param>
        /// <param name="mainAssemblyName">The single assembly meant to be stored in this assembly load context.</param>
        /// <param name="fallbackDirectorySearchPath">The path to search for assemblies requested by the assembly named in <paramref name="mainAssemblyName"/> in case they cannot be found another way.</param>
        internal VSAssemblyLoadContext(NetFrameworkAssemblyResolver owner, AssemblyName mainAssemblyName, string? fallbackDirectorySearchPath)
            : base(mainAssemblyName.FullName)
        {
            this.Loader = owner;
            this.FallbackDirectorySearchPath = fallbackDirectorySearchPath;
        }

        /// <summary>
        /// Gets the assembly loader used by this <see cref="AssemblyLoadContext"/>.
        /// </summary>
        internal NetFrameworkAssemblyResolver Loader { get; }

        /// <summary>
        /// Gets or sets the path to search for assemblies requested by the assembly loaded into this context.
        /// </summary>
        internal string? FallbackDirectorySearchPath { get; set; }

        private string DebuggerDisplay => this.Name ?? "(no name)";
    }
#endif
}

#endif
