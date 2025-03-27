// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma warning disable SYSLIB0044 // AssemblyName.CodeBase is obsolete

#if NETCOREAPP || NET472

// Copyright (c) Microsoft Corporation. All rights reserved.
using System.Reflection;
using System.Runtime.InteropServices;
#if NETCOREAPP
using System.Runtime.Loader;
#endif
using Nerdbank.NetStandardBridge;

public class NetFrameworkAssemblyResolverTests
{
    private static readonly string TestBaseDir = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? @"q:\doesnotexist" : "/doesnotexist";
    private readonly TestableAssemblyLoader loader;

    public NetFrameworkAssemblyResolverTests()
    {
        string testBinDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
        string configLocation = Path.Combine(testBinDir, "devenv.exe.config");
        this.loader = new TestableAssemblyLoader(configLocation, TestBaseDir);
    }

    private static AssemblyName ValidationAssemblyName => new($"Validation, Version=2.5.0.0, Culture=neutral, PublicKeyToken=2fc06f0d701809a7");

    private static AssemblyName NonExistingAssemblyName => new($"NonExisting, Version=2.5.0.0, Culture=neutral, PublicKeyToken=2fc06f0d701809a7");

    [Fact]
    public void Ctor_ValidatesInputs()
    {
        Assert.Throws<ArgumentException>("configFile", () => new NetFrameworkAssemblyResolver(null!));
    }

    [Fact]
    public void BaseDir()
    {
        Assert.Equal(TestBaseDir, this.loader.BaseDir);
    }

    [Fact]
    public void ProbingPathsAreNotEmpty()
    {
        Assert.NotEmpty(this.loader.ProbingPaths);
    }

    [Fact]
    public void ProbingPathsAreRelative()
    {
#if NETFRAMEWORK
        Assert.All(this.loader.ProbingPaths, path => Assert.False(Path.IsPathRooted(path)));
#else
        Assert.All(this.loader.ProbingPaths, path => Assert.False(Path.IsPathFullyQualified(path)));
#endif
    }

    [Fact]
    public void GetAssemblyPath_NullInput()
    {
        Assert.Throws<ArgumentNullException>(() => this.loader.GetAssemblyNameByPolicy(null!));
    }

    [Fact]
    public void GetAssemblyPath_NullName()
    {
        Assert.Null(this.loader.GetAssemblyNameByPolicy(new AssemblyName()));
    }

    [Fact]
    public void Codebase_NoRedirect()
    {
        this.loader.GetAssemblyNameMock = path => new AssemblyName("NuGet.VisualStudio.Common, Version=5.6.0.2, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
        AssemblyName? redirectedAssemblyName = this.loader.GetAssemblyNameByPolicy(new AssemblyName("NuGet.VisualStudio.Common, Version=5.6.0.2, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"));
        Assert.Equal(Path.Combine(TestBaseDir, @"commonextensions\microsoft\nuget\NuGet.VisualStudio.Common.dll"), redirectedAssemblyName?.CodeBase);
    }

    [Fact]
    public void Codebase_AbsolutePath()
    {
        string simpleAssemblyName = $"Microsoft.VisualStudio.Editor.{(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : "NonWindows")}";
        string fullAssemblyName = $"{simpleAssemblyName}, Version=16.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";
        this.loader.FileExistsMock = path => false;
        AssemblyName? redirectedAssemblyName = this.loader.GetAssemblyNameByPolicy(new AssemblyName(fullAssemblyName));
        string expected = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? @"c:\master\common7\ide\commonextensions\microsoft\editor\Microsoft.VisualStudio.Editor.dll"
            : "/master/common7/ide/commonextensions/microsoft/editor/Microsoft.VisualStudio.Editor.dll";
        Assert.Equal(expected, redirectedAssemblyName?.CodeBase);
    }

    [Fact]
    public void BindingRedirect_BelowSlide()
    {
        this.loader.FileExistsMock = this.loader.FileExistsDenySearch;
        AssemblyName? redirectedAssemblyName = this.loader.GetAssemblyNameByPolicy(new AssemblyName("Microsoft.TemplateEngine.Core, Version=0.1.0.0, Culture=neutral, PublicKeyToken=adb9793829ddae60"));
        Assert.NotNull(redirectedAssemblyName);
        Assert.Null(redirectedAssemblyName!.CodeBase);
    }

    [Fact]
    public void BindingRedirect_AboveSlide()
    {
        this.loader.FileExistsMock = this.loader.FileExistsDenySearch;
        AssemblyName? redirectedAssemblyName = this.loader.GetAssemblyNameByPolicy(new AssemblyName("Microsoft.TemplateEngine.Core, Version=5.1.0.0, Culture=neutral, PublicKeyToken=adb9793829ddae60"));
        Assert.NotNull(redirectedAssemblyName);
        Assert.Null(redirectedAssemblyName!.CodeBase);
    }

    [Fact]
    public void BindingRedirect_BetweenSlides()
    {
        this.loader.FileExistsMock = this.loader.FileExistsDenySearch;
        AssemblyName? redirectedAssemblyName = this.loader.GetAssemblyNameByPolicy(new AssemblyName("Microsoft.IdentityModel.Clients.ActiveDirectory, Version=4.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"));
        Assert.NotNull(redirectedAssemblyName);
        Assert.Null(redirectedAssemblyName!.CodeBase);
    }

    [Fact]
    public void BindingRedirect_SingleSlide()
    {
        var expectedAssemblyName = new AssemblyName("Microsoft.CodeAnalysis.ExternalAccess.Razor, Version=3.6.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
        this.loader.GetAssemblyNameMock = path => expectedAssemblyName;
        AssemblyName? redirectedAssemblyName = this.loader.GetAssemblyNameByPolicy(new AssemblyName("Microsoft.CodeAnalysis.ExternalAccess.Razor, Version=2.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"));
        Assert.Equal(expectedAssemblyName.FullName, redirectedAssemblyName?.FullName);
        Assert.Equal(Path.Combine(TestBaseDir, @"commonextensions\microsoft\managedlanguages\vbcsharp\languageservices\Microsoft.CodeAnalysis.ExternalAccess.Razor.dll"), redirectedAssemblyName?.CodeBase);
    }

    [Fact]
    public void BindingRedirect_DoubleSlide()
    {
        string v3Path = Path.Combine(TestBaseDir, @"PrivateAssemblies\Microsoft.IdentityModel.Clients.ActiveDirectory.dll");
        string v5Path = Path.Combine(TestBaseDir, @"PrivateAssemblies\AdalV5\Microsoft.IdentityModel.Clients.ActiveDirectory.dll");
        this.loader.GetAssemblyNameMock = path =>
            path == v3Path ? new AssemblyName("Microsoft.IdentityModel.Clients.ActiveDirectory, Version=3.19.8.16603, Culture=neutral, PublicKeyToken=31bf3856ad364e35") :
            path == v5Path ? new AssemblyName("Microsoft.IdentityModel.Clients.ActiveDirectory, Version=5.1.1.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35") :
            throw new Exception("Unexpected path: " + path);

        AssemblyName? redirectedAssemblyName = this.loader.GetAssemblyNameByPolicy(new AssemblyName("Microsoft.IdentityModel.Clients.ActiveDirectory, Version=3.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"));
        Assert.Equal(v3Path, redirectedAssemblyName?.CodeBase);

        redirectedAssemblyName = this.loader.GetAssemblyNameByPolicy(new AssemblyName("Microsoft.IdentityModel.Clients.ActiveDirectory, Version=5.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"));
        Assert.Equal(v5Path, redirectedAssemblyName?.CodeBase);
    }

    [Fact]
    public void NoMatch_NotStrongNamed()
    {
        this.loader.FileExistsMock = path => false;
        Assert.Null(this.loader.GetAssemblyNameByPolicy(new AssemblyName("NonExistentSimpleName")));
    }

    [Fact]
    public void NoMatch_StrongNamed()
    {
        this.loader.FileExistsMock = path => false;
        AssemblyName? redirectedAssemblyName = this.loader.GetAssemblyNameByPolicy(new AssemblyName("NonExistentSimpleName, Version=3.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"));
        Assert.NotNull(redirectedAssemblyName);
        Assert.Null(redirectedAssemblyName!.CodeBase);
    }

    [Fact]
    public void SearchForDll_BaseDir()
    {
        string madeUpName = "someassembly";
        string expectedPath = Path.Combine(TestBaseDir, madeUpName + ".dll");
        var assemblyName = new AssemblyName($"{madeUpName}, Version=3.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
        this.loader.FileExistsMock = path =>
        {
            Assert.Equal(expectedPath, path);
            return true;
        };
        this.loader.GetAssemblyNameMock = path => assemblyName;
        Assert.Equal(expectedPath, this.loader.GetAssemblyNameByPolicy(assemblyName)?.CodeBase);
    }

    [Fact]
    public void SearchForDll_ProbingPath()
    {
        string madeUpName = "someassembly";
        string expectedPath = Path.Combine(TestBaseDir, @"PrivateAssemblies\DataCollectors", madeUpName + ".dll");
        var assemblyName = new AssemblyName($"{madeUpName}, Version=3.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
        this.loader.FileExistsMock = path => expectedPath == path;
        this.loader.GetAssemblyNameMock = path => assemblyName;
        Assert.Equal(expectedPath, this.loader.GetAssemblyNameByPolicy(assemblyName)?.CodeBase);
    }

    [Fact]
    public void SearchForDll_ProbingPath_MismatchVersion()
    {
        string madeUpName = "someassembly";
        string expectedPath = Path.Combine(TestBaseDir, @"PrivateAssemblies\DataCollectors", madeUpName + ".dll");
        var assemblyName = new AssemblyName($"{madeUpName}, Version=3.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
        this.loader.FileExistsMock = path => expectedPath == path;
        this.loader.GetAssemblyNameMock = path => new AssemblyName($"{madeUpName}, Version=3.2.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
        Assert.Throws<InvalidOperationException>(() => this.loader.GetAssemblyNameByPolicy(assemblyName));
    }

    [Fact]
    public void FileExists_DefaultImpl()
    {
        Assert.True(this.loader.BaseFileExists(Assembly.GetExecutingAssembly().Location));
        Assert.False(this.loader.BaseFileExists(Assembly.GetExecutingAssembly().Location + ".notexist"));
    }

    [Fact]
    public void Load()
    {
#if NETFRAMEWORK
        AppDomain appDomain = AppDomain.CreateDomain("test");
        try
        {
            var helper = (AppDomainHelper)appDomain.CreateInstanceFromAndUnwrap(this.GetType().Assembly.CodeBase, typeof(AppDomainHelper).FullName);
            Assert.True(helper.TryLoadAssembly());
        }
        finally
        {
            AppDomain.Unload(appDomain);
        }
#else
        AssemblyLoadContext alc = new("test");
        NetFrameworkAssemblyResolver loader = new("Unreachable.config");
        Assert.Throws<FileNotFoundException>(() => alc.LoadFromAssemblyName(ValidationAssemblyName));
        Assembly? validationAssembly = loader.Load(ValidationAssemblyName);
        Assert.NotNull(validationAssembly);
#endif
    }

    [Fact]
    public void HookupResolver()
    {
#if NETFRAMEWORK
        AppDomain appDomain = AppDomain.CreateDomain("test");
        try
        {
            var helper = (AppDomainHelper)appDomain.CreateInstanceFromAndUnwrap(this.GetType().Assembly.CodeBase, typeof(AppDomainHelper).FullName);
            Assert.Throws<FileNotFoundException>(() => appDomain.Load(ValidationAssemblyName));
            Assert.True(helper.TryLoadAssemblyWithHookup());
        }
        finally
        {
            AppDomain.Unload(appDomain);
        }
#else
        AssemblyLoadContext alc = new("test");
        NetFrameworkAssemblyResolver loader = new("Unreachable.config");
        Assert.Throws<FileNotFoundException>(() => alc.LoadFromAssemblyName(ValidationAssemblyName));
        loader.HookupResolver(alc);
        Assembly? validationAssembly = alc.LoadFromAssemblyName(ValidationAssemblyName);
        Assert.NotNull(validationAssembly);
#endif
    }

    [Fact]
    public void ProvideAssemblyPath_NoThrowOnNonExistentPath()
    {
        this.loader.ProvideAssemblyPath("no good path");
        this.loader.ProvideAssemblyPath(Path.Combine(Environment.CurrentDirectory, "nonexistent.dll"));
        Assert.Null(this.loader.Load(new AssemblyName("nonexistent")));
    }

    [Fact]
    public void ProvideAssemblyPath_PathMultipleTimes()
    {
        this.loader.ProvideAssemblyPath("no good path");
        this.loader.ProvideAssemblyPath(Path.Combine(Environment.CurrentDirectory, "nonexistent.dll"));
        this.loader.ProvideAssemblyPath(Path.Combine(Environment.CurrentDirectory, "nonexistent.dll"));
    }

#if NETFRAMEWORK
    private class AppDomainHelper : MarshalByRefObject
    {
        internal bool TryLoadAssembly()
        {
            NetFrameworkAssemblyResolver loader = new("Unreachable.config");
            Assert.Throws<FileNotFoundException>(() => Assembly.Load(ValidationAssemblyName));
            Assembly? validationAssembly = loader.Load(ValidationAssemblyName);
            return validationAssembly is not null;
        }

        internal bool TryLoadAssemblyWithHookup()
        {
            NetFrameworkAssemblyResolver loader = new("Unreachable.config");
            Assert.Throws<FileNotFoundException>(() => Assembly.Load(ValidationAssemblyName));
            loader.HookupResolver();
            Assert.Throws<FileNotFoundException>(() => Assembly.Load(NonExistingAssemblyName));
            Assembly? validationAssembly = Assembly.Load(ValidationAssemblyName);
            return validationAssembly is not null;
        }
    }
#endif

    private class TestableAssemblyLoader : NetFrameworkAssemblyResolver
    {
        public TestableAssemblyLoader(string configFile, string? baseDir)
            : base(configFile, baseDir)
        {
        }

        internal new IReadOnlyList<string> ProbingPaths => base.ProbingPaths;

        internal new string BaseDir => base.BaseDir;

        internal Func<string, bool> FileExistsMock { get; set; } = path => true;

        internal Func<string, AssemblyName> GetAssemblyNameMock { get; set; } = path => throw new NotImplementedException();

        /// <summary>
        /// Fakes a file existence check, where the file is considered to exist if and only if
        /// it is <em>not</em> in the base directory or any of the probing paths.
        /// </summary>
        internal bool FileExistsDenySearch(string path) => path != Path.Combine(TestBaseDir, Path.GetFileName(path)) && !this.ProbingPaths.Any(probingDir => path.StartsWith(Path.Combine(TestBaseDir, probingDir), StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// Implements a real file-existence check.
        /// </summary>
        internal bool BaseFileExists(string path) => base.FileExists(path);

        internal AssemblyName BaseGetAssemblyName(string assemblyFile) => base.GetAssemblyName(assemblyFile);

        protected override bool FileExists(string path) => this.FileExistsMock(path);

        protected override AssemblyName GetAssemblyName(string assemblyFile) => this.GetAssemblyNameMock(assemblyFile);
    }
}

#endif
