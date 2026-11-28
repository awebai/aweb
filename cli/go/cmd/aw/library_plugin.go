package main

const (
	libraryPluginName           = "library"
	libraryPluginManifestURL    = "https://library.aweb.ai/.well-known/aweb-app.json"
	libraryPluginInstallCommand = "aw plugin install " + libraryPluginManifestURL
)

func missingLibraryPluginCommandError() error {
	return usageError("The aw Library plugin is not installed. Install it with:\n    %s", libraryPluginInstallCommand)
}
