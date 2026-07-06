package buildinfo

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func String() string {
	return "mcp-gateway " + Version + " " + Commit + " " + Date
}
