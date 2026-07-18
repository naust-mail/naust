package helper

// Wire protocol for the privileged helper socket.
//
// One request per connection. Request and response are each a single line
// of JSON terminated by '\n'. See .claude/memories/helper-intent-menu.md
// for the intent vocabulary and the invariants every intent must uphold.

// Request names one privileged operation from the fixed intent menu.
type Request struct {
	// Intent is the menu item, e.g. "service.reload".
	Intent string `json:"intent"`
	// Args are the intent's parameters. All values are strings; every
	// intent validates its args against a closed vocabulary. No arg is
	// ever a filesystem path.
	Args map[string]string `json:"args,omitempty"`
}

// Response reports the outcome of one Request.
type Response struct {
	// OK is true when the operation completed successfully.
	OK bool `json:"ok"`
	// Result holds intent output when there is any (host.apt_* command
	// output, shown in the admin panel). Empty for most intents.
	Result string `json:"result,omitempty"`
	// Error holds a human-readable failure reason when OK is false.
	Error string `json:"error,omitempty"`
}
