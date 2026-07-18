// Command muninweb is the small HTTP face munin lacks. Munin is a
// cron job that renders a static site plus a perl CGI that draws
// graphs on demand; the web tier's model is "apps are HTTP backends
// behind nginx auth_request". muninweb closes that gap: it serves the
// cron-rendered htmldir and executes munin-cgi-graph, on loopback,
// as the munin user. All authentication lives in nginx; this process
// must never be reachable from outside the box.
package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/cgi"
	"os"
	"time"
)

// handler routes graph requests to the munin CGI and everything else
// to the static site. The nginx mount strips its own prefix, so the
// paths here match munin.conf's cgiurl_graph suffix.
func handler(wwwDir, cgiBin string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/cgi-graph/", &cgi.Handler{
		Path: cgiBin,
		Root: "/cgi-graph",
	})
	mux.Handle("/", http.FileServer(http.Dir(wwwDir)))
	return mux
}

func main() {
	listen := flag.String("listen", "127.0.0.1:4948", "address to serve on (loopback only; nginx fronts this)")
	www := flag.String("www", "/var/cache/munin/www", "munin htmldir holding the cron-rendered site")
	cgiBin := flag.String("cgi", "/usr/lib/munin/cgi/munin-cgi-graph", "munin graph CGI executable")
	flag.Parse()

	if _, err := os.Stat(*cgiBin); err != nil {
		log.Printf("muninweb: graph CGI not found (%v); graph requests will fail until munin is installed", err)
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           handler(*www, *cgiBin),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("muninweb: serving %s on %s", *www, *listen)
	log.Fatal(srv.ListenAndServe())
}
