// Using the default instance of ServeMux:
package main

import (
	"github.com/kataras/go-servemux"
	"net/http"
)

func main() {

	servemux.Handle(http.MethodGet, "/hi", http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("hi"))
	}))("my route") // give an optional name here

	// println(servemux.Lookup("my route").Path), prints /hi

	servemux.HandleFunc(http.MethodGet, "/hi_func", func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("hi func"))
	})

	// servemux.Get
	// servemux.Post
	// servemux.Put
	// servemux.Trace
	// servemux.Patch
	// servemux.Delete
	// servemux.Head
	// servemux.Connect

	servemux.Get("/hello/:username", http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

		println("middleware1 served")

		username := req.Context().Value("username").(string)

		// check for the shake of the example we say if no /hello/kataras then return a StatusUnauthorized error to the client and cancel the next handler(s)
		// else continue to the next handler(s)
		if username != "kataras" {
			http.Error(res, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			servemux.Cancel(req.Context())
		}

	}), http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		username := req.Context().Value("username").(string)
		res.Write([]byte("Hello " + username))
	}))

	println("Server is running at http://localhost:8080")
	servemux.ListenAndServe("localhost:8080")
	// or http.ListenAndServe("localhost:8080", servemux)
}
