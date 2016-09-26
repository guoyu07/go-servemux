// Using more than one instance of ServeMux:
package main

import (
	"github.com/kataras/go-servemux"
	"net/http"
)

func main() {
	mux := servemux.New()

	mux.Handle(http.MethodGet, "/hi", http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("hi"))
	}))("my route") // give an optional name here

	// println(mux.Lookup("my route").Path), prints /hi

	mux.HandleFunc(http.MethodGet, "/hi_func", func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("hi func"))
	})

	// mux.Get
	// mux.Post
	// mux.Put
	// mux.Trace
	// mux.Patch
	// mux.Delete
	// mux.Head
	// mux.Connect

	mux.Get("/hi", http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("hi"))
	}))

	mux.Get("/hello/:username", http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		println("middleware1 served")

		// check for the shake of the example we say if no /hello/kataras then return a StatusUnauthorized error to the client and cancel the next handler(s)
		// else continue to the next handler(s)
		if req.Context().Value("username").(string) != "kataras" {
			http.Error(res, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			mux.Cancel(req.Context())
		}

	}), http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		username := req.Context().Value("username").(string)
		res.Write([]byte("Hello " + username))
	}))

	println("Server is running at http://localhost:8080")
	http.ListenAndServe("localhost:8080", mux)
}
