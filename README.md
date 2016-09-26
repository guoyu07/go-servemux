<p align="center">
  <img src="/logo.jpg" height="400">
  <br/>

 <a href="https://travis-ci.org/kataras/go-servemux"><img src="https://img.shields.io/travis/kataras/go-servemux.svg?style=flat-square" alt="Build Status"></a>


 <a href="https://github.com/avelino/awesome-go"><img src="https://img.shields.io/badge/awesome-%E2%9C%93-ff69b4.svg?style=flat-square" alt="Awesome GoLang"></a>

 <a href="http://goreportcard.com/report/kataras/go-servemux"><img src="https://img.shields.io/badge/-A%2B-F44336.svg?style=flat-square" alt="Report A+"></a>


 <a href="https://github.com/kataras/go-servemux/blob/master/LICENSE"><img src="https://img.shields.io/badge/%20license-MIT%20-E91E63.svg?style=flat-square" alt="License"></a>



 <a href="https://github.com/kataras/go-servemux/releases"><img src="https://img.shields.io/badge/%20release%20-%200.0.1-blue.svg?style=flat-square" alt="Releases"></a>

 <a href="https://godoc.org/github.com/kataras/go-servemux"><img src="https://img.shields.io/badge/%20docs-reference-5272B4.svg?style=flat-square" alt="godocs"></a>

 <a href="https://kataras.rocket.chat/channel/go-servemux"><img src="https://img.shields.io/badge/%20community-chat-00BCD4.svg?style=flat-square" alt="Chat"></a>

<br/><br/>

Fast and elegant <b>go1.7</b> Router, takes advantage of the new `context` package.

</p>



```go
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
    correctUsername := true // logic here

		if !correctUsername {
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

```

`New() *ServeMux  // New returns a new, empty, ServeMux`


```go
import (
	"github.com/kataras/go-servemux"
	"net/http"
)

mux := servemux.New()

mux.Handle(http.MethodGet, "/hi", http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
  res.Write([]byte("hi"))
}))("my route") // give an optional name here

// println(mux.Lookup("my route").Path), prints /hi

mux.HandleFunc(http.MethodGet, "/hi_func", func(res http.ResponseWriter, req *http.Request) {
  res.Write([]byte("hi func"))
})
//...
```

Installation
------------

The only requirement is the [Go Programming Language](https://golang.org/dl).

```bash
$ go get -u github.com/kataras/go-servemux
```

Features
------------
- Focus on high performance
- Robust routing
- Middleware
      `servemux.Handle("GET", "/hi", middleware1, handler, middleware2)` or `servemux.Use(middleware1); servemux.Handle("GET", "/hi", handler); servemux.Done(middleware2)`
- Named routes
      `servemux.Get(...)("myroute"))` with `servemux.Lookup("myroute").Path`
- Group of routes
      `g := servemux.Party(...)`
- Subdomains
      `d := servemux.Party("mysubdomain.")`
- What's next? `Don't worry, I cover you`

<img src="https://raw.githubusercontent.com/iris-contrib/website/gh-pages/assets/arrowdown.png" width="72"/>


| Name        | Description           
| ------------------|:---------------------:|
| [Hot Reload ](https://github.com/kataras/rizla)  | Builds, runs and monitors your app with ease |
| [Static Files ](https://github.com/kataras/go-fs)  | Common static file handlers |
| [Templates ](https://github.com/kataras/go-template)  | AIO Template Engine |
| [Sessions ](https://github.com/kataras/go-sessions)  | The fastest session manager |
| [Websocket ](https://github.com/kataras/go-websocket)  | socket.io like websocket server & client |
| [Rich Responses ](https://github.com/kataras/go-serializer)  | HTML, Markdown, JSON, JSONP, XML, Text |


FAQ
------------

Explore [these questions](https://github.com/kataras/go-servemux/issues?go-servemux=label%3Aquestion) or navigate to the [community chat][Chat].

Versioning
------------

Current: v0.0.1

Read more about Semantic Versioning 2.0.0

 - http://semver.org/
 - https://en.wikipedia.org/wiki/Software_versioning
 - https://wiki.debian.org/UpstreamGuide#Releases_and_Versions

People
------------

The author of go-servemux is [@kataras](https://github.com/kataras).

If you're **willing to donate**, feel **free** to send **any** amount through paypal

[![](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=kataras2006%40hotmail%2ecom&lc=GR&item_name=Iris%20web%20framework&item_number=iriswebframeworkdonationid2016&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted)


Contributing
------------

If you are interested in contributing to the go-servemux project, please make a PR.

License
------------

This project is licensed under the MIT License.

License can be found [here](LICENSE).

[Chat Widget]: https://img.shields.io/badge/community-chat-00BCD4.svg?style=flat-square
[Chat]: https://kataras.rocket.chat/channel/go-servemux
