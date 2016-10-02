// Package servemux provides fast net/http routing with named routes and named path parameters, takes advantage the golang 1.7 context
package servemux

import (
	"bytes"
	"context"
	"fmt"
	"github.com/kataras/go-errors"
	"io"
	"net/http"
	"strings"
	"sync"
)

const (
	// Version is the current version of the servemux package
	Version = "0.0.2"
)

var (
	// Default the default servemux instance
	Default *ServeMux
	// Errors the default servemux's error handlers, shortcut of: Default.Errors
	Errors map[int]http.Handler
)

func init() {
	Default = New()
	Errors = Default.Errors
}

// ListenAndServe listens on the TCP network address addr
// and then calls Serve with handler to handle requests
// on incoming connections.
// Accepted connections are configured to enable TCP keep-alives.
// Handler is the Default ServeMux.
//
// A trivial example server is:
//
//	package main
//
//	import (
//		"io"
//		"net/http"
//		"log"
// 	  "github.com/kataras/go-servemux"
//	)
//
//	// hello world, the web server
//	func HelloServer(w http.ResponseWriter, req *http.Request) {
//		io.WriteString(w, fmt.Sprintf("hello, %s!\n", req.Context().Value("name"))
//	}
//
//	func main() {
//		servemux.HandleFunc("/hello/:name", HelloServer)
//		log.Fatal(servemux.ListenAndServe(":12345"))
//	}
//
// ListenAndServe always returns a non-nil error.
func ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, Default)
}

// -------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------
// ------------------------- golang 1.7 context, keeps parameters-----------------------
// -------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------

type requestValue struct {
	key   []byte
	value interface{}
}

type requestValues []requestValue

// String returns a string implementation of all parameters that this values object keeps
// hasthe form of key1=value1,key2=value2... only string values are printed.
func (r *requestValues) String() string {
	var buff bytes.Buffer
	args := *r
	for i := range args {
		if v, isString := args[i].value.(string); isString {
			buff.WriteString(string(args[i].key))
			buff.WriteString("=")
			buff.WriteString(v)
			if i < len(args)-1 {
				buff.WriteString(",")
			}
		}

	}
	return buff.String()
}

func (r *requestValues) Set(key string, value interface{}) {
	args := *r
	n := len(args)
	for i := 0; i < n; i++ {
		kv := &args[i]
		if string(kv.key) == key {
			kv.value = value
			return
		}
	}

	c := cap(args)
	if c > n {
		args = args[:n+1]
		kv := &args[n]
		kv.key = append(kv.key[:0], key...)
		kv.value = value
		*r = args
		return
	}

	kv := requestValue{}
	kv.key = append(kv.key[:0], key...)
	kv.value = value
	*r = append(args, kv)
}

func (r *requestValues) Get(key string) interface{} {
	args := *r
	n := len(args)
	for i := 0; i < n; i++ {
		kv := &args[i]
		if string(kv.key) == key {
			return kv.value
		}
	}
	return nil
}

const (
	cancelKey   = "req_cancel"
	canceledKey = "req_canceled"
)

func (r *requestValues) Reset() {
	*r = (*r)[:0]
	r.Set(cancelKey, func() {
		r.Set(canceledKey, true)
	})
}

// A paramsCtx carries a key-value pair. It implements Value for that key and
// delegates all other calls to the embedded Context.
type paramsCtx struct {
	context.Context
	params requestValues
}

// Canceled returns true if the request has been canceled
func (ctx *paramsCtx) Canceled() bool {
	if v, isB := ctx.params.Get(canceledKey).(bool); isB {
		return v
	}
	return false
}

func (ctx *paramsCtx) String() string {
	return fmt.Sprintf("%v.WithParams(%#v)", ctx.Context, ctx.params)
}

func (ctx *paramsCtx) Value(key interface{}) interface{} {
	if k, isString := key.(string); isString {
		v := ctx.params.Get(k)
		if v != nil {
			return v
		}
	}

	// return any parent value if not found here
	return ctx.Context.Value(key)
}

// Handlers is a slice of http.Handler
type Handlers []http.Handler

// -------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------
// ------------------------- BSD-like trie using golang 1.7context----------------------
// -------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------

const (
	// parameterStartByte is very used on the node, it's just contains the byte for the ':' rune/char
	parameterStartByte = byte(':')
	// slashByte is just a byte of '/' rune/char
	slashByte = byte('/')
	// slash is just a string of "/"
	slash = "/"
	// matchEverythingByte is just a byte of '*" rune/char
	matchEverythingByte = byte('*')

	isStatic entryCase = iota
	isRoot
	hasParams
	matchEverything
)

type (

	// entryCase is the type which the type of muxEntryusing in order to determinate what type (parameterized, anything, static...) is the perticular node
	entryCase uint8

	// muxEntry is the node of a tree of the routes,
	// in order to learn how this is working, google 'trie' or watch this lecture: https://www.youtube.com/watch?v=uhAUk63tLRM
	// this method is used by the BSD's kernel also
	muxEntry struct {
		part        string
		entryCase   entryCase
		hasWildNode bool
		tokens      string
		nodes       []*muxEntry
		handlers    Handlers
		precedence  uint64
		paramsLen   uint8
	}
)

var (
	errMuxEntryConflictsWildcard         = errors.New("Router: Path's part: '%s' conflicts with wildcard '%s' in the route path: '%s' !")
	errMuxEntryhandlersAlreadyExists     = errors.New("Router: handlers were already registered for the path: '%s' !")
	errMuxEntryInvalidWildcard           = errors.New("Router: More than one wildcard found in the path part: '%s' in route's path: '%s' !")
	errMuxEntryConflictsExistingWildcard = errors.New("Router: Wildcard for route path: '%s' conflicts with existing children in route path: '%s' !")
	errMuxEntryWildcardUnnamed           = errors.New("Router: Unnamed wildcard found in path: '%s' !")
	errMuxEntryWildcardInvalidPlace      = errors.New("Router: Wildcard is only allowed at the end of the path, in the route path: '%s' !")
	errMuxEntryWildcardConflictshandlers = errors.New("Router: Wildcard  conflicts with existing handlers for the route path: '%s' !")
	errMuxEntryWildcardMissingSlash      = errors.New("Router: No slash(/) were found before wildcard in the route path: '%s' !")
)

// getParamsLen returns the parameters length from a given path
func getParamsLen(path string) uint8 {
	var n uint
	for i := 0; i < len(path); i++ {
		if path[i] != parameterStartByte && path[i] != matchEverythingByte {
			continue
		}
		n++
	}
	if n >= 255 {
		return 255
	}
	return uint8(n)
}

// findLower returns the smaller number between a and b
func findLower(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

// add adds a muxEntry to the existing muxEntry or to the tree if no muxEntry has the prefix of
func (e *muxEntry) add(path string, handlers Handlers) error {
	fullPath := path
	e.precedence++
	numParams := getParamsLen(path)

	if len(e.part) > 0 || len(e.nodes) > 0 {
	loop:
		for {
			if numParams > e.paramsLen {
				e.paramsLen = numParams
			}

			i := 0
			max := findLower(len(path), len(e.part))
			for i < max && path[i] == e.part[i] {
				i++
			}

			if i < len(e.part) {
				node := muxEntry{
					part:        e.part[i:],
					hasWildNode: e.hasWildNode,
					tokens:      e.tokens,
					nodes:       e.nodes,
					handlers:    e.handlers,
					precedence:  e.precedence - 1,
				}

				for i := range node.nodes {
					if node.nodes[i].paramsLen > node.paramsLen {
						node.paramsLen = node.nodes[i].paramsLen
					}
				}

				e.nodes = []*muxEntry{&node}
				e.tokens = string([]byte{e.part[i]})
				e.part = path[:i]
				e.handlers = nil
				e.hasWildNode = false
			}

			if i < len(path) {
				path = path[i:]

				if e.hasWildNode {
					e = e.nodes[0]
					e.precedence++

					if numParams > e.paramsLen {
						e.paramsLen = numParams
					}
					numParams--

					if len(path) >= len(e.part) && e.part == path[:len(e.part)] {

						if len(e.part) >= len(path) || path[len(e.part)] == slashByte {
							continue loop
						}
					}
					return errMuxEntryConflictsWildcard.Format(path, e.part, fullPath)
				}

				c := path[0]

				if e.entryCase == hasParams && c == slashByte && len(e.nodes) == 1 {
					e = e.nodes[0]
					e.precedence++
					continue loop
				}
				for i := range e.tokens {
					if c == e.tokens[i] {
						i = e.precedenceTo(i)
						e = e.nodes[i]
						continue loop
					}
				}

				if c != parameterStartByte && c != matchEverythingByte {

					e.tokens += string([]byte{c})
					node := &muxEntry{
						paramsLen: numParams,
					}
					e.nodes = append(e.nodes, node)
					e.precedenceTo(len(e.tokens) - 1)
					e = node
				}
				e.addNode(numParams, path, fullPath, handlers)
				return nil

			} else if i == len(path) {
				if e.handlers != nil {
					return errMuxEntryhandlersAlreadyExists.Format(fullPath)
				}
				e.handlers = handlers
			}
			return nil
		}
	} else {
		e.addNode(numParams, path, fullPath, handlers)
		e.entryCase = isRoot
	}
	return nil
}

// addNode adds a muxEntry as children to other muxEntry
func (e *muxEntry) addNode(numParams uint8, path string, fullPath string, handlers Handlers) error {
	var offset int

	for i, max := 0, len(path); numParams > 0; i++ {
		c := path[i]
		if c != parameterStartByte && c != matchEverythingByte {
			continue
		}

		end := i + 1
		for end < max && path[end] != slashByte {
			switch path[end] {
			case parameterStartByte, matchEverythingByte:
				/*
				   panic("only one wildcard per path segment is allowed, has: '" +
				   	path[i:] + "' in path '" + fullPath + "'")
				*/
				return errMuxEntryInvalidWildcard.Format(path[i:], fullPath)
			default:
				end++
			}
		}

		if len(e.nodes) > 0 {
			return errMuxEntryConflictsExistingWildcard.Format(path[i:end], fullPath)
		}

		if end-i < 2 {
			return errMuxEntryWildcardUnnamed.Format(fullPath)
		}

		if c == parameterStartByte {

			if i > 0 {
				e.part = path[offset:i]
				offset = i
			}

			child := &muxEntry{
				entryCase: hasParams,
				paramsLen: numParams,
			}
			e.nodes = []*muxEntry{child}
			e.hasWildNode = true
			e = child
			e.precedence++
			numParams--

			if end < max {
				e.part = path[offset:end]
				offset = end

				child := &muxEntry{
					paramsLen:  numParams,
					precedence: 1,
				}
				e.nodes = []*muxEntry{child}
				e = child
			}

		} else {
			if end != max || numParams > 1 {
				return errMuxEntryWildcardInvalidPlace.Format(fullPath)
			}

			if len(e.part) > 0 && e.part[len(e.part)-1] == '/' {
				return errMuxEntryWildcardConflictshandlers.Format(fullPath)
			}

			i--
			if path[i] != slashByte {
				return errMuxEntryWildcardMissingSlash.Format(fullPath)
			}

			e.part = path[offset:i]

			child := &muxEntry{
				hasWildNode: true,
				entryCase:   matchEverything,
				paramsLen:   1,
			}
			e.nodes = []*muxEntry{child}
			e.tokens = string(path[i])
			e = child
			e.precedence++

			child = &muxEntry{
				part:       path[i:],
				entryCase:  matchEverything,
				paramsLen:  1,
				handlers:   handlers,
				precedence: 1,
			}
			e.nodes = []*muxEntry{child}

			return nil
		}
	}

	e.part = path[offset:]
	e.handlers = handlers

	return nil
}

// get is used by the Router, it finds and returns the correct muxEntry for a path
func (e *muxEntry) get(path string, ctx *paramsCtx) (handlers Handlers, mustRedirect bool) {
loop:
	for {
		if len(path) > len(e.part) {
			if path[:len(e.part)] == e.part {
				path = path[len(e.part):]

				if !e.hasWildNode {
					c := path[0]
					for i := range e.tokens {
						if c == e.tokens[i] {
							e = e.nodes[i]
							continue loop
						}
					}

					mustRedirect = (path == slash && e.handlers != nil)
					return
				}

				e = e.nodes[0]
				switch e.entryCase {
				case hasParams:

					end := 0
					for end < len(path) && path[end] != '/' {
						end++
					}

					// edw exoume 9ema to key borei na einai mono 1
					ctx.params.Set(e.part[1:], path[:end])
					//context.WithValue(parent, key, val)
					//println("set " + key + " = " + value)
					if end < len(path) {
						if len(e.nodes) > 0 {
							path = path[end:]
							e = e.nodes[0]
							continue loop
						}

						mustRedirect = (len(path) == end+1)
						return
					}

					if handlers = e.handlers; handlers != nil {
						return
					} else if len(e.nodes) == 1 {
						e = e.nodes[0]
						mustRedirect = (e.part == slash && e.handlers != nil)
					}

					return

				case matchEverything:
					ctx.params.Set(e.part[2:], path)
					handlers = e.handlers
					return

				default:
					return
				}
			}
		} else if path == e.part {
			if handlers = e.handlers; handlers != nil {
				return
			}

			if path == slash && e.hasWildNode && e.entryCase != isRoot {
				mustRedirect = true
				return
			}

			for i := range e.tokens {
				if e.tokens[i] == slashByte {
					e = e.nodes[i]
					mustRedirect = (len(e.part) == 1 && e.handlers != nil) ||
						(e.entryCase == matchEverything && e.nodes[0].handlers != nil)
					return
				}
			}

			return
		}

		mustRedirect = (path == slash) ||
			(len(e.part) == len(path)+1 && e.part[len(path)] == slashByte &&
				path == e.part[:len(e.part)-1] && e.handlers != nil)
		return
	}
}

// precedenceTo just adds the priority of this muxEntry by an index
func (e *muxEntry) precedenceTo(index int) int {
	e.nodes[index].precedence++
	_precedence := e.nodes[index].precedence

	newindex := index
	for newindex > 0 && e.nodes[newindex-1].precedence < _precedence {
		tmpN := e.nodes[newindex-1]
		e.nodes[newindex-1] = e.nodes[newindex]
		e.nodes[newindex] = tmpN

		newindex--
	}

	if newindex != index {
		e.tokens = e.tokens[:newindex] +
			e.tokens[index:index+1] +
			e.tokens[newindex:index] + e.tokens[index+1:]
	}

	return newindex
}

type (
	// NamedRoute is the struct which the developer can set a custom name to a route in order to use the Lookup function
	// used for template funcs with kataras/go-template
	NamedRoute struct {
		// if no name given then it's the subdomain+path
		Name      string
		Subdomain string
		Method    string
		Path      string
		// used to replace : and * with %v, normally it doesn't used from user/dev
		FormattedPath  string
		formattedParts int

		Handlers Handlers
	}
)

func newNamedRoute(method string, subdomain string, path string, handlers Handlers) *NamedRoute {
	r := &NamedRoute{
		Name:      path + subdomain,
		Method:    method,
		Subdomain: subdomain,
		Path:      path,
		Handlers:  handlers,
	}
	r.formatPath()
	return r
}

func (r *NamedRoute) formatPath() {
	// we don't care about performance here.
	n1Len := strings.Count(r.Path, ":")
	isMatchEverything := len(r.Path) > 0 && r.Path[len(r.Path)-1] == matchEverythingByte
	if n1Len == 0 && !isMatchEverything {
		// its a static
		return
	}
	if n1Len == 0 && isMatchEverything {
		//if we have something like: /mypath/anything/* -> /mypatch/anything/%v
		r.FormattedPath = r.Path[0:len(r.Path)-2] + "%v"
		r.formattedParts++
		return
	}

	tempPath := r.Path
	splittedN1 := strings.Split(r.Path, "/")

	for _, v := range splittedN1 {
		if len(v) > 0 {
			if v[0] == ':' || v[0] == matchEverythingByte {
				r.formattedParts++
				tempPath = strings.Replace(tempPath, v, "%v", -1) // n1Len, but let it we don't care about performance here.
			}
		}

	}
	r.FormattedPath = tempPath
}

const (
	// subdomainIndicator where './' exists in a registed path then it contains subdomain
	subdomainIndicator = "./"
	// dynamicSubdomainIndicator where a registed path starts with '*.' then it contains a dynamic subdomain, if subdomain == "*." then its dynamic
	dynamicSubdomainIndicator = "*."
)

var statusCodesAll = []int{
	http.StatusContinue,
	http.StatusSwitchingProtocols,
	http.StatusProcessing,
	http.StatusOK,
	http.StatusCreated,
	http.StatusNonAuthoritativeInfo,
	http.StatusNoContent,
	http.StatusResetContent,
	http.StatusPartialContent,
	http.StatusMultiStatus,
	http.StatusAlreadyReported,
	http.StatusIMUsed,
	http.StatusMultipleChoices,
	http.StatusMovedPermanently,
	http.StatusFound,
	http.StatusSeeOther,
	http.StatusNotModified,
	http.StatusUseProxy,
	http.StatusTemporaryRedirect,
	http.StatusPermanentRedirect,
	http.StatusUnauthorized,
	http.StatusPaymentRequired,
	http.StatusForbidden,
	http.StatusBadRequest,
	http.StatusNotFound,
	http.StatusMethodNotAllowed,
	http.StatusNotAcceptable,
	http.StatusProxyAuthRequired,
	http.StatusRequestTimeout,
	http.StatusConflict,
	http.StatusGone,
	http.StatusLengthRequired,
	http.StatusPreconditionFailed,
	http.StatusRequestEntityTooLarge,
	http.StatusRequestURITooLong,
	http.StatusUnsupportedMediaType,
	http.StatusRequestedRangeNotSatisfiable,
	http.StatusExpectationFailed,
	http.StatusTeapot,
	http.StatusUnprocessableEntity,
	http.StatusLocked,
	http.StatusFailedDependency,
	http.StatusUpgradeRequired,
	http.StatusPreconditionRequired,
	http.StatusTooManyRequests,
	http.StatusRequestHeaderFieldsTooLarge,
	http.StatusUnavailableForLegalReasons,
	http.StatusInternalServerError,
	http.StatusNotImplemented,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
	http.StatusHTTPVersionNotSupported,
	http.StatusVariantAlsoNegotiates,
	http.StatusInsufficientStorage,
	http.StatusLoopDetected,
	http.StatusNotExtended,
	http.StatusNetworkAuthenticationRequired,
}

type (
	muxTree struct {
		method string
		// subdomain is empty for default-hostname routes,
		// ex: mysubdomain.
		subdomain string
		entry     *muxEntry
	}

	// ServeMux the Go 1.7 serve mux
	ServeMux struct {
		MuxAPI
		Lookups   []*NamedRoute
		maxParams uint8
		garden    []*muxTree
		mu        sync.Mutex
		hosts     bool // taken from routes
		Errors    map[int]http.Handler
		cpool     sync.Pool
		// options
		Host        string // if != "" then you have subdomain support
		MethodEqual func(string, string) bool
	}
)

// New returns a new ServeMux
func New() *ServeMux {
	// build the errors handlers
	defaultErrHandlers := make(map[int]http.Handler, 0)
	for _, statusCode := range statusCodesAll {
		if defaultErrHandlers[statusCode] == nil && statusCode != http.StatusOK && statusCode != http.StatusPermanentRedirect &&
			statusCode != http.StatusTemporaryRedirect && statusCode != http.StatusAccepted && statusCode != http.StatusCreated {
			// register the default error handler if not registed by the user
			func(statusCode int) {
				errHandler := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					res.WriteHeader(statusCode)
					io.WriteString(res, http.StatusText(statusCode))
				})
				defaultErrHandlers[statusCode] = errHandler
			}(statusCode)
		}
	}

	mux := &ServeMux{
		Lookups: make([]*NamedRoute, 0),
		MethodEqual: func(treeMethod string, reqMethod string) bool {
			return treeMethod == reqMethod
		},
		Errors: defaultErrHandlers,
		cpool:  sync.Pool{New: func() interface{} { return &paramsCtx{Context: context.Background()} }},
	}
	mux.MuxAPI = &muxAPI{mux: mux, relativePath: "/"}
	return mux
}

// Lookup takes a name and returns the route which registed with that name
func Lookup(routeName string) *NamedRoute {
	return Default.Lookup(routeName)
}

// Lookup takes a name and returns the route which registed with that name
func (mux *ServeMux) Lookup(routeName string) *NamedRoute {
	for i := range mux.Lookups {
		if r := mux.Lookups[i]; r.Name == routeName {
			return r
		}
	}
	return nil
}

func (mux *ServeMux) getTree(method string, subdomain string) *muxTree {
	for i := range mux.garden {
		t := mux.garden[i]
		if t.method == method && t.subdomain == subdomain {
			return t
		}
	}
	return nil
}

var errSubdomainsEmptyHost = errors.New("You passed a subdomain route but you didn't set the Host option on the mux.New declaration")

func (mux *ServeMux) register(method string, subdomain string, path string, handlers Handlers) *NamedRoute {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	if subdomain != "" {
		if mux.Host == "" {
			panic(errSubdomainsEmptyHost)
		}
		mux.hosts = true
	}

	// add to the lookups, it's just a collection of routes information
	r := newNamedRoute(method, subdomain, path, handlers)
	mux.Lookups = append(mux.Lookups, r)

	// add to the registry tree
	tree := mux.getTree(r.Method, r.Subdomain)
	if tree == nil {
		//first time we register a route to this method with this domain
		tree = &muxTree{method: r.Method, subdomain: r.Subdomain, entry: &muxEntry{}}
		mux.garden = append(mux.garden, tree)
	}
	// I decide that it's better to explicit give subdomain and a path to it than registedPath(mysubdomain./something) now its: subdomain: mysubdomain., path: /something
	// we have different tree for each of subdomains, now you can use everything you can use with the normal paths ( before you couldn't set /any/*path)
	if err := tree.entry.add(r.Path, r.Handlers); err != nil {
		panic(err.Error())
	}

	if mp := tree.entry.paramsLen; mp > mux.maxParams {
		mux.maxParams = mp // not used currently*
	}

	return r
}

// ServeHTTP is the Router, which is the http.Handler you should pass to your server
func ServeHTTP(res http.ResponseWriter, req *http.Request) {
	Default.ServeHTTP(res, req)
}

// ServeHTTP is the Router, which is the http.Handler you should pass to your server
func (mux *ServeMux) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	for i := range mux.garden {
		tree := mux.garden[i]
		if !mux.MethodEqual(tree.method, req.Method) {
			continue
		}
		// we have at least one subdomain on the root
		if mux.hosts && tree.subdomain != "" {
			requestHost := req.Host // on net/http that gives the full host, no just the main host(name)

			if strings.Index(tree.subdomain, dynamicSubdomainIndicator) != -1 {
			} else {
				// mux.host = mydomain.com:8080, the subdomain for example is api.,
				// so the host must be api.mydomain.com:8080
				if tree.subdomain+mux.Host != requestHost {
					// go to the next tree, we have a subdomain but it is not the correct
					continue
				}

			}
		}
		reqPath := req.URL.Path
		ctx := mux.cpool.Get().(*paramsCtx)
		ctx.params.Reset()
		//ctx := &paramsCtx{Context: context.TODO()}
		handlers, mustRedirect := tree.entry.get(reqPath, ctx) // pass the parameters here for 0 allocation
		if handlers != nil {
			req = req.WithContext(ctx)

			for i := range handlers {
				if ctx.Canceled() {
					break
				}

				handlers[i].ServeHTTP(res, req)
			}

			mux.cpool.Put(ctx)
			return

		} else if mustRedirect && req.Method != http.MethodConnect {

			pathLen := len(reqPath)

			if pathLen > 1 {

				if reqPath[pathLen-1] == '/' {
					reqPath = reqPath[:pathLen-1] //remove the last /
				} else {
					//it has path prefix, it doesn't ends with / and it hasn't be found, then just add the slash
					reqPath = reqPath + "/"
				}

				http.Redirect(res, req, reqPath, http.StatusMovedPermanently)

				mux.cpool.Put(ctx)
				return
			}
		}
		mux.cpool.Put(ctx)
		// not found
		break
	}
	errHandler := mux.Errors[http.StatusNotFound] //one reader, no need to lock this
	errHandler.ServeHTTP(res, req)
}

// Cancel stops a middleware from continue, returns true if cancel action was act successfully
func Cancel(ctx context.Context) bool {
	return Default.Cancel(ctx)
}

// Cancel stops a middleware from continue, returns true if cancel action was act successfully
func (mux *ServeMux) Cancel(ctx context.Context) bool {
	if cancelFn, isFunc := ctx.Value(cancelKey).(func()); cancelFn != nil && isFunc {
		cancelFn()
		return true
	}
	return false
}

// -------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------
// ----------------------------------MuxAPI implementation------------------------------
// -------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------
type (
	// RouteNameFunc the func returns from the MuxAPi's methods, optionally sets the name of the Route (*route)
	RouteNameFunc func(string)
	// MuxAPI the visible api for the serveMux
	MuxAPI interface {
		Party(string, ...http.Handler) MuxAPI
		// middleware serial, appending
		Use(...http.Handler)
		// returns itself, because at the most-cases used like .Layout, at the first-line party's declaration
		Done(...http.Handler) MuxAPI
		//

		// main handlers
		Handle(string, string, ...http.Handler) RouteNameFunc
		HandleFunc(string, string, ...func(http.ResponseWriter, *http.Request)) RouteNameFunc
		// http methods
		Get(string, ...http.Handler) RouteNameFunc
		Post(string, ...http.Handler) RouteNameFunc
		Put(string, ...http.Handler) RouteNameFunc
		Delete(string, ...http.Handler) RouteNameFunc
		Connect(string, ...http.Handler) RouteNameFunc
		Head(string, ...http.Handler) RouteNameFunc
		Options(string, ...http.Handler) RouteNameFunc
		Patch(string, ...http.Handler) RouteNameFunc
		Trace(string, ...http.Handler) RouteNameFunc
		Any(string, ...http.Handler)
	}

	muxAPI struct {
		mux            *ServeMux
		doneMiddleware Handlers
		apiRoutes      []*NamedRoute // used to register the .Done middleware
		relativePath   string
		middleware     Handlers
	}
)

var _ MuxAPI = &muxAPI{}

// joinMiddleware uses to create a copy of all middleware and return them in order to use inside the node
func joinMiddleware(middleware1 Handlers, middleware2 Handlers) Handlers {
	nowLen := len(middleware1)
	totalLen := nowLen + len(middleware2)
	// create a new slice of middleware in order to store all handlers, the already handlers(middleware) and the new
	newMiddleware := make(Handlers, totalLen)
	//copy the already middleware to the just created
	copy(newMiddleware, middleware1)
	//start from there we finish, and store the new middleware too
	copy(newMiddleware[nowLen:], middleware2)
	return newMiddleware
}

// Party is just a group joiner of routes which have the same prefix and share same middleware(s) also.
// Party can also be named as 'Join' or 'Node' or 'Group' , Party chosen because it has more fun
func Party(relativePath string, middleware ...http.Handler) MuxAPI {
	return Default.Party(relativePath, middleware...)
}

// Party is just a group joiner of routes which have the same prefix and share same middleware(s) also.
// Party can also be named as 'Join' or 'Node' or 'Group' , Party chosen because it has more fun
func (api *muxAPI) Party(relativePath string, middleware ...http.Handler) MuxAPI {
	parentPath := api.relativePath
	dot := string(subdomainIndicator[0])
	if len(parentPath) > 0 && parentPath[0] == slashByte && strings.HasSuffix(relativePath, dot) { // if ends with . , example: admin., it's subdomain->
		parentPath = parentPath[1:] // remove first slash
	}

	fullpath := parentPath + relativePath
	// append the parent's +child's handlers
	middleware = joinMiddleware(api.middleware, middleware)

	return &muxAPI{relativePath: fullpath, mux: api.mux, apiRoutes: make([]*NamedRoute, 0), middleware: middleware, doneMiddleware: api.doneMiddleware}
}

// Use registers Handler middleware
func Use(handlers ...http.Handler) {
	Default.Use(handlers...)
}

// Use registers Handler middleware
func (api *muxAPI) Use(handlers ...http.Handler) {
	api.middleware = append(api.middleware, handlers...)
}

// Done registers Handler 'middleware' the only difference from .Use is that it
// should be used BEFORE any party route registered or AFTER ALL party's routes have been registered.
//
// returns itself
func Done(handlers ...http.Handler) MuxAPI {
	return Default.Done(handlers...)
}

// Done registers Handler 'middleware' the only difference from .Use is that it
// should be used BEFORE any party route registered or AFTER ALL party's routes have been registered.
//
// returns itself
func (api *muxAPI) Done(handlers ...http.Handler) MuxAPI {
	if len(api.apiRoutes) > 0 { // register these middleware on previous-party-defined routes, it called after the party's route methods (Handle/HandleFunc/Get/Post/Put/Delete/...)
		for i, n := 0, len(api.apiRoutes); i < n; i++ {
			api.apiRoutes[i].Handlers = append(api.apiRoutes[i].Handlers, handlers...)
		}
	} else {
		// register them on the doneMiddleware, which will be used on Handle to append these middlweare as the last handler(s)
		api.doneMiddleware = append(api.doneMiddleware, handlers...)
	}

	return api
}

var allMethods = [...]string{
	http.MethodGet,
	http.MethodPost,
	http.MethodPut,
	http.MethodDelete,
	http.MethodConnect,
	http.MethodHead,
	http.MethodPatch,
	http.MethodOptions,
	http.MethodTrace,
}

// Handle registers a route to the servemux
// if empty method is passed then registers handler(s) for all methods, same as .Any, but returns nil as result
func Handle(method string, registedPath string, handlers ...http.Handler) RouteNameFunc {
	return Default.Handle(method, registedPath, handlers...)
}

// Handle registers a route to the servemux
// if empty method is passed then registers handler(s) for all methods, same as .Any, but returns nil as result
func (api *muxAPI) Handle(method string, registedPath string, handlers ...http.Handler) RouteNameFunc {
	if method == "" { // then use like it was .Any
		api.Any(registedPath, handlers...)
		return func(s string) {}
	}

	fullpath := api.relativePath + registedPath // keep the last "/" if any,  "/xyz/"

	middleware := joinMiddleware(api.middleware, handlers)

	// here we separate the subdomain and relative path
	subdomain := ""
	path := fullpath

	if dotWSlashIdx := strings.Index(path, subdomainIndicator); dotWSlashIdx > 0 {
		subdomain = fullpath[0 : dotWSlashIdx+1] // admin.
		path = fullpath[dotWSlashIdx+1:]         // /
	}
	// we splitted the path and subdomain parts so we're ready to check only the path, otherwise we will had problems with subdomains
	// remove last "/" if any, "/xyz/"
	if len(path) > 1 { // if it's the root, then keep it*
		if path[len(path)-1] == slashByte {
			// ok we are inside /xyz/
			path = path[0 : len(path)-1]
		}
	}

	path = strings.Replace(path, "//", "/", -1) // fix the path if double //

	if len(api.doneMiddleware) > 0 {
		middleware = append(middleware, api.doneMiddleware...) // register the done middleware, if any
	}
	r := api.mux.register(method, subdomain, path, middleware)
	api.apiRoutes = append(api.apiRoutes, r)

	// should we remove the api.apiRoutes on the .Party (new children party) ?, No, because the user maybe use this party later
	// should we add to the 'inheritance tree' the api.apiRoutes, No, these are for this specific party only, because the user propably, will have unexpected behavior when using Use/UseFunc, Done/DoneFunc
	return func(routeName string) {
		r.Name = routeName
	}
}

// convertToHandlers just make []HandlerFunc to []Handler, although HandlerFunc and Handler are the same
// we need this on some cases we explicit want a interface Handler, it is useless for users.
func convertToHandlers(handlersFn []func(http.ResponseWriter, *http.Request)) []http.Handler {
	hlen := len(handlersFn)
	mlist := make([]http.Handler, hlen)
	for i := 0; i < hlen; i++ {
		mlist[i] = http.HandlerFunc(handlersFn[i])
	}
	return mlist
}

// HandleFunc registers a route to the servemux
// if empty method is passed then registers handler(s) for all methods, same as .Any, but returns nil as result
func HandleFunc(method string, registedPath string, handlersFn ...func(http.ResponseWriter, *http.Request)) RouteNameFunc {
	return Default.HandleFunc(method, registedPath, handlersFn...)
}

// HandleFunc registers a route to the servemux
// if empty method is passed then registers handler(s) for all methods, same as .Any, but returns nil as result
func (api *muxAPI) HandleFunc(method string, registedPath string, handlersFn ...func(http.ResponseWriter, *http.Request)) RouteNameFunc {
	handlers := convertToHandlers(handlersFn)
	return api.Handle(method, registedPath, handlers...)
}

// Get registers a route for the Get http method
func Get(path string, handlers ...http.Handler) RouteNameFunc {
	return Default.Get(path, handlers...)
}

// Get registers a route for the Get http method
func (api *muxAPI) Get(path string, handlers ...http.Handler) RouteNameFunc {
	return api.Handle(http.MethodGet, path, handlers...)
}

// Post registers a route for the Post http method
func Post(path string, handlers ...http.Handler) RouteNameFunc {
	return Default.Post(path, handlers...)
}

// Post registers a route for the Post http method
func (api *muxAPI) Post(path string, handlers ...http.Handler) RouteNameFunc {
	return api.Handle(http.MethodPost, path, handlers...)
}

// Put registers a route for the Put http method
func Put(path string, handlers ...http.Handler) RouteNameFunc {
	return Default.Put(path, handlers...)
}

// Put registers a route for the Put http method
func (api *muxAPI) Put(path string, handlers ...http.Handler) RouteNameFunc {
	return api.Handle(http.MethodPut, path, handlers...)
}

// Delete registers a route for the Delete http method
func Delete(path string, handlers ...http.Handler) RouteNameFunc {
	return Default.Delete(path, handlers...)
}

// Delete registers a route for the Delete http method
func (api *muxAPI) Delete(path string, handlers ...http.Handler) RouteNameFunc {
	return api.Handle(http.MethodDelete, path, handlers...)
}

// Connect registers a route for the Connect http method
func Connect(path string, handlers ...http.Handler) RouteNameFunc {
	return Default.Connect(path, handlers...)
}

// Connect registers a route for the Connect http method
func (api *muxAPI) Connect(path string, handlers ...http.Handler) RouteNameFunc {
	return api.Handle(http.MethodConnect, path, handlers...)
}

// Head registers a route for the Head http method
func Head(path string, handlers ...http.Handler) RouteNameFunc {
	return Default.Head(path, handlers...)
}

// Head registers a route for the Head http method
func (api *muxAPI) Head(path string, handlers ...http.Handler) RouteNameFunc {
	return api.Handle(http.MethodHead, path, handlers...)
}

// Options registers a route for the Options http method
func Options(path string, handlers ...http.Handler) RouteNameFunc {
	return Default.Options(path, handlers...)
}

// Options registers a route for the Options http method
func (api *muxAPI) Options(path string, handlers ...http.Handler) RouteNameFunc {
	return api.Handle(http.MethodOptions, path, handlers...)
}

// Patch registers a route for the Patch http method
func Patch(path string, handlers ...http.Handler) RouteNameFunc {
	return Default.Patch(path, handlers...)
}

// Patch registers a route for the Patch http method
func (api *muxAPI) Patch(path string, handlers ...http.Handler) RouteNameFunc {
	return api.Handle(http.MethodPatch, path, handlers...)
}

// Trace registers a route for the Trace http method
func Trace(path string, handlers ...http.Handler) RouteNameFunc {
	return Default.Trace(path, handlers...)
}

// Trace registers a route for the Trace http method
func (api *muxAPI) Trace(path string, handlers ...http.Handler) RouteNameFunc {
	return api.Handle(http.MethodTrace, path, handlers...)
}

// Any registers a route for ALL of the http methods (Get,Post,Put,Head,Patch,Options,Connect,Delete)
func Any(registedPath string, handlers ...http.Handler) {
	Default.Any(registedPath, handlers...)
}

// Any registers a route for ALL of the http methods (Get,Post,Put,Head,Patch,Options,Connect,Delete)
func (api *muxAPI) Any(registedPath string, handlers ...http.Handler) {
	for _, k := range allMethods {
		api.Handle(k, registedPath, handlers...)
	}
}
