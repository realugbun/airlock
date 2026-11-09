package proxy

import "strings"

// NormalizePathPrefix removes trailing slashes from a route prefix so that
// "/git" and "/git/" describe the same set of paths. The root prefix "/" is
// kept as "/" and an empty prefix is kept empty; both match every path.
func NormalizePathPrefix(prefix string) string {
	for len(prefix) > 1 && strings.HasSuffix(prefix, "/") {
		prefix = prefix[:len(prefix)-1]
	}
	return prefix
}

// PathPrefixMatches reports whether path falls under prefix, treating the
// prefix as a sequence of whole path segments. A path matches when it equals
// the prefix or continues it after a "/" separator, so "/git" matches "/git"
// and "/git/repo" but not "/github/repos". The root prefix "/" (and an unset
// prefix) matches every path.
func PathPrefixMatches(prefix, path string) bool {
	p := NormalizePathPrefix(prefix)
	if p == "" || p == "/" {
		return true
	}
	if path == p {
		return true
	}
	return strings.HasPrefix(path, p+"/")
}

// PathPrefixShadows reports whether a route with prefix earlier matches every
// path a route with prefix later could match. First match wins, so a shadowed
// route can never be reached and its access rules never apply; config load
// rejects such a pair.
func PathPrefixShadows(earlier, later string) bool {
	return PathPrefixMatches(earlier, NormalizePathPrefix(later))
}

// stripRoutePrefix removes a route's strip_prefix from path on the same
// segment boundary that routing uses, so the path the access policy checks is
// the path the upstream receives. A path equal to the prefix becomes "/".
func stripRoutePrefix(path, stripPrefix string) string {
	s := NormalizePathPrefix(stripPrefix)
	if s == "" || s == "/" {
		return path
	}
	if path == s {
		return "/"
	}
	if strings.HasPrefix(path, s+"/") {
		if rest := path[len(s):]; rest != "" {
			return rest
		}
	}
	return path
}
