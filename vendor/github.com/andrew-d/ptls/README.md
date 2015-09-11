# ptls

[![Godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/andrew-d/ptls) [![Build Status](https://travis-ci.org/andrew-d/ptls.svg?branch=master)](https://travis-ci.org/andrew-d/ptls)

This package contains a wrapper around Go's TLS implementation that allows one
to explicitly specify the remote peer's TLS certificate.  This is useful in
cases where you want to, for example, pin the remote certificate of a
connection to a specific certificate.  For more information, please see
[the GoDoc](https://godoc.org/github.com/andrew-d/ptls).


## License

MIT.
