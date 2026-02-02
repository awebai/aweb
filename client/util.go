package aweb

import (
	"net/url"
	"strconv"
)

func urlQueryEscape(v string) string {
	return url.QueryEscape(v)
}

func urlPathEscape(v string) string {
	return url.PathEscape(v)
}

func itoa(v int) string {
	return strconv.Itoa(v)
}

