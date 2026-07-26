//go:build !awebtestpinstorecasbarrier

package main

func pinStoreCASPreLockHook() error {
	return nil
}
