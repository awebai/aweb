//go:build windows

package custodypath

import "fmt"

func Prepare(socket string) error {
	return fmt.Errorf("custody Unix sockets are unsupported on Windows")
}
func Check(socket string) error { return fmt.Errorf("custody Unix sockets are unsupported on Windows") }
