package main
import (
 "testing"
 "time"
)
func TestGrantTTLNeverFlag(t *testing.T) {
 resetGrantCommandGlobals(t)
 mint, _, err := rootCmd.Find([]string{"id", "grant", "mint"})
 if err != nil { t.Fatal(err) }
 if err := mint.Flags().Set("ttl", "never"); err != nil { t.Fatalf("never must parse: %v", err) }
 if grantMintTTL >= 0 { t.Fatal("never must have a distinct marker") }
 if err := mint.Flags().Set("ttl", "8h"); err != nil || grantMintTTL != 8*time.Hour { t.Fatal("finite duration changed") }
 if err := mint.Flags().Set("ttl", "nonsense"); err == nil { t.Fatal("malformed TTL accepted") }
}
