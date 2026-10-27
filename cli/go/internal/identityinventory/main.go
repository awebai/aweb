// Command identityinventory pins Go identity primitive uses to the shared inventory.
// It is a syntactic drift guard, not a control-flow or dynamic-dispatch proof.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type site struct {
	File   string `json:"file"`
	Symbol string `json:"symbol"`
}
type row struct {
	ID      string   `json:"id"`
	Repo    string   `json:"repo"`
	Files   []string `json:"files"`
	Sites   []site   `json:"sites"`
	Profile string   `json:"ed25519_profile"`
}
type catalogSite struct {
	Row    string         `json:"row"`
	File   string         `json:"file"`
	Symbol string         `json:"symbol"`
	Calls  map[string]int `json:"calls"`
}
type inventory struct {
	V       int   `json:"v"`
	Sites   []row `json:"sites"`
	GoGuard struct {
		V     int           `json:"v"`
		Sites []catalogSite `json:"sites"`
	} `json:"go_guard"`
}
type siteKey struct{ File, Symbol string }

const strictModule = "cli/go/awid/id_certificates.go"

func excluded(file string) bool {
	return strings.HasSuffix(file, "_test.go") || strings.Contains("/"+file, "/testdata/") || file == "cli/go/internal/identityinventory/main.go"
}

func primitive(name string) bool {
	terminal := name[strings.LastIndex(name, ".")+1:]
	lower := strings.ToLower(terminal)
	for _, prefix := range []string{"sign", "verify", "register", "revoke", "generatekey", "newkeyfromseed", "computedid", "extractpublickey", "idcertificate", "encodeidchain", "decodeidchain", "idstatus", "idrequest", "idchain"} {
		if strings.HasPrefix(lower, prefix) && (len(terminal) == len(prefix) || terminal[len(prefix)] == '_' || (terminal[len(prefix)] >= 'A' && terminal[len(prefix)] <= 'Z')) {
			return true
		}
	}
	return false
}

func primitiveModule(module string) bool {
	return module == "crypto/ed25519" || strings.HasPrefix(module, "filippo.io/edwards25519") || module == "github.com/awebai/aw/awid"
}

func scanGoSource(source []byte) (map[string]map[string]int, error) {
	tree, err := parser.ParseFile(token.NewFileSet(), "source.go", source, 0)
	if err != nil {
		return nil, err
	}
	aliases := map[string]string{}
	for _, imp := range tree.Imports {
		module, e := strconv.Unquote(imp.Path.Value)
		if e != nil {
			return nil, e
		}
		alias := path.Base(module)
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		if alias == "." && primitiveModule(module) {
			return nil, fmt.Errorf("dot import hides identity primitive: %s", module)
		}
		aliases[alias] = module
	}
	var name func(ast.Node) string
	name = func(node ast.Node) string {
		switch n := node.(type) {
		case *ast.Ident:
			if resolved, ok := aliases[n.Name]; ok {
				return resolved
			}
			return n.Name
		case *ast.SelectorExpr:
			return name(n.X) + "." + n.Sel.Name
		case *ast.CallExpr:
			return name(n.Fun) + "()"
		case *ast.ParenExpr:
			return name(n.X)
		case *ast.StarExpr:
			return "*" + name(n.X)
		case *ast.IndexExpr:
			return name(n.X)
		case *ast.IndexListExpr:
			return name(n.X)
		}
		return "<expression>"
	}
	result := map[string]map[string]int{}
	record := func(symbol, callee string) {
		if result[symbol] == nil {
			result[symbol] = map[string]int{}
		}
		result[symbol][callee]++
	}
	for _, decl := range tree.Decls {
		if gen, ok := decl.(*ast.GenDecl); ok && gen.Tok == token.IMPORT {
			continue
		}
		symbol := "<module>"
		if fn, ok := decl.(*ast.FuncDecl); ok {
			symbol = fn.Name.Name
			if fn.Recv != nil {
				receiver := name(fn.Recv.List[0].Type)
				if strings.HasPrefix(receiver, "*") {
					receiver = "(" + receiver + ")"
				}
				symbol = receiver + "." + symbol
			}
		}
		var stack []ast.Node
		ast.Inspect(decl, func(node ast.Node) bool {
			if node == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			var parent ast.Node
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			stack = append(stack, node)
			switch n := node.(type) {
			case *ast.CallExpr:
				callee := name(n.Fun)
				if primitive(callee) {
					record(symbol, callee)
				}
			case *ast.SelectorExpr, *ast.Ident:
				// Definitions, field names and selector receivers are not value loads.
				skip := false
				switch p := parent.(type) {
				case *ast.CallExpr:
					skip = p.Fun == node
				case *ast.SelectorExpr:
					skip = true
				case *ast.FuncDecl:
					skip = true
				case *ast.Field:
					skip = true
				case *ast.ValueSpec:
					for _, id := range p.Names {
						if id == node {
							skip = true
						}
					}
				case *ast.AssignStmt:
					for _, lhs := range p.Lhs {
						if lhs == node {
							skip = true
						}
					}
				case *ast.TypeSpec:
					skip = true
				}
				if id, ok := node.(*ast.Ident); ok && id.Obj != nil && id.Obj.Kind != ast.Fun {
					skip = true
				}
				if !skip {
					callee := name(n)
					if primitive(callee) {
						record(symbol, "reference:"+callee)
					}
				}
			case *ast.BasicLit:
				if n.Kind == token.STRING {
					value, e := strconv.Unquote(n.Value)
					if e == nil {
						for _, prefix := range []string{"did:key", "did:aw"} {
							if strings.HasPrefix(value, prefix+":") {
								record(symbol, "literal:"+prefix)
							}
						}
					}
				}
			}
			return true
		})
	}
	return result, nil
}

func rawVerifier(callee string) bool {
	callee = strings.TrimPrefix(callee, "reference:")
	return callee == "Verify" || strings.HasSuffix(callee, ".Verify") || strings.HasSuffix(callee, ".VerifyMessage") || strings.HasSuffix(callee, ".VerifySignedPayload") || callee == "VerifyMessage" || callee == "VerifySignedPayload"
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func mapped(row row, key siteKey) bool {
	for _, s := range row.Sites {
		if s.File == key.File && s.Symbol == key.Symbol {
			return true
		}
	}
	return false
}
func checkCatalog(rows map[string]row, entries []catalogSite, observed map[siteKey]map[string]int) []string {
	var errors []string
	declared := map[siteKey]map[string]int{}
	for _, entry := range entries {
		key := siteKey{entry.File, entry.Symbol}
		if entry.File == "" || entry.Symbol == "" || path.Clean(entry.File) != entry.File || strings.HasPrefix(entry.File, "/") || strings.HasPrefix(entry.File, "../") || !strings.HasSuffix(entry.File, ".go") || excluded(entry.File) {
			errors = append(errors, "invalid Go catalog site: "+fmt.Sprint(key))
			continue
		}
		if _, ok := declared[key]; ok {
			errors = append(errors, "duplicate Go catalog site: "+fmt.Sprint(key))
		}
		declared[key] = entry.Calls
		if len(entry.Calls) == 0 {
			errors = append(errors, "empty Go primitive counts: "+fmt.Sprint(key))
		}
		for name, count := range entry.Calls {
			if name == "" || count < 1 {
				errors = append(errors, "invalid Go primitive count: "+fmt.Sprint(key))
			}
		}
		r := rows[entry.Row]
		if r.Repo != "aweb" || !contains(r.Files, key.File) || !mapped(r, key) {
			errors = append(errors, "Go primitive needs mapped exact site: "+fmt.Sprint(key))
		}
		if r.Profile != "strict" && r.Profile != "legacy" {
			errors = append(errors, "Go row requires strict|legacy profile: "+entry.Row)
		}
		if (key.File == strictModule || key.File == "cli/go/awid/id_chain.go") && r.Profile != "strict" {
			errors = append(errors, "ID module cannot downgrade strict profile: "+key.Symbol)
		}
		if r.Profile == "strict" && key != (siteKey{strictModule, "VerifyIDCertificate"}) {
			for callee := range entry.Calls {
				if rawVerifier(callee) {
					errors = append(errors, "raw ID crypto must use shared strict verifier: "+fmt.Sprint(key))
				}
			}
		}
	}
	for key, counts := range observed {
		expected, ok := declared[key]
		if !ok {
			errors = append(errors, "unlisted Go identity primitive site: "+fmt.Sprint(key))
		} else if !reflect.DeepEqual(expected, counts) {
			errors = append(errors, "Go primitive counts changed: "+fmt.Sprint(key))
		}
	}
	for key := range declared {
		if _, ok := observed[key]; !ok {
			errors = append(errors, "stale Go identity primitive site: "+fmt.Sprint(key))
		}
	}
	sort.Strings(errors)
	return errors
}

func scanRepository(root string) (map[siteKey]map[string]int, error) {
	command := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.go")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, err
	}
	result := map[siteKey]map[string]int{}
	seen := map[string]bool{}
	for _, file := range strings.Split(string(output), "\x00") {
		if file == "" || seen[file] || excluded(file) {
			continue
		}
		seen[file] = true
		source, e := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, e
		}
		calls, e := scanGoSource(source)
		if e != nil {
			return nil, fmt.Errorf("cannot scan %s: %w", file, e)
		}
		for symbol, counts := range calls {
			result[siteKey{file, symbol}] = counts
		}
	}
	return result, nil
}

func run(root string) error {
	data, err := os.ReadFile(filepath.Join(root, "docs/identity-tree-coverage.json"))
	if err != nil {
		return err
	}
	var catalog inventory
	if err = json.Unmarshal(data, &catalog); err != nil {
		return err
	}
	if catalog.V != 1 || catalog.GoGuard.V != 1 || catalog.GoGuard.Sites == nil {
		return fmt.Errorf("identity inventory requires v=1 and go_guard {v:1, sites:[]}")
	}
	rows := map[string]row{}
	for _, r := range catalog.Sites {
		if r.ID == "" {
			return fmt.Errorf("inventory row requires id")
		}
		if _, ok := rows[r.ID]; ok {
			return fmt.Errorf("duplicate inventory row: %s", r.ID)
		}
		rows[r.ID] = r
	}
	observed, err := scanRepository(root)
	if err != nil {
		return err
	}
	if errors := checkCatalog(rows, catalog.GoGuard.Sites, observed); len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "\n"))
	}
	fmt.Printf("Go identity primitive inventory passed (%d exact sites); S8b release qualification remains separate\n", len(observed))
	return nil
}
func main() {
	root := "../.."
	if len(os.Args) == 2 {
		root = os.Args[1]
	} else if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: identityinventory [repository-root]")
		os.Exit(1)
	}
	if err := run(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
