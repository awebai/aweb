// Command identityinventory checks the raw primitive boundary without a call-count catalog.
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
	"sort"
	"strconv"
	"strings"
)

type legacyFile struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}
type inventory struct {
	PrimitiveGuard struct {
		LegacyFiles []legacyFile `json:"legacy_files"`
	} `json:"primitive_guard"`
}
type siteKey struct{ File, Symbol string }

const strictModule = "cli/go/awid/id_certificates.go"

func excluded(file string) bool {
	return strings.HasSuffix(file, "_test.go") || strings.Contains("/"+file, "/testdata/") || file == "cli/go/internal/identityinventory/main.go"
}

func cryptoPrimitive(name string) bool {
	for _, module := range []string{"crypto/ed25519", "golang.org/x/crypto/ed25519", "filippo.io/edwards25519"} {
		if strings.HasPrefix(name, module+".") {
			if module == "filippo.io/edwards25519" {
				return true
			}
			operation := strings.TrimPrefix(name, module+".")
			return operation == "Sign" || operation == "Verify" || operation == "GenerateKey" || operation == "NewKeyFromSeed"
		}
	}
	return false
}

func primitiveModule(module string) bool {
	return module == "crypto/ed25519" || module == "golang.org/x/crypto/ed25519" || strings.HasPrefix(module, "filippo.io/edwards25519")
}

func scanGoSource(source []byte) (map[string]map[string]bool, error) {
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
			if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" && len(n.Args) == 1 {
				return name(n.Args[0]) + "()"
			}
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
	result := map[string]map[string]bool{}
	record := func(symbol, callee string) {
		if result[symbol] == nil {
			result[symbol] = map[string]bool{}
		}
		result[symbol][callee] = true
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
				if cryptoPrimitive(callee) {
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
					if cryptoPrimitive(callee) {
						record(symbol, "reference:"+callee)
					}
				}
			}
			return true
		})
	}
	return result, nil
}

func checkPrimitiveUses(observed map[siteKey]map[string]bool, legacy []legacyFile) []string {
	var errors []string
	files := map[string]bool{}
	for _, entry := range legacy {
		if entry.File == "" || strings.TrimSpace(entry.Reason) == "" {
			errors = append(errors, "legacy primitive file requires a reason")
		} else {
			files[entry.File] = true
		}
	}
	for key := range observed {
		// idStrictVerify is the one shared strict verifier for certificates,
		// requests and covering envelopes; idCertificatePrimePoint is its
		// point check.
		shared := key.File == strictModule && (key.Symbol == "idStrictVerify" || key.Symbol == "idCertificatePrimePoint")
		if !shared && !files[key.File] {
			errors = append(errors, "raw Go crypto must use the shared verifier: "+fmt.Sprint(key))
		}
	}
	sort.Strings(errors)
	return errors
}

func scanRepository(root string) (map[siteKey]map[string]bool, error) {
	command := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.go")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, err
	}
	result := map[siteKey]map[string]bool{}
	sources := map[string][]byte{}
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
		sources[file] = source
	}
	for file, source := range sources {
		calls, e := scanGoSource(source)
		if e != nil {
			return nil, fmt.Errorf("cannot scan %s: %w", file, e)
		}
		for symbol, uses := range calls {
			result[siteKey{file, symbol}] = uses
		}
	}
	return result, nil
}

func run(root string) error {
	data, err := os.ReadFile(filepath.Join(root, "docs/identity-tree-coverage.json"))
	if err != nil {
		return err
	}
	var coverage inventory
	if err = json.Unmarshal(data, &coverage); err != nil {
		return err
	}
	observed, err := scanRepository(root)
	if err != nil {
		return err
	}
	if errors := checkPrimitiveUses(observed, coverage.PrimitiveGuard.LegacyFiles); len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "\n"))
	}
	fmt.Println("Go primitive-use boundary passed")
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
