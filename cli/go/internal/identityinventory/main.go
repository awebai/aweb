// Command identityinventory checks the raw primitive boundary and its call exemptions.
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

type callExemption struct {
	File   string `json:"file"`
	Symbol string `json:"symbol"`
	Callee string `json:"callee"`
	Reason string `json:"reason"`
}
type inventory struct {
	PrimitiveGuard struct {
		ExemptCalls []callExemption `json:"exempt_calls"`
	} `json:"primitive_guard"`
	CreationPaths []struct {
		Repo  string   `json:"repo"`
		Files []string `json:"files"`
	} `json:"creation_paths"`
}
type siteKey struct{ File, Symbol string }
type callKey struct {
	siteKey
	Callee string
}

func (k callKey) String() string { return k.File + ":" + k.Symbol + ": " + k.Callee }

const strictModule = "cli/go/signaturewire/signature.go"
const signerSign = "crypto.Signer.Sign"

func excluded(file string) bool {
	return strings.HasSuffix(file, "_test.go") || strings.Contains("/"+file, "/testdata/") || file == "cli/go/internal/identityinventory/main.go"
}

func cryptoPrimitive(name string) bool {
	if name == signerSign {
		return true
	}
	for _, module := range []string{"crypto/ed25519", "golang.org/x/crypto/ed25519", "filippo.io/edwards25519"} {
		if strings.HasPrefix(name, module+".") {
			if module == "filippo.io/edwards25519" {
				return true
			}
			operation := strings.TrimPrefix(name, module+".")
			switch operation {
			case "Sign", "Verify", "VerifyWithOptions", "GenerateKey", "NewKeyFromSeed":
				return true
			}
			return false
		}
	}
	return false
}

// A zero hash option passes the original message to a crypto.Signer.
func signsUnhashedMessage(call *ast.CallExpr, name func(ast.Node) string) bool {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Sign" || len(call.Args) != 3 {
		return false
	}
	option, ok := ast.Unparen(call.Args[2]).(*ast.CallExpr)
	if !ok || name(option.Fun) != "crypto.Hash" || len(option.Args) != 1 {
		return false
	}
	literal, ok := ast.Unparen(option.Args[0]).(*ast.BasicLit)
	if !ok || literal.Kind != token.INT {
		return false
	}
	value, err := strconv.ParseUint(literal.Value, 0, 64)
	return err == nil && value == 0
}

func primitiveModule(module string) bool {
	return module == "crypto/ed25519" || module == "golang.org/x/crypto/ed25519" || strings.HasPrefix(module, "filippo.io/edwards25519")
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
				if cryptoPrimitive(callee) {
					record(symbol, callee)
				} else if signsUnhashedMessage(n, name) {
					record(symbol, signerSign)
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

func checkPrimitiveUses(observed map[siteKey]map[string]int, exemptions []callExemption) []string {
	var errors []string
	matches := map[callKey]int{}
	for _, entry := range exemptions {
		key := callKey{siteKey{entry.File, entry.Symbol}, entry.Callee}
		if strings.TrimSpace(entry.File) == "" || strings.TrimSpace(entry.Symbol) == "" || strings.TrimSpace(entry.Callee) == "" || strings.TrimSpace(entry.Reason) == "" {
			errors = append(errors, "primitive exemption requires file, symbol, callee and reason")
			continue
		}
		if !cryptoPrimitive(entry.Callee) {
			errors = append(errors, "primitive exemption must name a call: "+key.String())
			continue
		}
		if _, found := matches[key]; found {
			errors = append(errors, "duplicate primitive exemption: "+key.String())
			continue
		}
		matches[key] = 0
	}
	for key, uses := range observed {
		// Raw signing, verification and profile checks live in signaturewire.
		shared := key.File == strictModule && (key.Symbol == "Verify" || key.Symbol == "SignBytes" || key.Symbol == "PrimePoint" || key.Symbol == "ValidIDSignatureShape")
		if shared {
			continue
		}
		for callee, count := range uses {
			call := callKey{key, callee}
			if _, found := matches[call]; found {
				matches[call] = count
			} else {
				errors = append(errors, "raw Go crypto must use the shared verifier: "+call.String())
			}
		}
	}
	for key, count := range matches {
		if count == 0 {
			errors = append(errors, "unused primitive exemption: "+key.String())
		} else if count != 1 {
			errors = append(errors, fmt.Sprintf("primitive exemption matches %d calls: %s", count, key))
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
		if e != nil {
			return nil, fmt.Errorf("cannot scan %s: %w", file, e)
		}
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

func checkListedFile(root, file string) error {
	if !filepath.IsLocal(file) || path.Clean(file) != file {
		return fmt.Errorf("listed source file must be a repository-relative path: %s", file)
	}
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(file)))
	if os.IsNotExist(err) {
		return fmt.Errorf("listed source file %s is missing", file)
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("listed source file %s must be a regular file", file)
	}
	return nil
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
	if coverage.PrimitiveGuard.ExemptCalls == nil {
		return fmt.Errorf("primitive_guard.exempt_calls must be an array")
	}
	var exemptions []callExemption
	for _, entry := range coverage.PrimitiveGuard.ExemptCalls {
		if strings.HasSuffix(entry.File, ".go") {
			if err := checkListedFile(root, entry.File); err != nil {
				return err
			}
			exemptions = append(exemptions, entry)
		}
	}
	for _, row := range coverage.CreationPaths {
		if row.Repo == "aweb" {
			for _, file := range row.Files {
				if strings.HasSuffix(file, ".go") {
					if err := checkListedFile(root, file); err != nil {
						return err
					}
				}
			}
		}
	}
	observed, err := scanRepository(root)
	if err != nil {
		return err
	}
	if errors := checkPrimitiveUses(observed, exemptions); len(errors) > 0 {
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
