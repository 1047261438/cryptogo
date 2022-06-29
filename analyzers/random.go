package analyzers

import (
	"github.com/1047261438/cryptogo/run"
	"github.com/1047261438/cryptogo/util"
"fmt"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

// AESKeyLenAnalyzer
var RandomAnalyzer = &analysis.Analyzer{
	Name:     "random",
	Doc:      "random generation is not correct",
	Run:      randomRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// sinkRandomFuncs() returns a map of functions that CBC
func sinkRandomFuncs() (map[string][]int, map[string][]string, map[string]string) {
	return  map[string][]int{
			"crypto/cipher": {1,1,1,1},
			"crypto/rsa": {1, 0, 0, 0},
			"crypto/dsa": {1, 1, 0},
			"crypto/ecdsa": {0, 0, 1},
			"golang.org/x/crypto/argon2": {1, 1},
			"golang.org/x/crypto/hkdf": {2},
			"golang.org/x/crypto/pbkdf2": {1},
			"golang.org/x/crypto/scrypt": {1},
			"crypto/aes": {0},
		}, map[string][]string{
			"crypto/cipher": {"NewCBCEncrypter", "NewCFBEncrypter", "NewCTR", "NewOFB"},
			"crypto/rsa": {"EncryptOAEP", "SignPSS", "GenerateKey", "GenerateMultiPrimeKey"},
			"crypto/dsa": {"GenerateKey", "GenerateParameters", "Sign"},
			"crypto/ecdsa": {"Sign", "SignASN1", "GenerateKey"},
			"golang.org/x/crypto/argon2": {"IDKey", "Key"},
			"golang.org/x/crypto/hkdf": {"New"},
			"golang.org/x/crypto/pbkdf2": {"Key"},
			"golang.org/x/crypto/scrypt": {"Key"},
			"crypto/aes": {"NewCipher"},
		} , map[string]string{
			"crypto/cipher": "IV is not random",
			"crypto/rsa": "rsa is not configured with prng",
			"crypto/dsa": "dsa is not configured with prng",
			"crypto/ecdsa": "ecdsa is not configured with prng",
			"golang.org/x/crypto/argon2": "argon2-salt is not random",
			"golang.org/x/crypto/hkdf": "hkdf-salt is not random",
			"golang.org/x/crypto/pbkdf2": "pbkdf2-salt is not random",
			"golang.org/x/crypto/scrypt": "scrypt-salt is not random",
			"crypto/aes": "AES-key is not random",
		}
}
// sourceRandomFuncs() returns a map of functions that CBC
func sourceRandomFuncs() map[string][]string {
	return map[string][]string{
		"math/rand": {"Read", "Intn", "Int", "Int63", "Int31", "Int31n", "Int63n", "Seed"},
		"encoding/hex": {"DecodeString"},
	}
}
// filtersRandomFuncs() returns a map of functions that CBC
func filtersRandomFuncs() map[string][]string {
	return map[string][]string{
		"crypto/rand": {"Read", "Reader"},
		"io": {"ReadFull"},

		"crypto/md5": {"New", "Sum"},
		"crypto/sha1": {"New", "Sum"},
		"crypto/sha256": {"New224", "Sum224", "New", "Sum256"},
		"crypto/sha512": {"New", "Sum512", "New384", "Sum384", "New512_224", "Sum512_224", "New512_256", "Sum512_256"},
		"golang.org/x/crypto/sha3": {"New224", "Sum224", "New256", "New384", "New512",  "Sum256", "Sum384", "Sum512",
			"NewLegacyKeccak256", "NewLegacyKeccak512", "ShakeSum128", "ShakeSum256"},
		"golang.org/x/crypto/argon2": {"IDKey", "Key"},
		"golang.org/x/crypto/hkdf": {"New"},
		"golang.org/x/crypto/pbkdf2": {"Key"},
		"golang.org/x/crypto/scrypt": {"Key"},
	}
}

func randomRun(pass *analysis.Pass) (interface{}, error) {

	results := []util.Finding{}

	// Creates call graph of function calls
	call_graph := make(util.CallGraph)

	// Fills in call graph
	if !run.CGFlat {	//wening
		// Builds SSA model of Go code
		ssa_functions := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs

		for _, fn := range ssa_functions {
			call_graph.AnalyzeFunctionO(fn)
		}
		run.CG = call_graph
	} else {
		call_graph = run.CG
	}

	VulnGlobalFuncs_temp := util.VulnGlobalFuncs
	util.VulnGlobalFuncs = make(map[string][]string)
	util.VulnGlobalFuncs = sourceRandomFuncs()

	util.FiltersGlobalFuncs = make(map[string][]string)
	util.FiltersGlobalFuncs = filtersRandomFuncs()

	// Grabs vulnerable functions to scan for
	vuln_random_parameter, vuln_random_funcs, wOutput := sinkRandomFuncs()

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vuln_random_funcs {
		parameter := vuln_random_parameter[pkg]

		// Iterate over every specified vulnerable function per package
		for i, fn := range funcs {
			parameterI := parameter[i]

			// Construct full name of function
			current_function := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range call_graph[current_function] {

				taintAnalyzer := util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				var taintSource []util.TaintedCode
				if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[parameterI], call_graph) {
					message := "Danger: Don't generate or use a predictable initialization Vector (IV) with Cipher Block Chaining (CBC) Mode"
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					taintSource = taintAnalyzer.TaintSource
					results = append(results, util.MakeFinding(message, targetFunc, taintSource, wOutput[pkg]))
				} else if util.CallFlat {
					s := pkg
					if(s=="crypto/cipher") {
						s = current_function
					}
					output := "Generation of Constant IV/key ----" + s
					message := "Danger: Don't use Constant IV"
					if !util.Cwelist[output] {
						util.Cwelist[output] = true
					}
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					results = append(results, util.MakeFinding(message, targetFunc, taintSource, output))
				} else { fmt.Println("Filter: ")
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					taintSource = taintAnalyzer.TaintSource
					fmt.Println(targetFunc,"\n",taintSource)
				}
			}
		}
	}

	util.VulnGlobalFuncs = VulnGlobalFuncs_temp
	return results, nil
}
