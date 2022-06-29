package analyzers

import (
	"github.com/1047261438/cryptogo/util"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"

	"fmt"
	"strings"
	"strconv"
	"golang.org/x/tools/go/ssa"

)

var TLSAnalyzer = &analysis.Analyzer{
	Name:     "tls_crypto",
	Doc:      "reports when weak tls is used",
	Run:      tlsRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

type FuncContent struct {
	Method string
	Attr map[string][]int
}
type FuncCheck map[string][]FuncContent
func tlsFuncsT() FuncCheck {
	return FuncCheck{
		"crypto/tls": []FuncContent{
			{
				Method: "Config",
				Attr: map[string][]int{
					"MinVersion":{769,770,771,772},
					"CipherSuites":{5,10,47,53,61,156,157,49171,49173,49174,49175,49176,49177,49178,49187,49191,22016},
					"InsecureSkipVerify": {1},
				},
			},
		},
	}
}


func (fc FuncCheck) AnalyzeFunction(fn *ssa.Function){
	fc = tlsFuncsT()
	funcFlat := make(map[string]string)
	for _, block := range fn.DomPreorder() {
		for _, instr := range block.Instrs {
			switch instr := instr.(type) {
			case *ssa.Alloc:
				for funcKey, funcVal := range fc {
					for _, funcContent := range funcVal {
						funcName := funcKey + "." + funcContent.Method

						if(strings.Contains(instr.String(),funcName)) {
							for _, re := range *instr.Referrers() {
								nRe := strings.Fields(re.String())
								newRe := strings.Trim(nRe[0], "&"+instr.Name()+".")
								val,ok := funcContent.Attr[newRe]
								if(ok&&val[0] == 1){
									funcFlat[re.String()] = "true"
								} else if(ok) {
									funcFlat[re.String()] = "uint16"
								}
							}
						}
					}
				}
			case *ssa.FieldAddr:
				if(funcFlat[instr.String()] == "true") {
					fmt.Printf("\033[1;37;42m%s\033[0m\n","Insecure：")
					fmt.Println(instr.String(), "Referrers：",(*instr.Referrers()))
				} else if(funcFlat[instr.String()] == "uint16") {
					for _, re := range *instr.Referrers() {
						funcFlat[re.String()] = "uint16"
						if(strings.Contains((*instr.Referrers())[0].String(),"769")) {
							fmt.Printf("\033[1;37;41m%s\033[0m\n","TLS1.0：")
							fmt.Println(instr.String(), "Referrers：",(*instr.Referrers()))
						} else if(strings.Contains((*instr.Referrers())[0].String(),"770")) {
							fmt.Printf("\033[1;37;44m%s\033[0m\n","TLS1.1：")
							fmt.Println(instr.String(), "Referrers：",(*instr.Referrers()))
						} else if(strings.Contains((*instr.Referrers())[0].String(),"771")) {
							fmt.Printf("\033[1;37;45m%s\033[0m\n","TLS1.2：")
							fmt.Println(instr.String(), "Referrers：",(*instr.Referrers()))
						} else if(strings.Contains((*instr.Referrers())[0].String(),"772")) {
							fmt.Printf("\033[1;37;46m%s\033[0m\n","TLS1.3：")
							fmt.Println(instr.String(), "Referrers：",(*instr.Referrers()))
						} else {
							funcFlat["CipherSuites"] = "uint16"
						}
					}
				}
			case *ssa.IndexAddr:
				if(funcFlat["CipherSuites"] == "uint16") {
					for _, funcVal := range fc {
						for _, funcContent := range funcVal {
							for _, attr := range funcContent.Attr["CipherSuites"] {
								s := "*" + instr.Name() + " = " + strconv.Itoa(attr) + ":uint16"
								if(strings.Contains((*instr.Referrers())[0].String(),s)) {
									fmt.Printf("\033[1;37;43m%s\033[0m\n","CipherSuites: ")
									fmt.Println(instr.String(), "Name = ",instr.X.Name(), "Referrers：",instr.Referrers())
								}
							}
						}
					}
				}
			case *ssa.Store:
				if(funcFlat[instr.String()] == "uint16") {
					_ = funcFlat["CipherSuites"] == "null"
				}
			default:
			}
		}
	}
}



// tlsRun runs the weakcrypto analyzer
func tlsRun(pass *analysis.Pass) (interface{}, error) {
	results := []util.Finding{}

	// Creates call graph of function calls
	cf := make(FuncCheck)

	// Fills in call graph
	// Builds SSA model of Go code
	ssa_functions := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs
	for _, fn := range ssa_functions {
		cf.AnalyzeFunction(fn)
	}

	return results, nil
}