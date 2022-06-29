// Copyright 2021 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analyzers

import (
"fmt"
	"github.com/praetorian-inc/gokart/run"	//wening
	"github.com/praetorian-inc/gokart/util"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

// AESKeyLenAnalyzer
var AesKeylenAnalyzer = &analysis.Analyzer{
	Name:     "aes_cbc",
	Doc:      "aes-cbc is wrong",
	Run:      aesRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// sinkAesFuncs() returns a map of functions that CBC
func sinkAesCBCFuncs() map[string][]string {
	return map[string][]string{
		"crypto/cipher": {"NewCBCEncrypter"},	//第一个参数
	}
}
// sinkAesFuncs() returns a map of functions that CTR
func sinkAesCTRFuncs() map[string][]string {
	return map[string][]string{
		"crypto/cipher": {"NewCTR"},	//第一个参数
	}
}
// sourceAesFuncs() returns a map of functions that CBC
func sourceAesFuncs() map[string][]string {
	return map[string][]string{
		"crypto/aes": {"NewCipher"},
		"crypto/rand": {"Read"},
		"math/rand": {"Read", "Intn", "Int", "Int63", "Int31", "Int31n", "Int63n"},
	}
}
// filtersAesFuncs() returns a map of functions that CBC
func filtersAesFuncs() map[string][]string {
	return map[string][]string{
		"io": {"ReadFull"},
	}
}


// rsaRun runs the rsa keylength analyzer
func aesRun(pass *analysis.Pass) (interface{}, error) {

	results := []util.Finding{}

	// Creates call graph of function calls
	call_graph := make(util.CallGraph)

	// Fills in call graph
	call_graph = run.CG //wening

	//暂存数据，测试
	VulnGlobalFuncs_temp := util.VulnGlobalFuncs
	util.VulnGlobalFuncs = make(map[string][]string)
	util.VulnGlobalFuncs = sourceAesFuncs()

	//设置过滤数据
	util.FiltersGlobalFuncs = make(map[string][]string)
	util.FiltersGlobalFuncs = filtersAesFuncs()

	// Grabs vulnerable functions to scan for
	vuln_aes_CBC_funcs := sinkAesCBCFuncs()

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vuln_aes_CBC_funcs {

		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {

			// Construct full name of function
			current_function := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range call_graph[current_function] {
				// vulnFunc.Fn.String() 记录了上面 sink 所属的调用方法名

				taintAnalyzer := util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				var taintSource []util.TaintedCode
				if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[0], call_graph) {
					message := "Danger: Don't use the operation mode CBC if AES is used "
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					taintSource = taintAnalyzer.TaintSource
					results = append(results, util.MakeFinding(message, targetFunc, taintSource, "new wrong"))
				}
				fmt.Println("----------------")
				taintAnalyzer = util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[1], call_graph) {	//wening iv随机性不强，匹配到不够优秀的随机数生成器
					message := "Danger: Don't use incorrect IV if AES is used "
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					taintSource = taintAnalyzer.TaintSource
					results = append(results, util.MakeFinding(message, targetFunc, taintSource, "CWE-329: Generation of Predictable IV with CBC Mode"))
				} else if util.CallFlat {	//wening iv不随机，没有匹配到随机性不强的生成器，也没有过滤正确的随机数生成器，即未进行随机化，或者自实现了随机性，这也不安全
					fmt.Println("util.CallFlat = ", util.CallFlat)
					message := "Danger: Don't use incorrect IV"
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					results = append(results, util.MakeFinding(message, targetFunc, nil, "CWE-xxx: Generation of Constant IV with CBC Mode"))
				}
			}
		}
	}

	// Grabs vulnerable functions to scan for
	vuln_aes_CTR_funcs := sinkAesCTRFuncs()

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vuln_aes_CTR_funcs {

		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {

			// Construct full name of function
			current_function := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range call_graph[current_function] {

				taintAnalyzer := util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				var taintSource []util.TaintedCode
				if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[0], call_graph) {
					message := "Danger: Don't use the operation mode CTR if AES is used "
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					taintSource = taintAnalyzer.TaintSource
					results = append(results, util.MakeFinding(message, targetFunc, taintSource, "new wrong"))
				}
			}
		}
	}

	//恢复数据，测试
	util.VulnGlobalFuncs = VulnGlobalFuncs_temp
	return results, nil
}
