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
	"go/constant"
	"go/token"
	//"crypto/dsa"

	"github.com/praetorian-inc/gokart/run"	//wening
	"github.com/praetorian-inc/gokart/util"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// RSAKeyLenAnalyzer is used to resolve constant values used for RSA key generation in order to more accurately
// detect use of an insecure RSA key length constructed
// all variables are converted to SSA form and a call graph is constructed
// recursive analysis is then used to resolve variables used as a key length to a final constant value at the callsite
var DsaKeylenAnalyzer = &analysis.Analyzer{
	Name:     "dsa",
	Doc:      "reports dsa ",
	Run:      dsaRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

const DSA_RECOMMENDED_KEYLEN = 1	//dsa.L1024N160 = iota

// DsakParameterFuncs() 检查长度
func DsakParameterFuncs() map[string][]string {
	return map[string][]string{
		"crypto/dsa": {"GenerateParameters"},	//第三个参数
	}
}
// DsakRandFuncs() 可能会没使用rand，比如写成nil 检查rand
func DsakRandFuncs() ([]int, map[string][]string) {
	return  []int{1,1,0},
	map[string][]string{
		"crypto/dsa": {"GenerateParameters", "GenerateKey", "Sign"},	//第几个参数(从零计数)：2，2，1
	}
}
// sourceDesFuncs() 正确使用rand标记——反向警告
func sourceDesGlobalVars() map[string][]string {
	return map[string][]string{
		"crypto/rand": {"Reader"},
	}
}

// DsaEvalConst attempts to take a value, and simplify it down to a single constant
// it returns a tuple of (the constant, whether or not it successfully simplified)
func DsaEvalConst(expr ssa.Value, cg util.CallGraph) (*ssa.Const, bool) {

	switch expr := expr.(type) {

	case *ssa.Const:
		return expr, true
	case *ssa.BinOp:
		X, okX := DsaEvalConst(expr.X, cg)
		Y, okY := DsaEvalConst(expr.Y, cg)

		if okX && okY {
			return dsa_merge(X, Y, expr)
		}
	case *ssa.Call:
		if dest := expr.Common().StaticCallee(); dest != nil {
			rets := util.ReturnValues(dest)
			if len(rets) == 1 && len(rets[0]) == 1 {
				return DsaEvalConst(rets[0][0], cg)
			}
		}
	case *ssa.Parameter:
		var values []*ssa.Value
		values = cg.ResolveParam(expr)
		return DsaEvalConst(*values[0], cg)

	case *ssa.Phi:
		var res bool
		var val *ssa.Const
		val, res = DsaEvalConst(expr.Edges[0], cg)

		for _, edge := range expr.Edges {
			var tmp *ssa.Const
			var tmp2 bool
			tmp, tmp2 = DsaEvalConst(edge, cg)
			if tmp.Int64() < val.Int64() {
				val = tmp //val ends up being the shortest value that this phi node could be
			}
			res = res && tmp2 //res is whether or not the boolean expr could be evaluated
		}
		return val, res
	}

	return nil, false
}

// Merge dsa_merges two Consts to a BinOp
func dsa_merge(x, y *ssa.Const, op *ssa.BinOp) (*ssa.Const, bool) {
	switch op.Op {
	case token.ADD, token.SUB, token.MUL:
		return ssa.NewConst(constant.BinaryOp(x.Value, op.Op, y.Value), x.Type()), true
	case token.QUO:
		return ssa.NewConst(constant.BinaryOp(x.Value, token.QUO_ASSIGN, y.Value), x.Type()), true

	}
	return nil, false
}

// dsa_keylen_check recursively checks if a vulnerable function that relies on RSA is using a number of bits that is less than DSA_RECOMMENDED_KEYLEN
func dsa_keylen_check(pass *analysis.Pass, keylen ssa.Value, cg util.CallGraph) bool {
	unsafe := false
	//fmt.Println("______",keylen,"__________")
	//暂不知其他功能，目前仅用到了 1、4
	switch keylen := keylen.(type) {
	case *ssa.Const:		//该参数为数值（无论别名多少次，只要这里的类型是数值即可检测）
		fmt.Println("1 - ",unsafe)
		real_len := keylen.Int64()
		if real_len < DSA_RECOMMENDED_KEYLEN {
			unsafe = true
		}
	case *ssa.Phi:
		//fmt.Println("2 - ",unsafe)
		for _, edge := range keylen.Edges {
			if keylen != edge {
				unsafe = unsafe || dsa_keylen_check(pass, edge, cg)
			}
		}
	case *ssa.BinOp:
		//fmt.Println("3 - ",unsafe)
		if val, ok := DsaEvalConst(keylen, cg); ok {
			unsafe = dsa_keylen_check(pass, val, cg)
		}
	case *ssa.Call:		//该参数为函数体（即，需要调用获取），可多次迭代
		fmt.Println("4 - ",unsafe)
		if dest := keylen.Common().StaticCallee(); dest != nil {
			returns := util.ReturnValues(dest)
			for _, retval := range returns {
				unsafe = unsafe || dsa_keylen_check(pass, retval[0], cg)
			}
		}
	case *ssa.Parameter:
		//fmt.Println("5 - ",unsafe)
		var values []*ssa.Value
		values = cg.ResolveParam(keylen)
		if len(values) > 0 {
			unsafe = unsafe || dsa_keylen_check(pass, *values[0], cg)
		}
	}
	return unsafe
}

// dsaRun runs the dsa keylength analyzer
func dsaRun(pass *analysis.Pass) (interface{}, error) {

	results := []util.Finding{}
	// Builds SSA model of Go code
	//ssa_functions := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs

	// Creates call graph of function calls
	call_graph := make(util.CallGraph)

	// Fills in call graph
	call_graph = run.CG //wening

	//这里是检查全局变量！！—— rand.Reader	不是检查函数调用
	VulnGlobalVars_temp := util.VulnGlobalVars
	util.VulnGlobalVars = make(map[string][]string)
	util.VulnGlobalVars = sourceDesGlobalVars()

	// Grabs vulnerable functions to scan for
	vuln_dsa_key_funcs := DsakParameterFuncs()
	parameter_i, vuln_dsa_rand_funcs := DsakRandFuncs()

	// Iterate over every specified vulnerable package	//key length
	for pkg, funcs := range vuln_dsa_key_funcs {

		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {

			// Construct full name of function
			current_function := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range call_graph[current_function] {

				// Check if argument of vulnerable function has keylen that is less than DSA_RECOMMENDED_KEYLEN
				//taintAnalyzer := util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				//var taintSource []util.TaintedCode

				if dsa_keylen_check(pass, vulnFunc.Instr.Call.Args[2], call_graph) {
					message := fmt.Sprint("Danger: DSA key length is too short, recommend dsa.L1024N160")
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					results = append(results, util.MakeFinding(message, targetFunc, nil, "CWE-xxx: warning L1024N160"))
				}
			}
		}
	}

	/* rand可能写成了nil*/
	// Iterate over every specified vulnerable package
	for pkg, funcs := range vuln_dsa_rand_funcs {

		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {

			// Construct full name of function
			current_function := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for i, vulnFunc := range call_graph[current_function] {
				// vulnFunc.Fn.String() 记录了上面 sink 所属的调用方法名

				parameterI := parameter_i[i]	//记录哪个函数检查哪个参数

				taintAnalyzer := util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[parameterI], call_graph) {	//wening 检测到，说明rand调用是对的，匹配到优秀的随机数生成器
					//fmt.Println("来证明是对的！！")
				} else {	//wening rand调用错误，没有匹配到优秀的随机数生成器
					//fmt.Println("来证明是错的！！")
					message := "Danger: Don't use incorrect rand generation if DSA is used "
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					results = append(results, util.MakeFinding(message, targetFunc, nil, "CWE-xxx: DSA is not randomly"))
				}
			}
		}
	}

	//恢复数据，测试
	util.VulnGlobalVars = VulnGlobalVars_temp
	return results, nil
}
