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

package util

import (
	"fmt"
	"go/token"
	"log"
	//"reflect"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"

	"golang.org/x/tools/go/ssa"
)

// TaintedCode is a struct that contains information about the vulnerable line of code
type TaintedCode struct {
	SourceCode     string
	SourceFilename string
	SourceLineNum  int
	ParentFunction string
}

//MapData is a struct that contains information about each hash
type MapData struct {
	Mapped     bool // whether a hash has already been mapped
	Vulnerable bool // whether a hash has been found vulnerable
	Count      int  // the number of times a hash has been visited
}

// TaintAnalyzer is a struct that contains information about each taint analyzer
type TaintAnalyzer struct {
	taint_map   map[uint64]MapData
	TaintSource []TaintedCode
	pass        *analysis.Pass
	location    token.Pos
}

// CreateTaintAnalyzer returns a new TaintAnalyzer struct
func CreateTaintAnalyzer(pass *analysis.Pass, location token.Pos) TaintAnalyzer {
	return TaintAnalyzer{
		make(map[uint64]MapData),
		[]TaintedCode{},
		pass,
		location,
	}
}

var CallFlat bool	//过滤标志 wening
var AESFlat bool	//过滤标志 wening
var DESFlat bool	//过滤标志 wening
var StringFlat bool	//过滤标志 wening

// ContainsTaint analyzes the ssa.Value, recursively traces the value to all possible sources, and returns True if any of the sources are vulnerable. It returns False otherwise.
func (ta *TaintAnalyzer) ContainsTaint(startCall *ssa.CallCommon, val *ssa.Value, cg CallGraph) bool {
	//fmt.Println("!!!",val)
	CallFlat = true	//过滤标志 wening
	return ta.ContainsTaintRecurse(startCall, val, cg, 0, []ssa.Value{})
}

func (ta *TaintAnalyzer) ContainsTaintRecurse(startCall *ssa.CallCommon, val *ssa.Value, cg CallGraph, depth int, visitedMutable []ssa.Value) bool {
	if *val == nil {
		return false
	}
	if Config.Debug {
		out := ""
		for i := 0; i < depth; i++ {
			out += "  "
		}
		log.Printf("%s%s (%T)\n", out, *val, *val)
	}

	call, isCall := (*val).(*ssa.Call)
	if isCall {
		//A function call cannot become tainted from itself This is due to a bug with how we handle referrers. Since we
		//check all function calls, past and future, we need to make sure to ignore the starting function call
		//This makes sure we dont duplicate findings by having one parameter infect other parameters
		if startCall == &call.Call {
			return false
		}
	}

	//We have already seen this buffer, assume its fine
	for _, visitedVal := range visitedMutable {
		if *val == visitedVal {
			return false
		}
	}

	// Memoize the ssa.Value
	map_status1 := ta.taint_map[SSAvalToHash(val)]
	ta.Memoize(val, map_status1.Vulnerable)
	// Store the memoization status in map_status
	map_status := ta.taint_map[SSAvalToHash(val)]

	// if the ssa.Value hash has been seen over fifty times, return false because it is likely an infinite loop
	if map_status.Count > 20 {
		if Config.Debug {
			log.Printf("Overflow detected, breaking the infinite loop")
		}

		return false
	}
	// if the ssa.Value hash has already been mapped, return it's vulnerable status
	if map_status.Mapped {
		return map_status.Vulnerable
	}

	//default set vulnerable to false, this may not be necessary anymore
	vulnerable := false

	//fmt.Println("值： ", reflect.TypeOf(*val), " --指令-- ", (*val).String())

	switch expr := (*val).(type) {
	case *ssa.Const:
		//fmt.Println("*ssa.Const -", vulnerable)
		if StringFlat == true {
			vulnerable = true
		} else {
			vulnerable = false
		}
	case *ssa.Parameter:
		//fmt.Println("*ssa.Parameter -", vulnerable)
		// Check if this function call is part of the tainted function source list
		globalPkgName := (expr).Parent().Pkg.Pkg.Name()
		//fmt.Println("globalPkgName:",globalPkgName)
		//fmt.Println("(expr).Name():",(expr).Name())
		//fmt.Println("(expr).Object().String():",(expr).Object().String())
		//fmt.Println("(expr).Object().Parent().Names():",(expr).Object().Parent().Names())
		/*if strings.Contains((expr).Object().Parent().Names()[0],"aes") {
			vulnerable = true
		}*/
		if val, ok := VulnGlobalFuncs[globalPkgName]; ok {
			for _, funcName := range val {
				if (expr).Name() == funcName {
					vulnerable = true
				}
			}
		}

		for pkg, types_ := range VulnTypes {
			for _, type_ := range types_ {
				if strings.TrimPrefix(expr.Type().String(), "*") == pkg+"."+type_ {
					vulnerable = true
				}
			}
		}

		var values []*ssa.Value
		values = cg.ResolveParam(expr)
		if len(values) > 0 {
			vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, values[0], cg, depth+1, visitedMutable) //loop B
		}
	case *ssa.FreeVar:
		//fmt.Println("*ssa.FreeVar -", vulnerable)
		vulnerable = false
	case *ssa.Function:
		//fmt.Println("*ssa.Function -", vulnerable)
		vulnerable = false
		pac := expr.Package()	//*Package
		if pac != nil {			//要判断空指针啊啊啊啊啊！！！
			path := (*pac).Pkg.Path()	//*types.Package.Path()
			val, ok := VulnGlobalFuncs[path]
			if ok {
				//fmt.Println("******expr******", expr.Package().Pkg.Path())
				for _, funcName := range val {
					if expr.Name() == funcName {
						vulnerable = true
						//fmt.Println("expr.Name():",expr.Name())
					}
				}
			}
		}
	case *ssa.Field:
		//fmt.Println("*ssa.Field -", vulnerable)
		vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.Next:
		//fmt.Println("*ssa.Next -", vulnerable)
		vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.Iter, cg, depth+1, visitedMutable)
	case *ssa.TypeAssert:
		//fmt.Println("*ssa.TypeAssert -", vulnerable)
		vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.Range:
		//fmt.Println("*ssa.Range -", vulnerable)
		vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.Phi:
		//fmt.Println("*ssa.Phi -", vulnerable)
		mapping := MapData{Mapped: true, Vulnerable: false}
		ta.taint_map[SSAvalToHash(val)] = mapping
		for _, edge := range (*expr).Edges {

			// this if statement is to prevent infiinite loop
			if edge != expr {
				vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &edge, cg, depth+1, visitedMutable)
			}
		}
	case *ssa.UnOp:
		//fmt.Println("*ssa.UnOp -", vulnerable)
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.BinOp:
		//fmt.Println("*ssa.BinOp -", vulnerable)

		if (strings.Contains(expr.String(),"io.ReadFull") == true) {
			vulnerable = true
		} else {
			vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable) || ta.ContainsTaintRecurse(startCall, &expr.Y, cg, depth+1, visitedMutable)
		}
	case *ssa.Extract:	//检测类似于 extract t6 #0 这样的汇编代码
		//fmt.Println("*ssa.Extract -", vulnerable)
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.Tuple, cg, depth+1, visitedMutable)
	case *ssa.Call:	//检测调用
		//fmt.Println("*ssa.Call -", vulnerable)
		//fmt.Println("Referrers", expr.Referrers())
		callFunc, ok := (expr.Call.Value).(*ssa.Function)
		if ok {
			globalPkgNamePart := callFunc.Pkg.Pkg.Name()	//package name —— 不带路径的包名
			if(globalPkgNamePart == "aes") {
				AESFlat =true
				fmt.Println("************", globalPkgNamePart)
			}else if(globalPkgNamePart == "des") {
				DESFlat =true
				fmt.Println("************", globalPkgNamePart)
			}
			globalPkgName := callFunc.Pkg.Pkg.Path()	//package path —— 带路径的包名	//wening
			//fmt.Println("******1******", globalPkgName)
			/*if strings.Contains(globalPkgName,"rand") {
				vulnerable = true
			}*/
			//fmt.Println("******2******", callFunc.Name())
			if val, ok := VulnGlobalFuncs[globalPkgName]; ok {	//VulnGlobalFuncs 是 加载的yml文件，函数调用部分
				for _, funcName := range val {
					if callFunc.Name() == funcName {
						vulnerable = true
					}
				}
			}
			if val, ok := FiltersGlobalFuncs[globalPkgName]; ok {	//FiltersGlobalFuncs 过滤
				for _, funcName := range val {
					if callFunc.Name() == funcName {	//有的话就不是漏洞
						//fmt.Println("看看对吗：",callFunc.Name())
						vulnerable = false
						CallFlat = false	//过滤标志 wening
						break
					}
				}
			}
		}
		if dest := expr.Common().StaticCallee(); dest != nil && CallFlat {	//过滤标志 wening
			returns := ReturnValues(dest)

			/* If return values of function can't be determined then we run under the assumption
			 * that if you can trust the arguments to the function, then you can trust the return value of the function.
			 */
			if len(returns) > 0 {

				for _, retval := range returns {
					if len(retval) > 0 {
						vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &retval[0], cg, depth+1, visitedMutable)
					}
				}
			} else {
				for _, arg := range expr.Call.Args {

					vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &arg, cg, depth+1, visitedMutable) //loop C
				}
			}
		} else if CallFlat {	//过滤标志 wening
			for _, arg := range expr.Call.Args {
				vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &arg, cg, depth+1, visitedMutable) //loop C
			}
			ta.pass.Reportf(ta.location, "Warning: Couldn't evaluate function statically")
		}
	case *ssa.Slice:
		//fmt.Println("*ssa.Slice -", vulnerable)
		valSlice := ssa.Slice(*expr)
		valSliceX := valSlice.X
		vulnerable = ta.ContainsTaintRecurse(startCall, &valSliceX, cg, depth+1, visitedMutable) //loop D
		refs := valSlice.Referrers()
		for _, ref := range *refs {
			expr, isVal := ref.(ssa.Value)
			if isVal && CallFlat {	//过滤标志 wening
				newMutable := make([]ssa.Value, len(visitedMutable)+1)
				copy(newMutable, visitedMutable)
				newMutable = append(newMutable, *val)
				vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr, cg, depth+1, newMutable)
			}
		}
	case *ssa.MakeSlice:
		//fmt.Println("*ssa.MakeSlice -", vulnerable)
		// MakeSlice is only used for new allocations and, as such, is
		// inherently safe.
		vulnerable = false
	case *ssa.Convert:	//
		//fmt.Println("*ssa.Convert -", vulnerable)
		if strings.Contains(expr.String(),"\":string)") {
			StringFlat = true
		}
		if(AESFlat == true) {
			if(strings.Count(expr.X.Name(),"")-10 <= 16) {
				fmt.Println("16 ", expr.X.Name(), " : ", strings.Count(expr.X.Name(),""))	//多10个字符
			} else if(strings.Count(expr.X.Name(),"")-10 <= 24) {
				fmt.Println("24 ", expr.X.Name(), " : ", strings.Count(expr.X.Name(),""))	//多10个字符
			} else if(strings.Count(expr.X.Name(),"")-10 <= 32) {
				fmt.Println("32 ", expr.X.Name(), " : ", strings.Count(expr.X.Name(),""))	//多10个字符
			}
			AESFlat = false
		}
		if(DESFlat == true) {
			if(strings.Count(expr.X.Name(),"")-10 < 32) {
				fmt.Println("EDE2 ", expr.X.Name(), " : ", strings.Count(expr.X.Name(),""))	//多10个字符
			} else {
				fmt.Println("EDE3 ", expr.X.Name(), " : ", strings.Count(expr.X.Name(),""))	//多10个字符
			}
			DESFlat = false
		}
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.ChangeType:
		//fmt.Println("*ssa.ChangeType -", vulnerable)
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.MakeInterface:
		//fmt.Println("*ssa.MakeInterface -", vulnerable)
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.MakeMap:
		//fmt.Println("*ssa.MakeMap -", vulnerable)
		vulnerable = false
	case *ssa.MakeClosure:
		//fmt.Println("*ssa.MakeClosure -", vulnerable)
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.Fn, cg, depth+1, visitedMutable)
		for _, val := range expr.Bindings {
			vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &val, cg, depth+1, visitedMutable)
		}
	case *ssa.Lookup:
		//fmt.Println("*ssa.Lookup -", vulnerable)
		// Traces not only the collection but also the source of the index
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable) || ta.ContainsTaintRecurse(startCall, &expr.Index, cg, depth+1, visitedMutable)
	case *ssa.Index:
		//fmt.Println("*ssa.Index -", vulnerable)
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable) || ta.ContainsTaintRecurse(startCall, &expr.Index, cg, depth+1, visitedMutable)
	case *ssa.ChangeInterface:
		//fmt.Println("*ssa.ChangeInterface -", vulnerable)
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.IndexAddr:
		//fmt.Println("*ssa.IndexAddr -", vulnerable)
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.FieldAddr:
		//fmt.Println("*ssa.FieldAddr -", vulnerable)
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.Alloc:
		//fmt.Println("*ssa.Alloc -", vulnerable)
		if(AESFlat == true) {
			len,_ := strconv.Atoi(expr.String()[5:7])	//小于10的内容截取带 ] ，无法转数字，得到0，符合<=16的要求
			if(len <= 16) {
				fmt.Println("[16] instr: ", expr.String())
			} else if(len <= 24) {
				fmt.Println("[24] instr: ", expr.String())
			} else if(len <= 32) {
				fmt.Println("[32] instr: ", expr.String())
			}
			AESFlat = false
		}
		if(DESFlat == true) {
			len,_ := strconv.Atoi(expr.String()[5:7])	//小于10的内容截取带 ] ，无法转数字，得到0，符合<=16的要求
			if(len < 32) {
				fmt.Println("[EDE2] instr: ", expr.String())
			} else {
				fmt.Println("[EDE3] instr: ", expr.String())
			}
			DESFlat = false
		}
		// Check all the references to this memory
		alloc_refs := expr.Referrers()
		vulnerable = false

		mapping := MapData{Mapped: true, Vulnerable: false}
		ta.taint_map[SSAvalToHash(val)] = mapping

		for alloc_item := range *alloc_refs {
			alloc_ref := (*alloc_refs)[alloc_item]

			switch instr := (alloc_ref).(type) {
			case *ssa.IndexAddr:
				for indexaddr_ref_idx := range *instr.Referrers() {
					indexaddr_ref := (*instr.Referrers())[indexaddr_ref_idx]
					switch instr2 := (indexaddr_ref).(type) {
					// If the variable is assigned to something else, check
					// the new assignment
					case *ssa.Store:
						if ta.ContainsTaintRecurse(startCall, &instr2.Val, cg, depth+1, visitedMutable) { //loop A -- I think this might be causing the problem
							vulnerable = true
						}
					}
				}

			case *ssa.FieldAddr:
				for _, ref := range *instr.Referrers() {
					expr, isStore := (ref).(*ssa.Store)
					if isStore {
						newMutable := make([]ssa.Value, len(visitedMutable)+1)
						copy(newMutable, visitedMutable)
						newMutable = append(newMutable, *val)
						vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.Val, cg, depth+1, newMutable)
					}
				}
			}

			var items []*ssa.Value
			operand_items := alloc_ref.Operands(items)
			for operand_idx := range operand_items {
				if ta.ContainsTaintRecurse(startCall, operand_items[operand_idx], cg, depth+1, visitedMutable) {
					vulnerable = true
				}
			}
		}
	case *ssa.Global:
		//fmt.Println("*ssa.Global -", vulnerable)
		if Config.Debug {
			test := GenerateTaintedCode(ta.pass, (*val).Parent(), (*val).Pos())
			log.Println("Global variable found: ", test.SourceCode, " in file ", test.SourceFilename)
		}
		vulnerable = !Config.GlobalsSafe
		//globalPkgName := (expr).Package().Pkg.Name()	//package name —— 不带路径的包名
		globalPkgName := (expr).Package().Pkg.Path()	//package path —— 带路径的包名	//wening
		//fmt.Println("这个是：globalPkgName = ", globalPkgName, " , VulnGlobalVars[globalPkgName] = ", VulnGlobalVars[globalPkgName])
		//fmt.Println("这个是：(expr).Name() = ", (expr).Name())
		if val, ok := FiltersGlobalFuncs[globalPkgName]; ok {	//FiltersGlobalFuncs 过滤
			for _, funcName := range val {
				if (expr).Name() == funcName {	//有的话就不是漏洞
					//fmt.Println("看看对吗：",(expr).Name())
					vulnerable = false
					CallFlat = false	//过滤标志 wening
					break
				}
			}
		}
		if Config.Debug {
			log.Println("expr", expr, expr.Package())
			log.Println("gloablPkgName", globalPkgName, *val)
			log.Println(VulnGlobalVars)
		}

		if val, ok := VulnGlobalVars[globalPkgName]; ok {	//yml文件中全局变量部分
			for _, funcName := range val {
				if (expr).Name() == funcName {
					if Config.Debug {
						log.Println(expr.Name())
						log.Println(funcName)
					}

					vulnerable = true
				}
			}
		}
	case nil:
		//fmt.Println("nil -", vulnerable)
		vulnerable = false
	default:
		//fmt.Println("default -", vulnerable)
		vulnerable = true
		if Config.Debug {
			log.Printf("Unknown SSA type found: %T\n", expr)
		}
	}

	// Memoize the ssa.Value along with whether or not it is vulnerable
	ta.Memoize(val, vulnerable)

	/* If the taint analysis reaches a vulnerable ssa.Value,
	 * then store the information about the state to display to the analyst as untrusted input.
	 */
	if vulnerable {
		tempTaintedCode := GenerateTaintedCode(ta.pass, (*val).Parent(), (*val).Pos())
		if tempTaintedCode.SourceLineNum > 0 {

			// Make sure that we don't output duplicate source code lines in Verbose Output
			duplicateSourceCode := false
			for _, current := range ta.TaintSource {
				if tempTaintedCode.SourceLineNum == current.SourceLineNum {
					duplicateSourceCode = true
					break
				}
			}

			if !duplicateSourceCode {
				ta.TaintSource = append(ta.TaintSource, tempTaintedCode)
			}
		}
	}
//fmt.Println("结果： ", vulnerable)
	return vulnerable
}