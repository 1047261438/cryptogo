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

var CallFlat bool
var AESFlat bool
var DESFlat bool
var StringFlat bool

// ContainsTaint analyzes the ssa.Value, recursively traces the value to all possible sources, and returns True if any of the sources are vulnerable. It returns False otherwise.
func (ta *TaintAnalyzer) ContainsTaint(startCall *ssa.CallCommon, val *ssa.Value, cg CallGraph) bool {
	CallFlat = true
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

	switch expr := (*val).(type) {
	case *ssa.Const:
		if StringFlat == true {
			vulnerable = true
		} else {
			vulnerable = false
		}
	case *ssa.Parameter:
		// Check if this function call is part of the tainted function source list
		globalPkgName := (expr).Parent().Pkg.Pkg.Name()
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
		vulnerable = false
	case *ssa.Function:
		vulnerable = false
		pac := expr.Package()	//*Package
		if pac != nil {
			path := (*pac).Pkg.Path()	//*types.Package.Path()
			val, ok := VulnGlobalFuncs[path]
			if ok {
				for _, funcName := range val {
					if expr.Name() == funcName {
						vulnerable = true
					}
				}
			}
		}
	case *ssa.Field:
		vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.Next:
		vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.Iter, cg, depth+1, visitedMutable)
	case *ssa.TypeAssert:
		vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.Range:
		vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.Phi:
		mapping := MapData{Mapped: true, Vulnerable: false}
		ta.taint_map[SSAvalToHash(val)] = mapping
		for _, edge := range (*expr).Edges {
			// this if statement is to prevent infiinite loop
			if edge != expr {
				vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &edge, cg, depth+1, visitedMutable)
			}
		}
	case *ssa.UnOp:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.BinOp:
		if (strings.Contains(expr.String(),"io.ReadFull") == true) {
			vulnerable = true
		} else {
			vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable) || ta.ContainsTaintRecurse(startCall, &expr.Y, cg, depth+1, visitedMutable)
		}
	case *ssa.Extract:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.Tuple, cg, depth+1, visitedMutable)
	case *ssa.Call:
		callFunc, ok := (expr.Call.Value).(*ssa.Function)
		if ok {
			globalPkgNamePart := callFunc.Pkg.Pkg.Name()	//package name
			if(globalPkgNamePart == "aes") {
				AESFlat =true
				fmt.Println("************", globalPkgNamePart)
			}else if(globalPkgNamePart == "des") {
				DESFlat =true
				fmt.Println("************", globalPkgNamePart)
			}
			globalPkgName := callFunc.Pkg.Pkg.Path()	//package path
			if val, ok := VulnGlobalFuncs[globalPkgName]; ok {
				for _, funcName := range val {
					if callFunc.Name() == funcName {
						vulnerable = true
					}
				}
			}
			if val, ok := FiltersGlobalFuncs[globalPkgName]; ok {
				for _, funcName := range val {
					if callFunc.Name() == funcName {
						vulnerable = false
						CallFlat = false
						break
					}
				}
			}
		}
		if dest := expr.Common().StaticCallee(); dest != nil && CallFlat {
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
		} else if CallFlat {
			for _, arg := range expr.Call.Args {
				vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &arg, cg, depth+1, visitedMutable) //loop C
			}
			ta.pass.Reportf(ta.location, "Warning: Couldn't evaluate function statically")
		}
	case *ssa.Slice:
		valSlice := ssa.Slice(*expr)
		valSliceX := valSlice.X
		vulnerable = ta.ContainsTaintRecurse(startCall, &valSliceX, cg, depth+1, visitedMutable) //loop D
		refs := valSlice.Referrers()
		for _, ref := range *refs {
			expr, isVal := ref.(ssa.Value)
			if isVal && CallFlat {
				newMutable := make([]ssa.Value, len(visitedMutable)+1)
				copy(newMutable, visitedMutable)
				newMutable = append(newMutable, *val)
				vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr, cg, depth+1, newMutable)
			}
		}
	case *ssa.MakeSlice:
		// MakeSlice is only used for new allocations and, as such, is
		// inherently safe.
		vulnerable = false
	case *ssa.Convert:
		if strings.Contains(expr.String(),"\":string)") {
			StringFlat = true
		}
		if(AESFlat == true) {
			if(strings.Count(expr.X.Name(),"")-10 <= 16) {
				fmt.Println("16 ", expr.X.Name(), " : ", strings.Count(expr.X.Name(),""))
			} else if(strings.Count(expr.X.Name(),"")-10 <= 24) {
				fmt.Println("24 ", expr.X.Name(), " : ", strings.Count(expr.X.Name(),""))
			} else if(strings.Count(expr.X.Name(),"")-10 <= 32) {
				fmt.Println("32 ", expr.X.Name(), " : ", strings.Count(expr.X.Name(),""))
			}
			AESFlat = false
		}
		if(DESFlat == true) {
			if(strings.Count(expr.X.Name(),"")-10 < 32) {
				fmt.Println("EDE2 ", expr.X.Name(), " : ", strings.Count(expr.X.Name(),""))
			} else {
				fmt.Println("EDE3 ", expr.X.Name(), " : ", strings.Count(expr.X.Name(),""))
			}
			DESFlat = false
		}
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.ChangeType:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.MakeInterface:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.MakeMap:
		vulnerable = false
	case *ssa.MakeClosure:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.Fn, cg, depth+1, visitedMutable)
		for _, val := range expr.Bindings {
			vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &val, cg, depth+1, visitedMutable)
		}
	case *ssa.Lookup:
		// Traces not only the collection but also the source of the index
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable) || ta.ContainsTaintRecurse(startCall, &expr.Index, cg, depth+1, visitedMutable)
	case *ssa.Index:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable) || ta.ContainsTaintRecurse(startCall, &expr.Index, cg, depth+1, visitedMutable)
	case *ssa.ChangeInterface:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.IndexAddr:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.FieldAddr:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable)
	case *ssa.Alloc:
		if(AESFlat == true) {
			len,_ := strconv.Atoi(expr.String()[5:7])
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
			len,_ := strconv.Atoi(expr.String()[5:7])
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
		if Config.Debug {
			test := GenerateTaintedCode(ta.pass, (*val).Parent(), (*val).Pos())
			log.Println("Global variable found: ", test.SourceCode, " in file ", test.SourceFilename)
		}
		vulnerable = !Config.GlobalsSafe
		globalPkgName := (expr).Package().Pkg.Path()	//package path
		if val, ok := FiltersGlobalFuncs[globalPkgName]; ok {
			for _, funcName := range val {
				if (expr).Name() == funcName {
					vulnerable = false
					CallFlat = false
					break
				}
			}
		}
		if Config.Debug {
			log.Println("expr", expr, expr.Package())
			log.Println("gloablPkgName", globalPkgName, *val)
			log.Println(VulnGlobalVars)
		}

		if val, ok := VulnGlobalVars[globalPkgName]; ok {
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
		vulnerable = false
	default:
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
	return vulnerable
}