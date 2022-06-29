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

package path_traversal

// zero vulns should be reported

import (
	"os"
)

func getFile6(temp string) string {
	tmp := "./list1/images/"
	DirTraversal8(tmp, "test")
	return "str"
}

func DirTraversal8(folderPath string, path2 string) {
	f, _ := os.Create(folderPath + path2 + "so" + "many" + "params!")
	f.Close()
}
