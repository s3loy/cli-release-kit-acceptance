package main
import("fmt";"os";"encoding/json")
func main(){if len(os.Args)>1 && os.Args[1]=="--json" {json.NewEncoder(os.Stdout).Encode(map[string]any{"message":"chirp","ok":true})} else {fmt.Println("go-demo 0.8.1")}}
