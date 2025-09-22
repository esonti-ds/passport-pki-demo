package main

import (
	"fmt"
)

func main() {
	fmt.Println("=== Passport PKI Demo Suite ===")
	fmt.Println()
	fmt.Println("This project has been refactored into organized command-line tools.")
	fmt.Println("Please use one of the following commands:")
	fmt.Println()
	fmt.Println("📚 Basic PKI Certificate Chain Demo:")
	fmt.Println("   go run cmd/basic-demo/main.go")
	fmt.Println()
	fmt.Println("🚀 Enhanced Demo with User JWT Embedding:")
	fmt.Println("   go run cmd/enhanced-demo/main.go")
	fmt.Println()
	fmt.Println("🔍 JWT Inspector Tool:")
	fmt.Println("   go run cmd/jwt-inspector/main.go")
	fmt.Println()
	fmt.Println("📖 Documentation:")
	fmt.Println("   docs/ARCHITECTURE.md - Detailed architecture")
	fmt.Println("   examples/ - Example code and demonstrations")
	fmt.Println()
	fmt.Println("For more information, see the README.md file.")
}
