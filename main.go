package main

import (
	"fmt"
)

func main() {
	fmt.Println("=== Passport PKI Demo Suite ===")
	fmt.Println()
	fmt.Println("This project demonstrates Service-as-Passport architecture with healthcare use cases.")
	fmt.Println("Please use one of the following demos:")
	fmt.Println()
	fmt.Println("🏗️ Service-to-Service Authentication Demo:")
	fmt.Println("   go run cmd/s2s-authn-demo/main.go")
	fmt.Println()
	fmt.Println("� Service-to-Service Authentication + User Authorization Demo:")
	fmt.Println("   go run cmd/s2s-authn-user-authz-demo/main.go")
	fmt.Println()
	fmt.Println("🔍 JWT Extractor Demo:")
	fmt.Println("   go run cmd/jwt-extractor-demo/main.go")
	fmt.Println()
	fmt.Println("📖 Documentation:")
	fmt.Println("   docs/ARCHITECTURE.md - Detailed architecture")
	fmt.Println("   DEMOS.md - Demo descriptions and instructions")
	fmt.Println("   cmd/ - Command-line demos and tools")
	fmt.Println()
	fmt.Println("For more information, see the README.md file.")
}
