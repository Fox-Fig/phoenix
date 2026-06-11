package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"phoenix/pkg/config"
)

type Scenario struct {
	Name      string
	Title     string
	Protocol  string
	Overrides map[string]string // key is toml key (like "tls_mode") to default value
}

func main() {
	fmt.Println("Generating configuration examples...")
	os.MkdirAll("examples", 0755)

	// 1. Generate Full Files
	serverFull := generateExample(reflect.TypeOf(config.ServerConfig{}), "Server (Comprehensive)", "", nil)
	os.WriteFile("example_server.toml", []byte(serverFull), 0644)
	fmt.Println("Generated example_server.toml")

	clientFull := generateExample(reflect.TypeOf(config.ClientConfig{}), "Client (Comprehensive)", "", nil)
	os.WriteFile("example_client.toml", []byte(clientFull), 0644)
	fmt.Println("Generated example_client.toml")

	// 2. Generate Scenarios
	scenarios := []Scenario{
		{
			Name:     "client_http1_cdn",
			Title:    "Client - HTTP/1 Camouflage via CDN",
			Protocol: "http1",
			Overrides: map[string]string{
				"remote_addr": `"your-cloudflare-domain.com:443"`,
				"tls_mode":    `"system"`,
			},
		},
		{
			Name:     "server_http1_cdn",
			Title:    "Server - HTTP/1 Camouflage via CDN (Flexible SSL)",
			Protocol: "http1",
			Overrides: map[string]string{
				"listen_addr": `":80"`,
				"allow_empty_sni": `true`,
			},
		},
		{
			Name:     "client_h2_mtls",
			Title:    "Client - H2 Transport with Strict mTLS",
			Protocol: "h2",
			Overrides: map[string]string{
				"private_key":       `"client.key"`,
				"server_public_key": `"server_pub_base64"`,
				"tls_mode":          `""`,
			},
		},
		{
			Name:     "server_h2_mtls",
			Title:    "Server - H2 Transport with Strict mTLS",
			Protocol: "h2",
			Overrides: map[string]string{
				"private_key":        `"server.key"`,
				"authorized_clients": `["client_pub_base64"]`,
			},
		},
		{
			Name:     "client_ssh",
			Title:    "Client - SSH Tunneling",
			Protocol: "ssh",
			Overrides: map[string]string{
			},
		},
		{
			Name:     "server_ssh",
			Title:    "Server - SSH Tunneling",
			Protocol: "ssh",
			Overrides: map[string]string{
				"enable_ssh": `true`,
			},
		},
	}

	for _, sc := range scenarios {
		var t reflect.Type
		if strings.HasPrefix(sc.Name, "server") {
			t = reflect.TypeOf(config.ServerConfig{})
		} else {
			t = reflect.TypeOf(config.ClientConfig{})
		}
		
		content := generateExample(t, sc.Title, sc.Protocol, sc.Overrides)
		filename := filepath.Join("examples", sc.Name+".toml")
		os.WriteFile(filename, []byte(content), 0644)
		fmt.Printf("Generated %s\n", filename)
	}
}

func generateExample(t reflect.Type, title string, targetProto string, overrides map[string]string) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("# Auto-generated %s Configuration Example\n", title))
	builder.WriteString("# --------------------------------------------------------\n\n")

	parseStruct(t, &builder, "", []string{}, false, targetProto, overrides)

	return builder.String()
}

func parseStruct(t reflect.Type, builder *strings.Builder, prefix string, path []string, inArray bool, targetProto string, overrides map[string]string) {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		tomlTag := field.Tag.Get("toml")
		docTag := field.Tag.Get("doc")
		groupTag := field.Tag.Get("group")
		defaultTag := field.Tag.Get("default")
		commentedTag := field.Tag.Get("commented")
		protocolTag := field.Tag.Get("protocol")

		if field.Anonymous {
			fieldType := field.Type
			if fieldType.Kind() == reflect.Ptr {
				fieldType = fieldType.Elem()
			}
			parseStruct(fieldType, builder, prefix, path, inArray, targetProto, overrides)
			continue
		}

		if tomlTag == "" || tomlTag == "-" {
			continue
		}
		parts := strings.Split(tomlTag, ",")
		key := parts[0]

		// Protocol Filtering
		if targetProto != "" && protocolTag != "" {
			validProtos := strings.Split(protocolTag, ",")
			match := false
			for _, p := range validProtos {
				if p == targetProto {
					match = true
					break
				}
			}
			if !match {
				continue // Skip this field entirely
			}
		}

		if groupTag != "" {
			builder.WriteString(fmt.Sprintf("\n# ═══════════════════════════════════════════════════════════\n"))
			builder.WriteString(fmt.Sprintf("#  %s\n", groupTag))
			builder.WriteString(fmt.Sprintf("# ═══════════════════════════════════════════════════════════\n"))
		}

		fieldType := field.Type
		if fieldType.Kind() == reflect.Ptr {
			fieldType = fieldType.Elem()
		}

		// Print visual badge if generating FULL example and field has specific protocol
		if targetProto == "" && protocolTag != "" {
			builder.WriteString(fmt.Sprintf("%s# [Requires Protocol: %s]\n", prefix, protocolTag))
		}

		if docTag != "" {
			lines := strings.Split(docTag, "\\n")
			for _, line := range lines {
				if inArray {
					builder.WriteString(fmt.Sprintf("%s  # %s\n", prefix, line))
				} else {
					builder.WriteString(fmt.Sprintf("%s# %s\n", prefix, line))
				}
			}
		}

		if fieldType.Kind() == reflect.Struct {
			newPath := append([]string{}, path...)
			newPath = append(newPath, key)
			pathStr := strings.Join(newPath, ".")
			builder.WriteString(fmt.Sprintf("%s[%s]\n", prefix, pathStr))
			parseStruct(fieldType, builder, prefix, newPath, false, targetProto, overrides)
			builder.WriteString("\n")
		} else if fieldType.Kind() == reflect.Slice && fieldType.Elem().Kind() == reflect.Struct {
			newPath := append([]string{}, path...)
			newPath = append(newPath, key)
			pathStr := strings.Join(newPath, ".")
			builder.WriteString(fmt.Sprintf("%s[[%s]]\n", prefix, pathStr))
			parseStruct(fieldType.Elem(), builder, prefix, newPath, true, targetProto, overrides)
			builder.WriteString("\n")
		} else {
			// Basic types
			var valStr string
			
			// Handle overrides
			if overrides != nil && overrides[key] != "" {
				valStr = overrides[key]
				commentedTag = "false" // force uncomment if overridden
			} else if defaultTag != "" {
				if fieldType.Kind() == reflect.String {
					valStr = fmt.Sprintf(`"%s"`, defaultTag)
				} else {
					valStr = defaultTag
				}
			} else {
				switch fieldType.Kind() {
				case reflect.String:
					valStr = `""`
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					valStr = "0"
				case reflect.Bool:
					valStr = "false"
				case reflect.Slice:
					valStr = "[]"
				default:
					valStr = `""`
				}
			}

			// If it's the transport protocol field, and targetProto is set, force the target protocol
			if key == "protocol" && targetProto != "" && (len(path) == 0 || (len(path) == 1 && path[0] == "outbound")) {
				valStr = fmt.Sprintf(`"%s"`, targetProto)
				commentedTag = "false"
			}

			commentPrefix := ""
			if commentedTag == "true" {
				commentPrefix = "# "
			}

			if inArray {
				builder.WriteString(fmt.Sprintf("%s  %s%s = %s\n\n", prefix, commentPrefix, key, valStr))
			} else {
				builder.WriteString(fmt.Sprintf("%s%s%s = %s\n\n", prefix, commentPrefix, key, valStr))
			}
		}
	}
}
