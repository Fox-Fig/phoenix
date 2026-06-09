package main

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"

	"phoenix/pkg/config"
)

func main() {
	fmt.Println("Generating configuration examples...")

	serverExample := generateExample(reflect.TypeOf(config.ServerConfig{}), "Server")
	err := ioutil.WriteFile("examples_server.toml", []byte(serverExample), 0644)
	if err != nil {
		fmt.Printf("Failed to write examples_server.toml: %v\n", err)
	} else {
		fmt.Println("Generated examples_server.toml")
	}

	clientExample := generateExample(reflect.TypeOf(config.ClientConfig{}), "Client")
	err = ioutil.WriteFile("examples_client.toml", []byte(clientExample), 0644)
	if err != nil {
		fmt.Printf("Failed to write examples_client.toml: %v\n", err)
	} else {
		fmt.Println("Generated examples_client.toml")
	}
}

func generateExample(t reflect.Type, title string) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("# Auto-generated %s Configuration Example\n", title))
	builder.WriteString("# --------------------------------------------------------\n\n")

	parseStruct(t, &builder, "", false)

	return builder.String()
}

func parseStruct(t reflect.Type, builder *strings.Builder, prefix string, inArray bool) {
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

		if field.Anonymous {
			fieldType := field.Type
			if fieldType.Kind() == reflect.Ptr {
				fieldType = fieldType.Elem()
			}
			parseStruct(fieldType, builder, prefix, inArray)
			continue
		}

		if tomlTag == "" || tomlTag == "-" {
			continue
		}

		if groupTag != "" {
			builder.WriteString(fmt.Sprintf("\n# ═══════════════════════════════════════════════════════════\n"))
			builder.WriteString(fmt.Sprintf("#  %s\n", groupTag))
			builder.WriteString(fmt.Sprintf("# ═══════════════════════════════════════════════════════════\n"))
		}

		parts := strings.Split(tomlTag, ",")
		key := parts[0]

		fieldType := field.Type
		if fieldType.Kind() == reflect.Ptr {
			fieldType = fieldType.Elem()
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
			builder.WriteString(fmt.Sprintf("%s[%s]\n", prefix, key))
			parseStruct(fieldType, builder, prefix, false)
			builder.WriteString("\n")
		} else if fieldType.Kind() == reflect.Slice && fieldType.Elem().Kind() == reflect.Struct {
			builder.WriteString(fmt.Sprintf("%s[[%s]]\n", prefix, key))
			parseStruct(fieldType.Elem(), builder, prefix, true)
			builder.WriteString("\n")
		} else {
			// Basic types
			var valStr string
			if defaultTag != "" {
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
