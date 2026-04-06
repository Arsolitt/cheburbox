// Package ruleset provides compilation of local sing-box rule-sets
// from JSON source format to binary .srs format.
package ruleset

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// Compile reads a JSON rule-set source and writes a binary .srs file.
// The input must be a valid sing-box rule-set JSON with a "rules" array.
// An optional "version" field controls the SRS format version; if omitted,
// RuleSetVersionCurrent is used.
func Compile(input []byte, outputPath string) error {
	var plainRuleSet option.PlainRuleSet
	if err := json.Unmarshal(input, &plainRuleSet); err != nil {
		return fmt.Errorf("parse rule-set JSON: %w", err)
	}

	version := extractVersion(input)
	if version == 0 {
		version = C.RuleSetVersionCurrent
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer outputFile.Close()

	if err := srs.Write(outputFile, plainRuleSet, version); err != nil {
		return fmt.Errorf("write .srs: %w", err)
	}

	return nil
}

func extractVersion(input []byte) uint8 {
	var v struct {
		Version uint8 `json:"version"`
	}
	if err := json.Unmarshal(input, &v); err != nil {
		return 0
	}

	return v.Version
}
