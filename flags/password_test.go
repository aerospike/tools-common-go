package flags

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPassword(t *testing.T) {
	envVar := "flag_test_password_env"
	envVarVal := testEnvVal
	envVarB64 := "flag_test_password_envb64"
	envVarB64Val := testB64EnvVal
	envVarB64Bad := "flag_test_password_env_bad_b64"
	envVarB64BadVal := testBadB64Val

	os.Setenv(envVar, envVarVal)
	os.Setenv(envVarB64, envVarB64Val)
	os.Setenv(envVarB64Bad, envVarB64BadVal)

	defer func() {
		os.Unsetenv(envVar)
		os.Unsetenv(envVarB64)
		os.Unsetenv(envVarB64Bad)
	}()

	decodedB64EnvVal, err := decode64(envVarB64Val)
	if err != nil {
		t.Error(err.Error())
	}

	fpath := testFileDataPath

	fdata, err := os.ReadFile(fpath)
	if err != nil {
		t.Error(err.Error())
	}

	// trim the trailing new line to match readFromFile
	fdata = bytes.TrimSuffix(fdata, []byte("\n"))

	testCases := []struct {
		name    string
		input   string
		output  PasswordFlag
		wantErr bool
	}{
		{
			name:    "t1",
			input:   "env-b64:" + envVarB64,
			output:  PasswordFlag(decodedB64EnvVal),
			wantErr: false,
		},
		{
			name:    "t2",
			input:   "env-b64:" + envVarB64Bad,
			output:  PasswordFlag(""),
			wantErr: true,
		},
		{
			name:    "t3",
			input:   "b64:" + envVarB64Val,
			output:  PasswordFlag(decodedB64EnvVal),
			wantErr: false,
		},
		{
			name:    "t4",
			input:   "file:" + fpath,
			output:  PasswordFlag(fdata),
			wantErr: false,
		},
		{
			name:    "t5",
			input:   "file:" + "filedoesnotexist.go",
			output:  PasswordFlag(""),
			wantErr: true,
		},
		{
			name:    "t6",
			input:   "env:" + envVar,
			output:  PasswordFlag(envVarVal),
			wantErr: false,
		},
		{
			name:    "t7",
			input:   fpath,
			output:  PasswordFlag(fpath),
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := PasswordFlag{}
			err := actual.Set(tc.input)

			if (err != nil) != tc.wantErr {
				t.Errorf("flagFormatParser() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !reflect.DeepEqual(actual, tc.output) {
				t.Errorf("flagFormatParser() = %v, want %v", string(actual), string(tc.output))
			}
		})
	}
}

func TestPasswordSetEmptyB64(t *testing.T) {
	t.Parallel()

	var flag PasswordFlag

	require.ErrorContains(t, flag.Set("b64:"), "b64: value is empty")
	require.Empty(t, string(flag))
}

func writePasswordFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "password")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

func TestReadPassword(t *testing.T) {
	t.Setenv("TCG_PW", "env-pass")
	t.Setenv("TCG_PW_B64", encode("env-b64-pass\n"))
	t.Setenv("TCG_PW_B64_WRAPPED", "ZW52LWI2\nNC1wYXNz\r\n")

	tests := map[string]struct {
		value     string
		want      string
		firstLine bool
	}{
		"literal":             {value: "hunter2", want: "hunter2"},
		"empty literal":       {value: "", want: ""},
		"unknown prefix":      {value: "ENV:TCG_PW", want: "ENV:TCG_PW"},
		"env source":          {value: "env:TCG_PW", want: "env-pass"},
		"env-b64 source":      {value: "env-b64:TCG_PW_B64", want: "env-b64-pass"},
		"env-b64 wrapped":     {value: "env-b64:TCG_PW_B64_WRAPPED", want: "env-b64-pass"},
		"b64 source":          {value: "b64:" + encode("b64-pass"), want: "b64-pass"},
		"b64 one newline":     {value: "b64:" + encode("b64-pass\n\n"), want: "b64-pass\n"},
		"b64 wrapped":         {value: "b64:YjY0\nLXBh\nc3M=", want: "b64-pass"},
		"file source":         {value: "file:" + writePasswordFile(t, "file-pass"), want: "file-pass"},
		"file LF":             {value: "file:" + writePasswordFile(t, "file-pass\n"), want: "file-pass"},
		"file CRLF":           {value: "file:" + writePasswordFile(t, "file-pass\r\n"), want: "file-pass"},
		"file one LF":         {value: "file:" + writePasswordFile(t, "file-pass\n\n"), want: "file-pass\n"},
		"file keeps spaces":   {value: "file:" + writePasswordFile(t, " file pass \n"), want: " file pass "},
		"file whole":          {value: "file:" + writePasswordFile(t, "line1\nline2\n"), want: "line1\nline2"},
		"file first line LF":  {value: "file:" + writePasswordFile(t, "line1\nline2\n"), want: "line1", firstLine: true},
		"file first line CR":  {value: "file:" + writePasswordFile(t, "line1\r\nline2"), want: "line1", firstLine: true},
		"file first line EOF": {value: "file:" + writePasswordFile(t, "line1"), want: "line1", firstLine: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := readPassword("--password", tt.value, tlsKeyFilePasswordMaxLen, tt.firstLine)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestReadPasswordErrors(t *testing.T) {
	t.Setenv("TCG_EMPTY", "")
	t.Setenv("TCG_B64_EMPTY", encode("\n"))
	t.Setenv("TCG_B64_BAD", testBadB64Val)
	t.Setenv("TCG_B64_NUL", encode("a\x00b"))

	emptyFile := writePasswordFile(t, "")
	newlineFile := writePasswordFile(t, "\n")
	crlfFile := writePasswordFile(t, "\r\n")
	emptyFirstLine := writePasswordFile(t, "\nsecond")
	emptyFirstLineCR := writePasswordFile(t, "\r\nsecond")
	nulFile := writePasswordFile(t, "a\x00b")
	missingFile := filepath.Join(t.TempDir(), "missing")
	dir := t.TempDir()

	tests := map[string]struct {
		value     string
		want      string
		firstLine bool
	}{
		"env no name":     {value: "env:", want: "env: requires a variable name"},
		"env-b64 no name": {value: "env-b64:", want: "env-b64: requires a variable name"},
		"file no path":    {value: "file:", want: "file: requires a path"},
		"env unset":       {value: "env:TCG_UNSET", want: "environment variable TCG_UNSET is not set or empty"},
		"env empty":       {value: "env:TCG_EMPTY", want: "environment variable TCG_EMPTY is not set or empty"},
		"env-b64 unset":   {value: "env-b64:TCG_UNSET", want: "environment variable TCG_UNSET is not set or empty"},
		"env-b64 decodes empty": {
			value: "env-b64:TCG_B64_EMPTY", want: "password from environment variable TCG_B64_EMPTY is empty",
		},
		"env-b64 invalid": {
			value: "env-b64:TCG_B64_BAD", want: "invalid base64 in environment variable TCG_B64_BAD",
		},
		"env-b64 NUL": {
			value: "env-b64:TCG_B64_NUL", want: "environment variable TCG_B64_NUL decodes to a value containing a NUL byte",
		},
		"b64 empty":         {value: "b64:", want: "password from b64: value is empty"},
		"b64 decodes empty": {value: "b64:" + encode("\n"), want: "password from b64: value is empty"},
		"b64 invalid":       {value: "b64:" + testBadB64Val, want: "invalid base64 in b64: value"},
		"b64 NUL":           {value: "b64:" + encode("a\x00b"), want: "b64: value decodes to a value containing a NUL byte"},
		"file empty":        {value: "file:" + emptyFile, want: "password from file " + emptyFile + " is empty"},
		"file LF only":      {value: "file:" + newlineFile, want: "password from file " + newlineFile + " is empty"},
		"file CRLF only":    {value: "file:" + crlfFile, want: "password from file " + crlfFile + " is empty"},
		"file NUL":          {value: "file:" + nulFile, want: "file " + nulFile + " contains a NUL byte"},
		"file missing": {
			value: "file:" + missingFile, want: "cannot read file " + missingFile + ": No such file or directory",
		},
		"file is a directory": {
			value: "file:" + dir, want: "cannot read file " + dir + ": Is a directory",
		},
		"literal NUL": {value: "a\x00b", want: "password contains a NUL byte"},
		"first line empty": {
			value: "file:" + emptyFirstLine, firstLine: true,
			want: "password from first line of file " + emptyFirstLine + " is empty",
		},
		"first line empty CRLF": {
			value: "file:" + emptyFirstLineCR, firstLine: true,
			want: "password from first line of file " + emptyFirstLineCR + " is empty",
		},
		"first line empty file": {
			value: "file:" + emptyFile, firstLine: true,
			want: "password from file " + emptyFile + " is empty",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := readPassword("--password", tt.value, passwordMaxLen, tt.firstLine)
			require.EqualError(t, err, "--password: "+tt.want)
		})
	}
}

func TestReadPasswordLimits(t *testing.T) {
	at63, over63 := strings.Repeat("p", passwordMaxLen), strings.Repeat("p", passwordMaxLen+1)
	at1024, over1024 := strings.Repeat("k", tlsKeyFilePasswordMaxLen), strings.Repeat("k", tlsKeyFilePasswordMaxLen+1)

	t.Setenv("TCG_PW_63", at63)
	t.Setenv("TCG_PW_64", over63)
	t.Setenv("TCG_PW_B64_63", encode(at63))
	t.Setenv("TCG_PW_B64_64", encode(over63))

	over63File := writePasswordFile(t, over63+"\n")
	capped63File := writePasswordFile(t, over63+"pp\x00")
	over1024File := writePasswordFile(t, over1024+"\nsecond\n")
	capped1024File := writePasswordFile(t, over1024+"kk\x00")
	cappedAfterCRLFFile := writePasswordFile(t, at63+"\r\nX")

	keyMax := tlsKeyFilePasswordMaxLen

	accepted := map[string]struct {
		value     string
		maxLen    int
		firstLine bool
	}{
		"literal 63":         {value: at63, maxLen: passwordMaxLen},
		"env 63":             {value: "env:TCG_PW_63", maxLen: passwordMaxLen},
		"env-b64 63":         {value: "env-b64:TCG_PW_B64_63", maxLen: passwordMaxLen},
		"b64 63":             {value: "b64:" + encode(at63+"\n"), maxLen: passwordMaxLen},
		"file 63 CRLF":       {value: "file:" + writePasswordFile(t, at63+"\r\n"), maxLen: passwordMaxLen},
		"literal 1024":       {value: at1024, maxLen: keyMax, firstLine: true},
		"b64 1024":           {value: "b64:" + encode(at1024), maxLen: keyMax, firstLine: true},
		"first line 1024":    {value: "file:" + writePasswordFile(t, at1024+"\n"+over1024), maxLen: keyMax, firstLine: true},
		"first line 1024 CR": {value: "file:" + writePasswordFile(t, at1024+"\r\n"), maxLen: keyMax, firstLine: true},
	}

	for name, tt := range accepted {
		t.Run(name, func(t *testing.T) {
			got, err := readPassword("--password", tt.value, tt.maxLen, tt.firstLine)
			require.NoError(t, err)
			require.Len(t, got, tt.maxLen)
		})
	}

	rejected := map[string]struct {
		value     string
		want      string
		maxLen    int
		firstLine bool
	}{
		"literal 64": {
			value: over63, maxLen: passwordMaxLen,
			want: "--password: password is longer than 63 bytes",
		},
		"env 64": {
			value: "env:TCG_PW_64", maxLen: passwordMaxLen,
			want: "--password: value from environment variable TCG_PW_64 is longer than 63 bytes",
		},
		"env-b64 64": {
			value: "env-b64:TCG_PW_B64_64", maxLen: passwordMaxLen,
			want: "--password: decoded value from environment variable TCG_PW_B64_64 is longer than 63 bytes",
		},
		"b64 64": {
			value: "b64:" + encode(over63), maxLen: passwordMaxLen,
			want: "--password: decoded b64: value is longer than 63 bytes",
		},
		"file 64": {
			value: "file:" + over63File, maxLen: passwordMaxLen,
			want: "--password: value from file " + over63File + " is longer than 63 bytes",
		},
		"file read stops at 66 bytes": {
			value: "file:" + capped63File, maxLen: passwordMaxLen,
			want: "--password: value from file " + capped63File + " is longer than 63 bytes",
		},
		"file read reaches past CRLF": {
			value: "file:" + cappedAfterCRLFFile, maxLen: passwordMaxLen,
			want: "--password: value from file " + cappedAfterCRLFFile + " is longer than 63 bytes",
		},
		"literal 64 bytes in 32 runes": {
			value: strings.Repeat("é", 32), maxLen: passwordMaxLen,
			want: "--password: password is longer than 63 bytes",
		},
		"literal 1026 bytes in 513 runes": {
			value: strings.Repeat("é", 513), maxLen: tlsKeyFilePasswordMaxLen, firstLine: true,
			want: "--password: password is longer than 1024 bytes",
		},
		"literal 1025": {
			value: over1024, maxLen: tlsKeyFilePasswordMaxLen, firstLine: true,
			want: "--password: password is longer than 1024 bytes",
		},
		"b64 1025": {
			value: "b64:" + encode(over1024), maxLen: tlsKeyFilePasswordMaxLen, firstLine: true,
			want: "--password: decoded b64: value is longer than 1024 bytes",
		},
		"first line 1025": {
			value: "file:" + over1024File, maxLen: tlsKeyFilePasswordMaxLen, firstLine: true,
			want: "--password: value from file " + over1024File + " is longer than 1024 bytes",
		},
		"first line read stops at 1027 bytes": {
			value: "file:" + capped1024File, maxLen: tlsKeyFilePasswordMaxLen, firstLine: true,
			want: "--password: value from file " + capped1024File + " is longer than 1024 bytes",
		},
	}

	for name, tt := range rejected {
		t.Run(name, func(t *testing.T) {
			_, err := readPassword("--password", tt.value, tt.maxLen, tt.firstLine)
			require.EqualError(t, err, tt.want)
		})
	}
}
