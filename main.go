package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	spath "path"
	"strings"
)

var (
	path  string
	root  string
	found = make(map[string]struct{})
)

func init() {
	flag.StringVar(&path, "path", "", "XML file")
	flag.StringVar(&root, "root", "/", "Root in the password store")
}

func main() {
	flag.Parse()

	if path == "" {
		fmt.Printf("Specify a path\n")
		os.Exit(1)
	}

	if kpFile, err := Parse(path); err != nil {
		fmt.Printf("Failed to parse '%s': %#v\n", path, err)
		os.Exit(1)
	} else {
		if err := export(kpFile); err != nil {
			fmt.Printf("Failed to export to passwordstore: %#v\n", err)
			os.Exit(1)
		}
	}
}

func export(kpFile *KeePassFile) error {
	for _, group := range kpFile.Groups {
		if err := exportGroup(kpFile, group, root); err != nil {
			return err
		}
	}
	return nil
}

func exportGroup(kpFile *KeePassFile, group Group, rootPath string) error {
	groupPath := spath.Join(rootPath, group.Name)
	for _, entry := range group.Entries {
		if err := exportEntry(kpFile, entry, groupPath); err != nil {
			return err
		}
	}
	for _, childGroup := range group.Groups {
		if err := exportGroup(kpFile, childGroup, groupPath); err != nil {
			return err
		}
	}
	return nil
}

func exportEntry(kpFile *KeePassFile, entry Entry, groupPath string) error {
	title := cleanPath(entry.GetValue("Title"))
	path := makeUniquePath(spath.Join(groupPath, title))
	found[path] = struct{}{}
	fmt.Printf("Found '%s'\n", path)

	content, err := formatEntry(kpFile, entry)
	if err != nil {
		return err
	}

	if err := insertIntoPath(path, []byte(content)); err != nil {
		return err
	}

	for _, bin := range entry.Binaries {
		key := bin.Key
		if key == "" {
			continue
		}
		data, err := findBinary(kpFile, bin.Value.Ref)
		if err != nil {
			return err
		}
		attachmentPath := makeUniquePath(spath.Join(path, cleanPath(key)))
		found[attachmentPath] = struct{}{}
		if err := insertIntoPath(attachmentPath, data); err != nil {
			return err
		}
	}

	return nil
}

func cleanPath(path string) string {
	if strings.HasPrefix(path, ".") {
		return "_" + path[1:]
	}
	return path
}

func insertIntoPath(path string, content []byte) error {
	cmd := exec.Command("pass", "insert", "-m", path)
	cmd.Stdin = bytes.NewBuffer(content)
	if stdout, err := cmd.Output(); err != nil {
		fmt.Printf("Failed to insert '%s': %v\n%s\n", path, err, string(stdout))
		return err
	}

	return nil
}

func makeUniquePath(path string) string {
	if _, ok := found[path]; !ok {
		return path
	}
	i := 1
	for {
		p := fmt.Sprintf("%s@%d", path, i)
		if _, ok := found[p]; !ok {
			return p
		}
		i++
	}
}

func formatEntry(kpFile *KeePassFile, entry Entry) (string, error) {
	lines := []string{
		entry.GetValue("Password"),
	}
	for _, key := range []string{"UserName", "URL", "Notes"} {
		x := entry.GetValue(key)
		if x != "" {
			lines = append(lines, fmt.Sprintf("%s: %s", key, x))
		}
	}
	return strings.Join(lines, "\n"), nil
}

func findBinary(kpFile *KeePassFile, id string) ([]byte, error) {
	for _, bin := range kpFile.Meta.Binaries {
		if bin.ID == id {
			return bin.Decode()
		}
	}
	return nil, fmt.Errorf("Binary '%s' not found", id)
}
