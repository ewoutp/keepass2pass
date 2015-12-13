package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
)

type KeePassFile struct {
	Meta   Meta    `xml:"Meta"`
	Groups []Group `xml:"Root>Group"`
}

type Meta struct {
	Binaries []Binary `xml:"Binaries>Binary"`
}

type Binary struct {
	ID         string `xml:"ID,attr"`
	Compressed bool   `xml:"Compressed,attr"`
	Base64     string `xml:",innerxml"`
}

type Group struct {
	Name    string  `xml:"Name"`
	Entries []Entry `xml:"Entry"`
	Groups  []Group `xml:"Group"`
}

type Entry struct {
	UUID     string      `xml:"UUID"`
	Strings  []String    `xml:"String"`
	Binaries []BinaryRef `xml:"Binary"`
}

type String struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type BinaryRef struct {
	Key   string   `xml:"Key"`
	Value ValueRef `xml:"Value"`
}

type ValueRef struct {
	Ref string `xml:"Ref,attr"`
}

func Parse(path string) (*KeePassFile, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kpFile := &KeePassFile{}
	if err := xml.Unmarshal(data, kpFile); err != nil {
		return nil, err
	}
	return kpFile, nil
}

func (b *Binary) Decode() ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b.Base64)
	if err != nil {
		return nil, err
	}
	if !b.Compressed {
		return raw, nil
	}
	buf := bytes.NewBuffer(raw)
	gzipReader, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	uncompressed, err := ioutil.ReadAll(gzipReader)
	if err != nil {
		return nil, err
	}
	return uncompressed, nil
}

func (e *Entry) GetValue(key string) string {
	for _, s := range e.Strings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}
