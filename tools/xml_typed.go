// Typed Marshal/Unmarshal menu for tools/xml_check.py. The Rust twin is
// tools/derive-check/src/bin/xml_typed_probe.rs; keep the two in lockstep.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"

	"encoding/xml"
)

type Scalars struct {
	XMLName xml.Name `xml:"scalars" json:"-"`
	B       bool     `xml:"b"`
	I       int      `xml:"i"`
	I8      int8     `xml:"i8"`
	I16     int16    `xml:"i16"`
	I32     int32    `xml:"i32"`
	I64     int64    `xml:"i64"`
	U       uint     `xml:"u"`
	U8      uint8    `xml:"u8"`
	U16     uint16   `xml:"u16"`
	U32     uint32   `xml:"u32"`
	U64     uint64   `xml:"u64"`
	F32     float32  `xml:"f32"`
	F64     float64  `xml:"f64"`
	S       string   `xml:"s"`
}

type Attrs struct {
	XMLName xml.Name `xml:"attrs" json:"-"`
	S       string   `xml:"s,attr"`
	I       int      `xml:"i,attr"`
	B       bool     `xml:"b,attr"`
	F       float64  `xml:"f,attr"`
	E       string   `xml:"e,attr,omitempty"`
	N       int      `xml:"n,attr,omitempty"`
	P       *string  `xml:"p,attr"`
	Q       *int     `xml:"q,attr,omitempty"`
	Ns      string   `xml:"urn:x ns,attr"`
	Ns2     string   `xml:"urn:y ns2,attr"`
	Xl      string   `xml:"http://www.w3.org/XML/1998/namespace lang,attr,omitempty"`
	L       []string `xml:"l,attr"`
	Text    string   `xml:",chardata"`
}

type Paths struct {
	XMLName xml.Name `xml:"paths" json:"-"`
	A       string   `xml:"x>y>a"`
	B       string   `xml:"x>y>b"`
	C       string   `xml:"x>c"`
	D       []string `xml:"x>d"`
	E       string   `xml:"z"`
	F       string   `xml:"x>y>f"`
	G       *string  `xml:"p>q"`
	H       []int    `xml:"p>r"`
	I       string   `xml:"x>y>z>i,omitempty"`
}

type Content struct {
	XMLName xml.Name `xml:"content" json:"-"`
	ID      string   `xml:"id,attr"`
	Text    string   `xml:",chardata"`
	Note    string   `xml:",comment"`
	Items   []string `xml:"item"`
}

type Cdata struct {
	XMLName xml.Name `xml:"cdata" json:"-"`
	Data    string   `xml:",cdata"`
	Other   string   `xml:"o"`
}

type Inner struct {
	XMLName xml.Name `xml:"inner" json:"-"`
	Raw     string   `xml:",innerxml"`
	Attr    string   `xml:"a,attr"`
}

type InnerBytes struct {
	XMLName xml.Name `xml:"innerbytes" json:"-"`
	Raw     []byte   `xml:",innerxml"`
	T       string   `xml:"t"`
}

type Comments struct {
	XMLName xml.Name `xml:"comments" json:"-"`
	C1      string   `xml:",comment"`
	E       string   `xml:"e"`
	C2      []byte   `xml:",comment"`
}

type Child struct {
	XMLName xml.Name `json:"-"`
	Name    string   `xml:"name,attr"`
	Value   string   `xml:",chardata"`
}

type Anys struct {
	XMLName xml.Name   `xml:"anys" json:"-"`
	Name    string     `xml:"name"`
	Rest    []Child    `xml:",any"`
	Extra   []xml.Attr `xml:",any,attr"`
}

type Leaf struct {
	V string `xml:"v"`
	N int    `xml:"n,attr"`
}

type Ptrs struct {
	XMLName xml.Name `xml:"ptrs" json:"-"`
	P       *string  `xml:"p"`
	Q       *Leaf    `xml:"q"`
	R       []*Leaf  `xml:"r"`
	L       []int    `xml:"l"`
	B       []byte   `xml:"b"`
	A       [3]int   `xml:"a"`
	O       *int     `xml:"o,omitempty"`
}

type Tree struct {
	XMLName xml.Name `xml:"tree" json:"-"`
	Value   string   `xml:"v,attr"`
	Kids    []Tree   `xml:"tree"`
}

type Base struct {
	ID    string `xml:"id,attr,omitempty"`
	Title string `xml:"title"`
}

type Derived struct {
	Base    `json:"Base"`
	XMLName xml.Name `xml:"derived" json:"-"`
	Title2  string   `xml:"title2"`
	Extra   string   `xml:"extra"`
}

type Shadow struct {
	Base    `json:"Base"`
	XMLName xml.Name `xml:"shadow" json:"-"`
	Title   string   `xml:"title"`
}

type PtrEmbed struct {
	*Base   `json:"Base"`
	XMLName xml.Name `xml:"ptrembed" json:"-"`
	Extra   string   `xml:"extra"`
}

type BaseEl struct {
	Title string `xml:"title"`
	Note  string `xml:"note,omitempty"`
}

type PtrEmbedEl struct {
	*BaseEl `json:"BaseEl"`
	XMLName xml.Name `xml:"ptrembedel" json:"-"`
	Extra   string   `xml:"extra"`
}

type Conflict struct {
	A string `xml:"x"`
	B string `xml:"x"`
}

type ConflictPath struct {
	A string `xml:"x>y"`
	B string `xml:"x"`
}

type BadFlags struct {
	A string `xml:"a,attr,chardata"`
}

type BadChain struct {
	A string `xml:"a>b,attr"`
}

type Trailing struct {
	A string `xml:"a>"`
}

type NsNoName struct {
	A string `xml:"urn:x ,attr"`
}

type OmitBad struct {
	A string `xml:",chardata,omitempty"`
}

type Named struct {
	XMLName xml.Name `xml:"real" json:"-"`
	V       string   `xml:"v"`
}

type UsesNamed struct {
	N Named `xml:"other"`
}

type UsesNamedOK struct {
	XMLName xml.Name `xml:"usesnamedok" json:"-"`
	N       Named    `xml:"real"`
	M       Named
	L       []Named
}

type Nss struct {
	XMLName xml.Name `xml:"urn:a root" json:"-"`
	A       string   `xml:"urn:b child"`
	B       string   `xml:"urn:b child2,attr"`
	C       string   `xml:"urn:c c"`
	D       string   `xml:"d"`
	L       []NsItem `xml:"urn:a item"`
}

type NsItem struct {
	XMLName xml.Name `json:"-"`
	V       string   `xml:",chardata"`
	K       string   `xml:"http://x.org/p/k,attr"`
}

type NoNs struct {
	XMLName xml.Name `xml:"" json:"-"`
	V       string   `xml:"v"`
}

type Omit struct {
	XMLName xml.Name       `xml:"omit" json:"-"`
	S       string         `xml:"s,omitempty"`
	I       int            `xml:"i,omitempty"`
	B       bool           `xml:"b,omitempty"`
	F       float64        `xml:"f,omitempty"`
	L       []string       `xml:"l,omitempty"`
	P       *string        `xml:"p,omitempty"`
	Q       *Leaf          `xml:"q,omitempty"`
	St      Leaf           `xml:"st,omitempty"`
	By      []byte         `xml:"by,omitempty"`
	M       map[string]int `xml:"m,omitempty"`
}

type Maps struct {
	XMLName xml.Name       `xml:"maps" json:"-"`
	M       map[string]int `xml:"m"`
}

type Defaults struct {
	Title string
	Count int    `xml:",attr"`
	Body  string `xml:",chardata"`
}

type BadComment struct {
	XMLName xml.Name `xml:"badcomment" json:"-"`
	C       string   `xml:",comment"`
}

type BadCommentType struct {
	XMLName xml.Name `xml:"badcommenttype" json:"-"`
	C       int      `xml:",comment"`
}

type Chars struct {
	XMLName xml.Name `xml:"chars" json:"-"`
	I       int      `xml:",chardata"`
	U       uint     `xml:",cdata"`
	F       float32  `xml:",chardata"`
	B       bool     `xml:",chardata"`
	Y       []byte   `xml:",chardata"`
	S       *string  `xml:",chardata"`
}

// ---- custom marshalers ------------------------------------------------------

type Upper string

func (u Upper) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(strings.ToUpper(string(u)), start)
}

func (u *Upper) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}
	*u = Upper(strings.ToLower(s))
	return nil
}

type Pair struct {
	A string
	B string
}

func (p Pair) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "a"}, Value: p.A})
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	if err := e.EncodeToken(xml.CharData(p.B)); err != nil {
		return err
	}
	if err := e.EncodeToken(xml.Comment("pair")); err != nil {
		return err
	}
	return e.EncodeToken(start.End())
}

func (p *Pair) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, a := range start.Attr {
		if a.Name.Local == "a" {
			p.A = a.Value
		}
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t := t.(type) {
		case xml.CharData:
			p.B += string(t)
		case xml.EndElement:
			return nil
		case xml.StartElement:
			if err := d.Skip(); err != nil {
				return err
			}
		}
	}
}

type Leaky struct {
	V string
}

func (l Leaky) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeToken(start)
}

type Overclose struct {
	V string
}

func (o Overclose) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	if err := e.EncodeToken(start.End()); err != nil {
		return err
	}
	return e.EncodeToken(start.End())
}

type Failing struct {
	V string
}

func (f Failing) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return errors.New("marshal failed: " + f.V)
}

func (f *Failing) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	return errors.New("unmarshal failed")
}

type Lazy struct {
	V string
}

func (l *Lazy) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	return nil
}

type RawUser struct {
	V string
}

func (l *RawUser) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	_, err := d.RawToken()
	return err
}

type Txt string

func (t Txt) MarshalText() ([]byte, error) {
	if t == "fail" {
		return nil, errors.New("text marshal failed")
	}
	return []byte("txt:" + string(t)), nil
}

func (t *Txt) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*t = Txt(s)
	return nil
}

func (t *Txt) UnmarshalText(b []byte) error {
	s := string(b)
	if s == "fail" {
		return errors.New("text unmarshal failed")
	}
	*t = Txt(strings.TrimPrefix(s, "txt:"))
	return nil
}

type AttrVal string

func (a *AttrVal) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	if a == nil {
		return xml.Attr{}, nil
	}
	switch *a {
	case "skip":
		return xml.Attr{}, nil
	case "fail":
		return xml.Attr{}, errors.New("attr marshal failed")
	}
	return xml.Attr{Name: name, Value: "A-" + string(*a)}, nil
}

func (a *AttrVal) UnmarshalXMLAttr(attr xml.Attr) error {
	if attr.Value == "fail" {
		return errors.New("attr unmarshal failed")
	}
	*a = AttrVal(strings.TrimPrefix(attr.Value, "A-"))
	return nil
}

type Customs struct {
	XMLName xml.Name  `xml:"customs" json:"-"`
	U       Upper     `xml:"u"`
	Us      []Upper   `xml:"us"`
	Up      *Upper    `xml:"up"`
	P       Pair      `xml:"p"`
	T       Txt       `xml:"t"`
	Ts      []Txt     `xml:"ts"`
	TA      Txt       `xml:"ta,attr"`
	TC      Txt       `xml:",chardata"`
	AV      AttrVal   `xml:"av,attr"`
	AVs     []AttrVal `xml:"avs,attr"`
	AVp     *AttrVal  `xml:"avp,attr"`
}

type LeakyHolder struct {
	XMLName xml.Name `xml:"leakyholder" json:"-"`
	L       Leaky    `xml:"l"`
}

type OverHolder struct {
	XMLName xml.Name  `xml:"overholder" json:"-"`
	O       Overclose `xml:"o"`
}

type FailHolder struct {
	XMLName xml.Name `xml:"failholder" json:"-"`
	F       Failing  `xml:"f"`
}

type LazyHolder struct {
	XMLName xml.Name `xml:"lazyholder" json:"-"`
	L       Lazy     `xml:"l"`
}

type RawHolder struct {
	XMLName xml.Name `xml:"rawholder" json:"-"`
	R       RawUser  `xml:"r"`
}

type NameHolder struct {
	XMLName xml.Name `xml:"nameholder" json:"-"`
	N       xml.Name `xml:"n"`
	A       xml.Attr `xml:"a,attr"`
}

// ---- registry -----------------------------------------------------------------

func zero[T any]() T {
	var v T
	return v
}

type kind struct {
	marshal   func(spec string, prefix, indent string) string
	marshalEl func(spec string, prefix, indent string, start xml.StartElement) string
	unmarshal func(input []byte) string
}

// encodeEl runs Encoder.EncodeElement with a start template.
func encodeEl(v any, prefix, indent string, start xml.StartElement) ([]byte, error) {
	var b bytes.Buffer
	e := xml.NewEncoder(&b)
	e.Indent(prefix, indent)
	if err := e.EncodeElement(v, start); err != nil {
		return nil, err
	}
	if err := e.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func marshalElFor[T any](spec string, prefix, indent string, start xml.StartElement) string {
	v := new(T)
	if err := json.Unmarshal([]byte(spec), v); err != nil {
		panic(fmt.Sprintf("bad spec for %T: %v: %s", v, err, spec))
	}
	plain, err1 := encodeEl(v, "", "", start)
	indented, err2 := encodeEl(v, prefix, indent, start)
	return result(plain, err1) + " | " + result(indented, err2)
}

// startTemplate maps a mode name to an EncodeElement start element.
func startTemplate(mode string) xml.StartElement {
	switch mode {
	case "el":
		return xml.StartElement{Name: xml.Name{Space: "urn:s", Local: "wrap"}, Attr: []xml.Attr{
			{Name: xml.Name{Local: "k"}, Value: "v<&>"},
			{Name: xml.Name{Space: "urn:q", Local: "q"}, Value: "w"},
			{Name: xml.Name{Space: "urn:s", Local: "s"}, Value: "x"},
		}}
	case "elplain":
		return xml.StartElement{Name: xml.Name{Local: "wrap"}}
	case "elbad":
		return xml.StartElement{Name: xml.Name{Space: "urn:s"}}
	}
	panic("unknown start template " + mode)
}

func result(out []byte, err error) string {
	if err != nil {
		return "ERR " + hx([]byte(errText(err)))
	}
	return "OK " + hx(out)
}

func marshalFor[T any](spec string, prefix, indent string) string {
	v := new(T)
	if err := json.Unmarshal([]byte(spec), v); err != nil {
		panic(fmt.Sprintf("bad spec for %T: %v: %s", v, err, spec))
	}
	plain, err1 := xml.Marshal(v)
	indented, err2 := xml.MarshalIndent(v, prefix, indent)
	return result(plain, err1) + " | " + result(indented, err2)
}

func unmarshalFor[T any](input []byte) string {
	v := new(T)
	err := xml.Unmarshal(input, v)
	out, merr := xml.Marshal(v)
	return "U " + func() string {
		if err != nil {
			return "ERR " + hx([]byte(errText(err)))
		}
		return "OK"
	}() + " | " + result(out, merr)
}

func entry[T any]() kind {
	return kind{marshal: marshalFor[T], marshalEl: marshalElFor[T], unmarshal: unmarshalFor[T]}
}

var kinds = map[string]kind{
	"Scalars": entry[Scalars](), "Attrs": entry[Attrs](), "Paths": entry[Paths](),
	"Content": entry[Content](), "Cdata": entry[Cdata](), "Inner": entry[Inner](),
	"InnerBytes": entry[InnerBytes](), "Comments": entry[Comments](), "Anys": entry[Anys](),
	"Ptrs": entry[Ptrs](), "Tree": entry[Tree](), "Derived": entry[Derived](),
	"Shadow": entry[Shadow](), "PtrEmbed": entry[PtrEmbed](), "PtrEmbedEl": entry[PtrEmbedEl](), "Conflict": entry[Conflict](),
	"ConflictPath": entry[ConflictPath](), "BadFlags": entry[BadFlags](),
	"BadChain": entry[BadChain](), "Trailing": entry[Trailing](), "NsNoName": entry[NsNoName](),
	"OmitBad": entry[OmitBad](), "UsesNamed": entry[UsesNamed](), "UsesNamedOK": entry[UsesNamedOK](),
	"Nss": entry[Nss](), "NoNs": entry[NoNs](), "Omit": entry[Omit](), "Maps": entry[Maps](),
	"Defaults": entry[Defaults](), "BadComment": entry[BadComment](),
	"BadCommentType": entry[BadCommentType](), "Chars": entry[Chars](), "Customs": entry[Customs](),
	"LeakyHolder": entry[LeakyHolder](), "OverHolder": entry[OverHolder](),
	"FailHolder": entry[FailHolder](), "LazyHolder": entry[LazyHolder](),
	"RawHolder": entry[RawHolder](), "NameHolder": entry[NameHolder](),
}

// bare values: Marshal/Unmarshal of non-struct top-level values.
func bareMarshal(name, spec string, prefix, indent string) string {
	var v any
	dec := func(p any) {
		if err := json.Unmarshal([]byte(spec), p); err != nil {
			panic(fmt.Sprintf("bad bare spec %s: %v", spec, err))
		}
	}
	switch name {
	case "int":
		var x int
		dec(&x)
		v = x
	case "int8":
		var x int8
		dec(&x)
		v = x
	case "uint16":
		var x uint16
		dec(&x)
		v = x
	case "uint64":
		var x uint64
		dec(&x)
		v = x
	case "float32":
		var x float32
		dec(&x)
		v = x
	case "float64":
		var x float64
		dec(&x)
		v = x
	case "f32bits":
		bits, _ := strconv.ParseUint(spec, 10, 32)
		v = math.Float32frombits(uint32(bits))
	case "f64bits":
		bits, _ := strconv.ParseUint(spec, 10, 64)
		v = math.Float64frombits(bits)
	case "bool":
		var x bool
		dec(&x)
		v = x
	case "string":
		var x string
		dec(&x)
		v = x
	case "strings":
		var x []string
		dec(&x)
		v = x
	case "ints":
		var x []int
		dec(&x)
		v = x
	case "bytes":
		var x []byte
		dec(&x)
		v = x
	case "bytearr":
		var x [2]byte
		dec(&x)
		v = x
	case "optstr":
		var x *string
		dec(&x)
		v = x
	case "map":
		var x map[string]int
		dec(&x)
		v = x
	case "nil":
		v = nil
	case "upper":
		var x Upper
		dec(&x)
		v = x
	case "txt":
		var x Txt
		dec(&x)
		v = x
	case "name":
		var x xml.Name
		dec(&x)
		v = x
	default:
		panic("unknown bare kind " + name)
	}
	plain, err1 := xml.Marshal(v)
	indented, err2 := xml.MarshalIndent(v, prefix, indent)
	return result(plain, err1) + " | " + result(indented, err2)
}

func bareUnmarshal(name string, input []byte) string {
	var v any
	switch name {
	case "int":
		v = new(int)
	case "int8":
		v = new(int8)
	case "uint16":
		v = new(uint16)
	case "uint64":
		v = new(uint64)
	case "float32":
		v = new(float32)
	case "float64":
		v = new(float64)
	case "bool":
		v = new(bool)
	case "string":
		v = new(string)
	case "strings":
		v = new([]string)
	case "ints":
		v = new([]int)
	case "bytes":
		v = new([]byte)
	case "optstr":
		v = new(*string)
	case "name":
		v = new(xml.Name)
	case "upper":
		v = new(Upper)
	case "txt":
		v = new(Txt)
	case "bytearr":
		v = new([2]byte)
	default:
		panic("unknown bare kind " + name)
	}
	err := xml.Unmarshal(input, v)
	out, merr := xml.Marshal(reflect.ValueOf(v).Elem().Interface())
	status := "OK"
	if err != nil {
		status = "ERR " + hx([]byte(errText(err)))
	}
	return "U " + status + " | " + result(out, merr)
}

var _ = io.EOF
var _ = hex.EncodeToString

func typedMarshal(name string, prefix, indent []byte, spec string) string {
	if mode, rest, ok := strings.Cut(name, ":"); ok && strings.HasPrefix(mode, "el") {
		k, ok := kinds[rest]
		if !ok {
			panic("unknown struct " + rest)
		}
		return k.marshalEl(spec, string(prefix), string(indent), startTemplate(mode))
	}
	if strings.HasPrefix(name, "bare:") {
		return bareMarshal(name[5:], spec, string(prefix), string(indent))
	}
	k, ok := kinds[name]
	if !ok {
		panic("unknown struct " + name)
	}
	return k.marshal(spec, string(prefix), string(indent))
}

func typedUnmarshal(name string, input []byte) string {
	if strings.HasPrefix(name, "bare:") {
		return bareUnmarshal(name[5:], input)
	}
	k, ok := kinds[name]
	if !ok {
		panic("unknown struct " + name)
	}
	return k.unmarshal(input)
}
