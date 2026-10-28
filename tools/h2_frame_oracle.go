// Frame section of the Go HTTP/2 oracle (see h2_oracle.go). Requests:
//
//	R<maxread>,<meta>,<maxhdrlist>,<valuecount>,<illegal>:<hex stream>
//	    Read every frame of the byte stream with a Framer (meta = merge and decode
//	    HEADERS/CONTINUATION). The answer lists one summary per frame (';'
//	    separated) and ends with "E:<error>|<ErrorDetail>" for the terminal error.
//	    Stream errors do not end the read.
//	W<illegal>:<op>;<op>...
//	    Run Framer.Write* calls (one fresh Framer per op) and answer the bytes
//	    written ("hex") or "err:<text>" per op, ';' separated.
//	Q:<priority dictionary hex>,<canUseDefault>   parseRFC9218Priority
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"h2oracle/hpack"
	"h2oracle/http2"
)

func hx(b []byte) string { return hex.EncodeToString(b) }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func header(h http2.FrameHeader) string {
	return fmt.Sprintf("t%d f%d l%d s%d", uint8(h.Type), uint8(h.Flags), h.Length, h.StreamID)
}

func prio(p http2.PriorityParam) string {
	return fmt.Sprintf("%d/%d/%d", p.StreamDep, b2i(p.Exclusive), p.Weight)
}

func summarize(f http2.Frame) string {
	h := header(f.Header())
	switch f := f.(type) {
	case *http2.DataFrame:
		return h + " DATA " + hx(f.Data())
	case *http2.HeadersFrame:
		return h + " HEADERS " + prio(f.Priority) + " " + hx(f.HeaderBlockFragment())
	case *http2.PriorityFrame:
		return h + " PRIORITY " + prio(f.PriorityParam)
	case *http2.RSTStreamFrame:
		return h + " RST " + strconv.Itoa(int(f.ErrCode))
	case *http2.SettingsFrame:
		var parts []string
		f.ForeachSetting(func(s http2.Setting) error {
			parts = append(parts, fmt.Sprintf("%d=%d", uint16(s.ID), s.Val))
			return nil
		})
		return fmt.Sprintf("%s SETTINGS %s dups=%d ack=%d", h, strings.Join(parts, ","), b2i(f.HasDuplicates()), b2i(f.IsAck()))
	case *http2.PushPromiseFrame:
		return fmt.Sprintf("%s PUSH %d %s", h, f.PromiseID, hx(f.HeaderBlockFragment()))
	case *http2.PingFrame:
		return h + " PING " + hx(f.Data[:])
	case *http2.GoAwayFrame:
		return fmt.Sprintf("%s GOAWAY %d %d %s", h, f.LastStreamID, f.ErrCode, hx(f.DebugData()))
	case *http2.WindowUpdateFrame:
		return fmt.Sprintf("%s WU %d", h, f.Increment)
	case *http2.ContinuationFrame:
		return h + " CONT " + hx(f.HeaderBlockFragment())
	case *http2.PriorityUpdateFrame:
		u, i, ok := http2.ParseRFC9218(f.Priority, true)
		return fmt.Sprintf("%s PU %d %s %d/%d/%d", h, f.PrioritizedStreamID, hx([]byte(f.Priority)), u, i, b2i(ok))
	case *http2.UnknownFrame:
		return h + " UNKNOWN " + hx(f.Payload())
	case *http2.MetaHeadersFrame:
		u, i, aware, inter := f.RFC9218(false)
		return fmt.Sprintf("%s META %s trunc=%d fields=%s r9218=%d/%d/%d/%d", h, prio(f.Priority), b2i(f.Truncated), fieldsText(f.Fields), u, i, b2i(aware), b2i(inter))
	}
	return h + " ?"
}

func frameRead(head, rest string) string {
	p := strings.Split(head, ",")
	fr := http2.NewFramer(io.Discard, bytes.NewReader(unhex(rest)))
	fr.SetMaxReadFrameSize(uint32(atoi(p[0])))
	if p[1] == "1" {
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	}
	fr.MaxHeaderListSize = uint32(atoi(p[2]))
	fr.MaxHeaderValueCount = atoi(p[3])
	fr.AllowIllegalReads = p[4] == "1"
	var out []string
	for n := 0; n < 200; n++ {
		f, err := fr.ReadFrame()
		if err != nil {
			detail := ""
			if d := fr.ErrorDetail(); d != nil {
				detail = d.Error()
			}
			out = append(out, "E:"+err.Error()+"|"+detail)
			if _, ok := err.(http2.StreamError); ok {
				continue
			}
			break
		}
		out = append(out, summarize(f))
	}
	return strings.Join(out, ";")
}

func writeOp(fr *http2.Framer, buf *bytes.Buffer, op string) string {
	a := strings.Split(op, ",")
	u32 := func(i int) uint32 {
		n, err := strconv.ParseUint(a[i], 10, 32)
		if err != nil {
			panic(err)
		}
		return uint32(n)
	}
	var err error
	switch a[0] {
	case "data":
		var pad []byte
		if a[4] != "n" {
			pad = unhex(a[4])
			if pad == nil {
				pad = []byte{}
			}
		}
		err = fr.WriteDataPadded(u32(1), a[2] == "1", unhex(a[3]), pad)
	case "settings":
		var ss []http2.Setting
		for _, s := range a[1:] {
			if s == "" {
				continue
			}
			kv := strings.Split(s, "=")
			ss = append(ss, http2.Setting{ID: http2.SettingID(atoi(kv[0])), Val: uint32(atoi(kv[1]))})
		}
		err = fr.WriteSettings(ss...)
	case "settingsack":
		err = fr.WriteSettingsAck()
	case "ping":
		var d [8]byte
		copy(d[:], unhex(a[2]))
		err = fr.WritePing(a[1] == "1", d)
	case "goaway":
		err = fr.WriteGoAway(u32(1), http2.ErrCode(u32(2)), unhex(a[3]))
	case "wu":
		err = fr.WriteWindowUpdate(u32(1), u32(2))
	case "headers":
		err = fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID: u32(1), EndStream: a[2] == "1", EndHeaders: a[3] == "1", PadLength: uint8(atoi(a[4])),
			Priority:      http2.PriorityParam{StreamDep: u32(5), Exclusive: a[6] == "1", Weight: uint8(atoi(a[7]))},
			BlockFragment: unhex(a[8]),
		})
	case "priority":
		err = fr.WritePriority(u32(1), http2.PriorityParam{StreamDep: u32(2), Exclusive: a[3] == "1", Weight: uint8(atoi(a[4]))})
	case "pu":
		err = fr.WritePriorityUpdate(u32(1), string(unhex(a[2])))
	case "rst":
		err = fr.WriteRSTStream(u32(1), http2.ErrCode(u32(2)))
	case "cont":
		err = fr.WriteContinuation(u32(1), a[2] == "1", unhex(a[3]))
	case "pp":
		err = fr.WritePushPromise(http2.PushPromiseParam{StreamID: u32(1), PromiseID: u32(2), EndHeaders: a[3] == "1", PadLength: uint8(atoi(a[4])), BlockFragment: unhex(a[5])})
	case "raw":
		err = fr.WriteRawFrame(http2.FrameType(atoi(a[1])), http2.Flags(atoi(a[2])), u32(3), unhex(a[4]))
	default:
		return "unknown op"
	}
	if err != nil {
		return "err:" + err.Error()
	}
	return hx(buf.Bytes())
}

func frameWrite(head, rest string) string {
	var out []string
	for _, op := range strings.Split(rest, ";") {
		var buf bytes.Buffer
		fr := http2.NewFramer(&buf, nil)
		fr.AllowIllegalWrites = head == "1"
		out = append(out, writeOp(fr, &buf, op))
	}
	return strings.Join(out, ";")
}

func frameRequest(head, rest string) string {
	switch {
	case head[0] == 'R':
		return frameRead(head[1:], rest)
	case head[0] == 'W':
		return frameWrite(head[1:], rest)
	case head == "Q":
		p := strings.Split(rest, ",")
		u, i, ok := http2.ParseRFC9218(string(unhex(p[0])), p[1] == "1")
		return fmt.Sprintf("%d/%d/%d", u, i, b2i(ok))
	}
	return "unsupported request " + head
}
