#!/usr/bin/env python3
"""Compare binary/CSV/XML accepted interoperability corpus with Go's standard library."""
import io,json,os,pathlib,random,subprocess,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
def main():
    started=time.monotonic();rng=random.Random(91824);vectors=[]
    for i in range(250):
        rows=[[rng.choice(['','alpha','a,b','"quotes"','line\nbreak','日本語','😀',' trailing ']) for _ in range(1+i%8)] for _ in range(1+i%6)]
        import csv
        buf=io.StringIO(newline='');csv.writer(buf,lineterminator='\r\n').writerows(rows)
        vectors.append({'format':'csv','input':buf.getvalue()})
    vectors.extend({'format':'csv','input':s} for s in ['a"b','"unterminated','"a"z','a,b\nc','\n\r\na,b\n', 'a,'])
    from xml.sax.saxutils import escape,quoteattr
    for i in range(250):
        text=rng.choice(['','alpha','<&>日本語😀','line\nbreak',' quotes " ']);attr=rng.choice(['a&b','"\'','line\nbreak','雪'])
        vectors.append({'format':'xml','input':f'<root a={quoteattr(attr)}><!--ok--><child>{escape(text)}</child><![CDATA[<&]]><?work data?></root>'})
    vectors.extend({'format':'xml','input':s} for s in ['<r>','<r></s>','<r>&bad;</r>','<r>&#0;</r>','<r a="<"/>','<1/>','<r>]]></r>'])
    for i in range(250):
        vectors.append({'format':'xmlns','input':f"<r xmlns='urn:r{i}' xmlns:p='urn:p{i}' id='1' p:id='2' xml:lang='en'><p:x xmlns:p='urn:nested{i}'/><child xmlns=''><p:x/></child><p:x/></r>"})
    for _ in range(500):
        vectors.append({'format':'uvarint','input':str(rng.randrange(1<<64))})
        vectors.append({'format':'varint','input':str(rng.randrange(-(1<<63),1<<63))})
    for value in [0,1,127,128,255,256,(1<<63),(1<<64)-1]:
        vectors.append({'format':'uvarint','input':str(value)})
    for value in [0,-1,1,-128,128,-(1<<63),(1<<63)-1]:
        vectors.append({'format':'varint','input':str(value)})
    int_ranges={'u8':(0,2**8-1),'i8':(-2**7,2**7-1),'u16':(0,2**16-1),'i16':(-2**15,2**15-1),'u32':(0,2**32-1),'i32':(-2**31,2**31-1),'u64':(0,2**64-1),'i64':(-2**63,2**63-1)}
    sizes={'u8':1,'i8':1,'bool':1,'u16':2,'i16':2,'u32':4,'i32':4,'f32':4,'u64':8,'i64':8,'f64':8}
    def sample(typ):
        if typ in int_ranges:
            lo,hi=int_ranges[typ]
            return str(rng.choice([lo,hi,0 if lo<=0<=hi else lo,rng.randint(lo,hi)]))
        if typ in ('f32','f64'):
            return format(rng.getrandbits(32 if typ=='f32' else 64),'x')
        return rng.choice(['true','false'])
    for typ,size in sizes.items():
        for order in ['BE','LE','NE']:
            for _ in range(4):
                value=sample(typ)
                for buflen in (0,size-1,size,size+1):
                    vectors.append({'format':'binary_encode','input':f'{order}|{typ}|{value}|{buflen}'})
                vectors.append({'format':'binary_write','input':f'{order}|{typ}|{value}'})
                for _ in range(3):
                    h=bytes(rng.randrange(256) for _ in range(rng.randrange(0,size+3))).hex()
                    vectors.append({'format':'binary_decode','input':f'{order}|{typ}|{h}'})
                    vectors.append({'format':'binary_read','input':f'{order}|{typ}|{h}'})
    def uvarint_bytes(x):
        out=bytearray()
        while x>=128:
            out.append((x&127)|128);x>>=7
        out.append(x)
        return bytes(out)
    for _ in range(300):
        value=rng.getrandbits(64)
        vectors.append({'format':'append_uvarint','input':str(value)})
        vectors.append({'format':'append_varint','input':str(value-(1<<63))})
    for _ in range(400):
        raw=uvarint_bytes(rng.getrandbits(rng.randrange(1,65)))
        mutants=[raw,raw[:-1],raw+b'\x01',b'\xff'*rng.randrange(0,13),
                 bytes(rng.randrange(256) for _ in range(rng.randrange(0,13))),
                 raw[:-1]+bytes([rng.randrange(256)])]
        for mutant in mutants:
            for fmt in ['uvarint_get','varint_get','read_uvarint','read_varint']:
                vectors.append({'format':fmt,'input':mutant.hex()})
    # csv Reader.Read sequences and Writer.WriteAll under Go's option combinations.
    text_chars=['a','b',',',';','"','\r','\n',' ','\t','#','雪','x','\\','.']
    option_sets=[{},{'comma':';'},{'comma':'\t'},{'comment':'#'},{'fields':'2'},{'fields':'-1'},
                 {'lazy':True},{'trim':True},{'comma':'"'},{'comma':'\r'},{'comma':''},{'comma':'é'},
                 {'comment':'#','trim':True,'lazy':True,'fields':'0'},{'comma':',','comment':','},
                 {'lazy':True,'fields':'1'},{'trim':True,'fields':'3'}]
    for _ in range(1500):
        text=''.join(rng.choice(text_chars) for _ in range(rng.randrange(0,40)))
        vectors.append({'format':'csv_read','input':text,'options':rng.choice(option_sets)})
    for _ in range(300):
        records=[[''.join(rng.choice(['a',',','"','\r','\n',' ','雪','\\.','']) for _ in range(rng.randrange(0,4)))
                  for _ in range(rng.randrange(0,4))] for _ in range(rng.randrange(0,4))]
        options={'comma':rng.choice([',',';','\t','"','\n','é','']),'crlf':rng.choice([True,False])}
        vectors.append({'format':'csv_write','input':json.dumps(records,ensure_ascii=False),'options':options})
    # Raw bytes (invalid UTF-8 kept as Go does) and an injected I/O error: Go returns the
    # partial record together with the error.
    raw_chars=[b'a',b'b',b',',b';',b'"',b'\r',b'\n',b' ',b'#',b'\xff',b'\xc3',b'\xa9',b'\x00',b'\xe9\x9b\xaa']
    for _ in range(1500):
        raw=b''.join(rng.choice(raw_chars) for _ in range(rng.randrange(0,40)))
        options=dict(rng.choice(option_sets))
        if rng.random()<0.5:
            options['fail_at']=str(rng.randrange(0,len(raw)+3))
        vectors.append({'format':'csv_raw_read','input':raw.hex(),'options':options})
    data=''.join(json.dumps(v,ensure_ascii=False)+'\n' for v in vectors)
    subprocess.run(['cargo','build','--offline','--locked','--example','encoding_probe'],cwd=ROOT,check=True)
    outputs=[]
    probe=ROOT/'target/debug/examples'/('encoding_probe.exe' if os.name=='nt' else 'encoding_probe')
    for command in [[str(probe)],['go','run',str(ROOT/'tools/encoding_oracle.go')]]:
        p=subprocess.run(command,input=data,text=True,capture_output=True,cwd=ROOT,check=True);outputs.append([json.loads(l) for l in p.stdout.splitlines()])
    if not all(len(o)==len(vectors) for o in outputs):raise AssertionError('missing oracle output')
    for i,(a,b) in enumerate(zip(*outputs)):
        if a!=b:raise AssertionError(f'vector {i}: {vectors[i]!r}\nRust={a!r}\nGo={b!r}')
    print(f'Binary/CSV/XML Go conformance: {len(vectors)} vectors passed in {time.monotonic()-started:.3f}s')
if __name__=='__main__':main()
