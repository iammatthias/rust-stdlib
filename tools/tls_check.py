#!/usr/bin/env python3
"""Exercise the complete example through live HTTP after verified TLS bootstrap."""
import http.client
import json
import pathlib
import queue
import subprocess
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]

def main():
    subprocess.run(["cargo", "build", "--offline", "--locked", "--manifest-path", "backends/tls/Cargo.toml", "--example", "web_milestone"], cwd=ROOT, check=True)
    import os
    suffix=".exe" if os.name=="nt" else ""
    command=ROOT/"backends/tls/target/debug/examples"/("web_milestone"+suffix)
    process=subprocess.Popen([str(command),"127.0.0.1:0"],cwd=ROOT,stdin=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    messages=queue.Queue()
    def read():
        for line in process.stderr:
            try: messages.put(json.loads(line))
            except ValueError: messages.put({"unexpected":line})
    thread=threading.Thread(target=read,daemon=True);thread.start()
    try:
        tls=messages.get(timeout=10)
        assert tls["message"]=="verified_https" and tls["fields"]["status"]==200,tls
        listening=messages.get(timeout=10)
        assert listening["message"]=="listening",listening
        host,port=listening["fields"]["address"].rsplit(":",1)
        client=http.client.HTTPConnection(host,int(port),timeout=5)
        client.request("GET","/?title=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        response=client.getresponse();body=response.read().decode()
        assert response.status==200 and '<h1>&lt;script&gt;alert(1)&lt;/script&gt;</h1>' in body
        assert 'fetch(\'/echo\'' in body
        client.close()
        client=http.client.HTTPConnection(host,int(port),timeout=5)
        client.request("POST","/echo",json.dumps({"message":"typed JSON over live HTTP"}),{"Content-Type":"application/json"})
        response=client.getresponse();assert response.status==200
        assert json.loads(response.read())=={"message":"typed JSON over live HTTP"}
        client.close()
        process.stdin.write("\n");process.stdin.flush()
        assert process.wait(timeout=10)==0
        print("Web milestone passed: embedded assets, escaped templates, typed JSON, verified HTTPS, structured logs")
    finally:
        if process.poll() is None: process.kill();process.wait()
        process.stdin.close();process.stderr.close()

if __name__=="__main__":main()
