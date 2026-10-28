"""Seeded generators for the template differential (tools/template_check.py)."""

FUNCS = ["printf", "print", "println", "len", "index", "slice", "not", "and", "or", "eq", "ne", "lt",
         "le", "gt", "ge", "html", "js", "urlquery", "call", "upper", "join", "add", "dbl", "fail", "seq",
         "pair", "nilf", "echo", "typeOf", "makemap", "count", "zeroArgs", "oneArg", "twoArgs", "mapOfThree"]
IDENTS = ["A", "B", "Name", "X", "list", "m", "k", "n", "_u", "é", "Z9"]
STRINGS = ['"a"', '"hello world"', '""', '"x\\ty"', '"\\u00e9"', '`raw`', '"<b>&\'"', '"%d"', '"%v"',
           '"%q"', '"%s-%s"', '"a b"', '"1"']
NUMBERS = ["0", "1", "2", "3", "-1", "7", "10", "1.5", "-2.5", "1e3", "0x1f", "0b11", "0o17", "1_000",
           "'a'", "'\\n'", "1+2i", "4i", "3.0", "100"]
HUGE = "99999999999999999999"
ARITY = {"printf": (1, 4), "print": (0, 3), "println": (0, 3), "len": (1, 1), "index": (2, 3), "slice": (1, 3),
         "not": (1, 1), "and": (1, 3), "or": (1, 3), "eq": (2, 3), "ne": (2, 2), "lt": (2, 2), "le": (2, 2),
         "gt": (2, 2), "ge": (2, 2), "html": (1, 2), "js": (1, 2), "urlquery": (1, 2), "call": (1, 3),
         "upper": (1, 1), "join": (1, 3), "add": (0, 3), "dbl": (1, 1), "fail": (1, 1), "seq": (1, 1),
         "pair": (2, 2), "nilf": (0, 0), "echo": (1, 1), "typeOf": (1, 1), "makemap": (0, 4), "count": (1, 1),
         "zeroArgs": (0, 0), "oneArg": (1, 1), "twoArgs": (2, 2), "mapOfThree": (0, 0)}
LTRIMS = ["", "", "", "", "- "]
RTRIMS = ["", "", "", "", " -"]


class Gen:
    def __init__(self, rng, funcs=None):
        self.rng = rng
        self.funcs = funcs or FUNCS
        self.names = ["alpha", "beta", "gamma"]

    def pick(self, seq):
        return self.rng.choice(seq)

    def literal(self):
        r = self.rng.random()
        if r < 0.35:
            return self.pick(STRINGS)
        if r < 0.75:
            return self.pick(NUMBERS) if self.rng.random() < 0.97 else HUGE
        return self.pick(["true", "false", "nil"])

    def field(self):
        n = self.rng.choice([1, 1, 2, 3])
        return "".join("." + self.pick(IDENTS) for _ in range(n))

    def variable(self, scope):
        v = self.pick(scope)
        if self.rng.random() < 0.3:
            v += self.field()
        return v

    def operand(self, scope, depth):
        r = self.rng.random()
        if r < 0.28:
            return self.field()
        if r < 0.38:
            return "."
        if r < 0.5 and scope:
            return self.variable(scope)
        if r < 0.7:
            return self.literal()
        if r < 0.78 and depth < 3:
            p = "(" + self.pipeline(scope, depth + 1) + ")"
            if self.rng.random() < 0.3:
                p += self.field()
            return p
        return self.pick(self.funcs)

    def command(self, scope, depth, first=True):
        r = self.rng.random()
        if first and r < 0.3:
            return self.operand(scope, depth)
        if not first and r < 0.12:
            # A method or field in the middle of a pipeline.
            return self.field() + (" " + self.operand(scope, depth) if self.rng.random() < 0.4 else "")
        name = self.pick(self.funcs)
        lo, hi = ARITY.get(name, (0, 2))
        n = self.rng.randint(lo, hi)
        if not first:
            n = max(0, n - 1)  # the piped value is the final argument
        if self.rng.random() < 0.1:
            n = self.rng.randrange(0, 4)
        return " ".join([name] + [self.operand(scope, depth) for _ in range(n)])

    def pipeline(self, scope, depth=0):
        n = self.rng.choice([1, 1, 1, 2, 3])
        return " | ".join(self.command(scope, depth, i == 0) for i in range(n))

    def text(self):
        alphabet = ["a", "b", " ", "\n", "\t", "<", ">", "/", "-", "é", "雪", "x y", "<p>", "</p>",
                    "&", "\"", "'", "0", ".", "=", "<a href=\"", "\">", "<script>", "</script>"]
        return "".join(self.pick(alphabet) for _ in range(self.rng.choice([0, 1, 1, 2, 3, 5])))

    def action(self, scope, in_range, depth):
        r = self.rng.random()
        l = "{{" + self.pick(LTRIMS)
        rr = self.pick(RTRIMS) + "}}"
        if r < 0.35 or depth > 3:
            return f"{l}{self.pipeline(scope)}{rr}"
        if r < 0.40:
            return f"{l}/* {self.text()} */{rr}"
        if r < 0.48:
            v = f"$v{len(scope)}"
            return f"{l}{v} := {self.pipeline(scope)}{rr}"
        if r < 0.52 and len(scope) > 1:
            v = self.pick(scope[1:])
            return f"{l}{v} = {self.pipeline(scope)}{rr}"
        if r < 0.66:
            body = self.body(scope, in_range, depth + 1)
            out = f"{l}if {self.pipeline(scope)}{rr}{body}"
            k = self.rng.random()
            if k < 0.25:
                out += f"{{{{else}}}}{self.body(scope, in_range, depth + 1)}"
            elif k < 0.4:
                out += f"{{{{else if {self.pipeline(scope)}}}}}{self.body(scope, in_range, depth + 1)}"
            return out + "{{end}}"
        if r < 0.78:
            nv = f"$i{len(scope)}"
            decl = ""
            sc = scope
            q = self.rng.random()
            if q < 0.3:
                decl = f"{nv} := "
                sc = scope + [nv]
            elif q < 0.55:
                decl = f"{nv}, {nv}e := "
                sc = scope + [nv, nv + "e"]
            body = self.body(sc, True, depth + 1)
            out = f"{l}range {decl}{self.pipeline(scope)}{rr}{body}"
            if self.rng.random() < 0.3:
                out += f"{{{{else}}}}{self.body(scope, in_range, depth + 1)}"
            return out + "{{end}}"
        if r < 0.86:
            out = f"{l}with {self.pipeline(scope)}{rr}{self.body(scope, in_range, depth + 1)}"
            k = self.rng.random()
            if k < 0.25:
                out += f"{{{{else}}}}{self.body(scope, in_range, depth + 1)}"
            elif k < 0.35:
                out += f"{{{{else with {self.pipeline(scope)}}}}}{self.body(scope, in_range, depth + 1)}"
            return out + "{{end}}"
        if r < 0.92:
            arg = "" if self.rng.random() < 0.3 else " " + self.pipeline(scope)
            return f'{l}template "{self.pick(self.names)}"{arg}{rr}'
        if r < 0.95:
            return f'{l}block "{self.pick(self.names)}" {self.pipeline(scope)}{rr}{self.body(scope, in_range, depth + 1)}{{{{end}}}}'
        if in_range:
            return f"{l}{self.pick(['break', 'continue'])}{rr}"
        return f"{l}{self.pipeline(scope)}{rr}"

    def body(self, scope, in_range, depth):
        n = self.rng.choice([1, 2, 2, 3])
        out = []
        for _ in range(n):
            if self.rng.random() < 0.45:
                out.append(self.text())
            else:
                out.append(self.action(scope, in_range, depth))
        return "".join(out)

    def template(self):
        out = self.body(["$"], False, 0)
        if self.rng.random() < 0.25:
            out += f'{{{{define "{self.pick(self.names)}"}}}}{self.body(["$"], False, 2)}{{{{end}}}}'
        return out


MUT_TOKENS = ["{{", "}}", "{{-", "-}}", "(", ")", "|", "$", ".", "end", "else", "if", "range", "with", "define",
              "template", "block", "\"", "`", "'", ":=", "=", ",", "/*", "*/", "break", "continue", "nil", " ",
              "\n", "-", "é", "\x00", "0x", "1e", "..", "$x", ".A.", "{{else}}", "{{end}}"]


def mutate(rng, s):
    for _ in range(rng.choice([1, 1, 2, 3])):
        k = rng.random()
        pos = rng.randrange(len(s) + 1)
        if k < 0.3 and s:
            pos = min(pos, len(s) - 1)
            s = s[:pos] + s[pos + rng.choice([1, 1, 2, 5]):]
        elif k < 0.8:
            s = s[:pos] + rng.choice(MUT_TOKENS) + s[pos:]
        elif s:
            pos = min(pos, len(s) - 1)
            s = s[:pos] + rng.choice(MUT_TOKENS) + s[pos + 1:]
    return s


def parse_requests(rng, count):
    reqs = []
    g = Gen(rng)
    delims = [("", ""), ("", ""), ("", ""), ("<<", ">>"), ("[[", "]]"), ("{{-", "-}}"), ("$", "$")]
    for _ in range(count):
        src = g.template()
        if rng.random() < 0.4:
            src = mutate(rng, src)
        ld, rd = rng.choice(delims)
        if (ld, rd) != ("", ""):
            src = src.replace("{{", ld).replace("}}", rd) if rng.random() < 0.8 else src
        pmode = rng.choice([0, 0, 1, 2, 3])
        funcs = FUNCS if rng.random() < 0.85 else rng.sample(FUNCS, 6) + ["break", "continue"][: rng.choice([0, 1, 2])]
        reqs.append({"mode": "parse", "name": rng.choice(["t", "main", "x y"]), "src": src, "ld": ld, "rd": rd,
                     "pmode": pmode, "funcs": funcs})
    return reqs


TYPED_NUMS = ["int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr"]


def gen_data(rng, depth=0):
    r = rng.random()
    if depth > 3:
        r = r * 0.6
    if r < 0.12:
        return None
    if r < 0.2:
        return rng.random() < 0.5
    if r < 0.32:
        return rng.choice([0, 1, 2, 3, -1, 7, 10, 100, 1.5, -2.5, 0.0, 1e21, 1e-7, 3.0])
    if r < 0.45:
        return rng.choice(["", "a", "hello", "x y", "<b>&", "é雪", "3", "it's", '"q"', "a\nb", "%d"])
    if r < 0.5:
        return {"$t": rng.choice(TYPED_NUMS), "v": rng.choice([0, 1, 2, 5, 100])}
    if r < 0.53:
        return {"$t": rng.choice(["float32", "float64"]), "v": rng.choice([0, 1.5, 2.25, 3.14159265358979])}
    if r < 0.55:
        return {"$t": "complex128", "re": rng.choice([0, 1, 1.5]), "im": rng.choice([0, 2, -1])}
    if r < 0.6:
        e = rng.choice(["int", "string", "bool", "float64"])
        pool = {"int": [0, 1, 2], "string": ["a", "b", ""], "bool": [True, False], "float64": [0.5, 1.0, 2.5]}[e]
        return {"$t": "slice", "e": e, "v": [rng.choice(pool) for _ in range(rng.randrange(0, 4))]}
    if r < 0.63:
        k = rng.choice(["string", "int"])
        keys = ["one", "two", "three"] if k == "string" else [1, 2, 3]
        return {"$t": "map", "k": k, "e": "int",
                "v": [[rng.choice(keys), rng.choice([10, 20])] for _ in range(rng.randrange(0, 3))]}
    if r < 0.66:
        return {"$ref": rng.choice(["tVal", "cmp", "nilT", "tSliceOfNil", "embedded", "&embedded", "namedInt", "tree"])}
    if r < 0.8:
        return [gen_data(rng, depth + 1) for _ in range(rng.randrange(0, 4))]
    return {rng.choice(IDENTS): gen_data(rng, depth + 1) for _ in range(rng.randrange(0, 5))}


def text_requests(rng, count):
    reqs = []
    g = Gen(rng)
    for _ in range(count):
        src = g.template()
        if rng.random() < 0.2:
            src = mutate(rng, src)
        req = {"mode": "text", "name": rng.choice(["t", "main"]), "src": src, "data": gen_data(rng)}
        if rng.random() < 0.1:
            req["opts"] = [rng.choice(["missingkey=error", "missingkey=zero", "missingkey=default"])]
        if rng.random() < 0.3:
            req["defs"] = [[nm, g.body(["$"], False, 2)] for nm in g.names if rng.random() < 0.6]
        if rng.random() < 0.05:
            req["exec"] = rng.choice(g.names)
        reqs.append(req)
    return reqs


HTML_FRAGMENTS = [
    "<p>", "</p>", "<div class=\"", "<div class='", "<a href=\"", "<a href='", "<a href=", "<a ", "<img src=\"",
    "<img srcset=\"", "<script>", "</script>", "<script type=\"text/javascript\">", "<script type=\"text/template\">",
    "<style>", "</style>", "<textarea>", "</textarea>", "<title>", "</title>", "<meta http-equiv=\"refresh\" content=\"",
    "<meta ", "<!--", "-->", "\" ", "' ", ">", "/>", " onclick=\"", " onclick='", " style=\"", " style=", " title=",
    " id=", " class=", " data-x=\"", " href=\"/", " href=\"/x?", " href=\"/x#", " href=\"javascript:",
    "var x = ", "var y = '", "var z = \"", "var r = /", "x = y / 2;", "return /", "a(", ");", "{", "}", "`", "${", "// c\n",
    "/* c */", "color: ", "background: url(", "background: url('", "font-family: \"", ";", ":", "?a=", "&b=", "#f", " ",
    "\n", "x", "é", "<b>", "</b>", "&amp;", "&lt;", "=", "'", "\"", "\\", "<", ">=", "<!DOCTYPE html>", "url=",
]

HTML_STRINGS = ["", "plain", "<b>x</b>", "a&b", "\"q\"", "it's", "javascript:alert(1)", "http://x/y?z=1&w=2#f", "/a b/c",
                "expression(1)", "a;b", "1.5", "back\\slash", "</script>", "<!--", "-->", "x y", "é雪", "\n", "\u2028",
                "${x}", "`t`", "red", "100%", "url(x)", "ZgotmplZ"]
HTML_TYPED = [{"$t": t, "v": v} for t, v in [
    ("html", "<b>bold</b> &amp; <i>it</i>"), ("html", "a<script>x</script>b"), ("css", "color: red"),
    ("htmlattr", " dir=\"ltr\""), ("js", "alert(1)"), ("js", "a /* b */ c"), ("jsstr", "a\\nb"),
    ("url", "javascript:foo()"), ("url", "/a b?c=d"), ("srcset", "a.png 1x, b.png 2x")]]


def html_data(rng, depth=0):
    r = rng.random()
    if r < 0.5:
        return rng.choice(HTML_STRINGS)
    if r < 0.65:
        return rng.choice(HTML_TYPED)
    if r < 0.72:
        return rng.choice([0, 1, 42, -3, 1.5, 1e21, 0.000001])
    if r < 0.76:
        return rng.choice([True, False, None])
    if r < 0.8 and depth < 2:
        return [html_data(rng, depth + 1) for _ in range(rng.randrange(0, 3))]
    if r < 0.85 and depth < 2:
        return {rng.choice(IDENTS): html_data(rng, depth + 1) for _ in range(rng.randrange(0, 3))}
    if r < 0.88:
        return {"$ref": rng.choice(["stringer3", "errorer7", "xyStruct", "anySlice", "stringsAngle"])}
    return rng.choice(HTML_STRINGS)


class HGen(Gen):
    """Generates templates whose text looks like HTML, so actions land in many contexts."""

    def text(self):
        return "".join(self.pick(HTML_FRAGMENTS) for _ in range(self.rng.choice([0, 1, 2, 3, 4])))


def html_requests(rng, count):
    reqs = []
    g = HGen(rng)
    for _ in range(count):
        src = g.template()
        if rng.random() < 0.15:
            src = mutate(rng, src)
        data = {k: html_data(rng) for k in IDENTS if rng.random() < 0.6}
        data["."] = None
        del data["."]
        req = {"mode": "html", "name": rng.choice(["t", "main"]), "src": src,
               "data": data if rng.random() < 0.8 else html_data(rng)}
        if rng.random() < 0.3:
            req["defs"] = [[nm, g.body(["$"], False, 2)] for nm in g.names if rng.random() < 0.6]
        if rng.random() < 0.15:
            req["exec"] = rng.choice(g.names)
        if rng.random() < 0.5:
            req["twice"] = True
        reqs.append(req)
    return reqs


ACTIONS = ["{{.A}}", "{{.B}}", "{{.X}}", "{{.}}", "{{.A}}", "{{.B}}", "{{printf \"%s\" .A}}", "{{html .A}}", "{{.A | html}}",
           "{{js .A}}", "{{urlquery .A}}", "{{.A | urlquery}}", "{{$x := .A}}{{$x}}", "{{len .L}}", "{{index .L 0}}",
           "{{.A | print}}", "{{print .A .B}}", "{{.Name.A}}", "{{\"lit<\"}}", "{{42}}", "{{.A | printf \"%v\"}}"]

SCENARIOS = [
    "<p>@</p>", "<p>@ and @</p>", "<div class=\"@\">", "<div class='@'>", "<div class=@>", "<div class=x@y>",
    "<a href=\"@\">", "<a href='@'>", "<a href=@>", "<a href=\"/p?q=@&r=@\">", "<a href=\"/p/@/x\">", "<a href=\"#@\">",
    "<a href=\"mailto:@\">", "<a href=\" @\">", "<img src=\"@\">", "<img srcset=\"@ 1x, @ 2x\">", "<img srcset=\"a.png 1x, @\">",
    "<input value=@>", "<input value=\"@\" disabled>", "<div style=\"color: @\">", "<div style='background: url(@)'>",
    "<div style=\"background: url('@')\">", "<div style=\"font-family: '@'\">", "<a onclick=\"f(@, '@')\">",
    "<a onclick='g(\"@\")'>", "<a onclick=\"var r = /@/\">", "<a onclick=\"x = @ / 2\">",
    "<meta http-equiv=\"refresh\" content=\"0; url=@\">", "<meta name=x content=\"@\">", "<a @>", "<a b=@ c>", "<a @=1>",
    "<a b=\"c\" @=\"d\">", "<textarea>@</textarea>", "<title>@</title>", "<textarea>a</textarea>@",
    "<script>var x = @;</script>", "<script>var y = '@';</script>", "<script>var z = \"@\";</script>",
    "<script>var r = /@/g;</script>", "<script>var t = `a @ b ${@}`;</script>", "<script>if (a) /@/.test(b)</script>",
    "<script>x = a / @ / b</script>", "<script>// @\n</script>", "<script>/* @ */</script>", "<script>var a = {b: @}</script>",
    "<script type=\"application/json\">@</script>", "<script type=\"text/template\">@</script>",
    "<style>p { color: @ }</style>", "<style>p { background: url(\"@\") }</style>", "<style>p { content: '@' }</style>",
    "<style>p { background: url(@) }</style>", "<style>/* @ */ p {}</style>", "<style>@</style>",
    "<!-- @ -->", "<!-- a -->@", "<p title=\"a&amp;@\">", "<p title=\"&lt;@\">", "<p title=\"@\" id=@>",
    "<svg><a xlink:href=\"@\"></a></svg>", "<div data-x=\"@\" data-url=\"@\">", "<div onload=@>", "<form action=\"@\">",
    "<a href=\"/x?a=@#b=@\">", "<a href=\"{{if .T}}/a{{else}}/b?x={{end}}@\">", "<option selected=@>",
]


def scenario_requests(rng, count):
    reqs = []
    for _ in range(count):
        parts = []
        for _ in range(rng.choice([1, 1, 2, 2, 3])):
            sc = rng.choice(SCENARIOS)
            parts.append("".join(rng.choice(ACTIONS) if ch == "@" else ch for ch in sc))
        src = "".join(parts)
        r = rng.random()
        if r < 0.15:
            src = "{{if .T}}" + src + "{{else}}" + rng.choice(SCENARIOS).replace("@", "{{.A}}") + "{{end}}"
        elif r < 0.25:
            src = "{{range .L}}" + src + "{{end}}"
        elif r < 0.3:
            src = "{{with .W}}" + src + "{{else}}" + "x" + "{{end}}"
        elif r < 0.35:
            src = src + '{{define "alpha"}}' + rng.choice(SCENARIOS).replace("@", "{{.}}") + "{{end}}" + '{{template "alpha" .A}}'
        elif r < 0.38:
            src = '<div {{template "alpha"}}>' + '{{define "alpha"}}' + rng.choice(["a=b", "c=\"{{.A}}\"", "{{.A}}"]) + "{{end}}"
        if rng.random() < 0.1:
            src = mutate(rng, src)
        data = {k: html_data(rng) for k in ["A", "B", "X", "Name"]}
        data["T"] = rng.random() < 0.5
        data["L"] = [html_data(rng, 1) for _ in range(rng.randrange(0, 3))]
        data["W"] = html_data(rng, 1)
        req = {"mode": "html", "name": rng.choice(["t", "main"]), "src": src, "data": data}
        if rng.random() < 0.5:
            req["twice"] = True
        reqs.append(req)
    return reqs


def generate(rng):
    return (parse_requests(rng, 4000) + text_requests(rng, 6000) + html_requests(rng, 3000)
            + scenario_requests(rng, 6000))
