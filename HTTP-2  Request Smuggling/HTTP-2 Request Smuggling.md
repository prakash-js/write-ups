# HTTP/2 Request Smuggling

## Task 2 

### Q1 Which version of the HTTP protocol uses \r\n to separate headers in a request?
> HTTP/1.1

**Explaination :** 
</br>
HTTP/1.0 and HTTP/1.1 use a text-based format where each header line is terminated by CRLF (\r\n), which stands for Carriage Return and Line Feed. The protocol inherited this convention from earlier Internet protocols such as SMTP. In an HTTP/1.1 request, every header ends with \r\n, and an additional empty \r\n line indicates the end of the header section and the beginning of the message body. Because the protocol is text-based, it is human-readable and can be inspected easily using tools such as Telnet, Netcat, Wireshark, or Burp Suite.

```
Request Line\r\n
Header 1\r\n
Header 2\r\n
Header 3\r\n
\r\n
Body

```
</br>
</br>

### Q2 Which version of the HTTP protocol uses a binary format and clearly defines boundaries for elements in requests/responses?
> HTTP/2

**Explaination :** 
HTTP/2 uses a binary framing layer instead of plain text. Requests and responses are split into structured frames such as HEADERS and DATA frames. Multiple related frames are grouped into a stream, which represents a single HTTP request/response exchange. Each frame contains metadata such as its length, type, flags, and stream identifier, allowing the receiver to determine exactly where the frame begins and ends and which stream it belongs to. This design enables multiplexing, reduces protocol overhead, improves parsing efficiency, and provides better performance than HTTP/1.1.
```
Stream 1

HEADERS Frame
  :method = POST
  :path = /login

DATA Frame
  username=admin

DATA Frame
  password=123

END_STREAM

```
