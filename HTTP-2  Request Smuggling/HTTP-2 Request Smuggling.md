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

## TASK 2

## H2.CL Attack

H2.CL stands for HTTP/2 / Content-Length.

In an H2.CL attack, the frontend server accepts HTTP/2 requests and then downgrades them to HTTP/1.1 before forwarding them to the backend server.

The problem occurs because the frontend and backend determine the end of a request differently:

The frontend uses HTTP/2 frames to determine where the request ends.
The backend uses the Content-Length header after the request is converted to HTTP/1.1.

An attacker sends an HTTP/2 request and manually includes:

Content-Length: 0

Even though HTTP/2 does not rely on Content-Length for request framing, some proxies copy this header when converting the request to HTTP/1.1.

As a result:

* The frontend reads the complete HTTP/2 request using HTTP/2 framing.
* The request is downgraded to HTTP/1.1.
* The backend sees Content-Length: 0 and assumes the request body is empty.
* Any remaining data is interpreted as a new HTTP/1.1 request.
* This allows the attacker to smuggle a hidden request to the backend.

## H2.TE Attack

H2.TE Attack

H2.TE stands for HTTP/2 / Transfer-Encoding.

In an H2.TE attack, the frontend server accepts HTTP/2 requests and then downgrades them to HTTP/1.1 before forwarding them to the backend server.

The problem occurs because the frontend and backend determine the end of a request differently:

The frontend uses HTTP/2 frames to determine where the request ends.
The backend uses the Transfer-Encoding: chunked header after the request is converted to HTTP/1.1.

An attacker sends an HTTP/2 request and manually includes:

Transfer-Encoding: chunked

Even though Transfer-Encoding has no meaning in HTTP/2, some proxies incorrectly copy this header when converting the request to HTTP/1.1.

The attacker then sends a chunked body that contains a:

0

chunk terminator, followed by additional data.

In chunked encoding, a chunk size of 0 indicates the end of the request body.

As a result:

* The frontend reads the complete HTTP/2 request using HTTP/2 framing.
* The request is downgraded to HTTP/1.1.
* The backend sees Transfer-Encoding: chunked.
* When the backend encounters the 0 chunk, it assumes the request has ended.
* Any remaining data is interpreted as a new HTTP request.
* This allows an attacker to smuggle a hidden request to the backend.

### Q1 Repeat the request shown in the practical example against the app and wait for a user to fall for our trap. What is the username of the victim user who liked our post?
> THM{my_name_is_a_flag}

**Explaination :**
To exploit the vulnerability, I sent the following HTTP/2 request:
```
POST /post/12315198742342 HTTP/2
Host: 10.48.182.31:8000
Cookie: sessid=ba89f897ef7f68752abc
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /post/like/12315198742342 HTTP/1.1
foo: bar
```
The frontend server accepted the request as HTTP/2, but due to the request smuggling vulnerability, the embedded HTTP/1.1 request was forwarded to the backend as a separate request.

The smuggled request: GET /post/like/12315198742342 HTTP/1.1

was left in the backend connection queue. When another user later reused the same backend connection, the queued request was processed using the victim's session.

As a result, the victim user unknowingly liked the post.

## Task 3

### H2 CRLF Injection — Header Leaking Attack
This attack is specifically called H2 CRLF Injection to Leak Internal Headers. It is a variant of HTTP Request Smuggling where the goal is not to attack another user, but to reveal hidden internal headers that the frontend proxy secretly adds to every request before forwarding it to the backend.

The frontend proxy was silently injecting internal headers like x-thm-flag and Host into every request before passing it to the backend. These headers are invisible to the attacker from the outside. To smuggle a successful request later, or simply to find sensitive information, we first needed to know what those hidden headers looked like.

# Q1 What's the value of the leaked internal header?
> THM{not_secret_anymore}

**Expalaination :**</br>
From the lab instructions, it was mentioned that the frontend proxy preserves the Content-Length header when downgrading from HTTP/2 to HTTP/1.1. This told me that the backend relies on Content-Length to determine where a request ends, not Transfer-Encoding.

Knowing this, I added a custom foo header to my HTTP/2 request and injected a new complete HTTP/1.1 request inside its value using CRLF characters via Burp.
When the frontend downgraded to HTTP/1.1, the injected \r\n\r\n split the request. The Content-Length: 0 I injected made the backend treat request 1 as having no body.

Since the backend was trusting Content-Length, it then read everything that came after as a brand new request — which was exactly my smuggled POST /hello with Content-Length: 300 and body q=.

The backend obeyed that Content-Length: 300, greedily consumed the next 300 bytes from the pipeline — which happened to be the internal proxy headers — and reflected them back in the response, leaking the x-thm-flag.


```
Payload
--------------------------------
foo: bar\r\n
Host: 10.48.135.151:8100\r\n
\r\n
POST /hello HTTP/1.1\r\n
Host: 10.48.159.191:8100\r\n
Content-Length: 400\r\n
Content-Type: application/x-www-form-urlencoded\r\n
\r\n
q=Search
```
