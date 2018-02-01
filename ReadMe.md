# shm


shm is Golang shared memory library.

## History
* Feb 1st 2018 to make the first release 0.0.2

## Example

```go
w, _ := shm.Create("shm_name", 256,false)
defer w.Close()

r, _ := shm.Open("shm_name", 256,false)
defer r.Close()

wbuf := []byte("Hello World")
w.Write(wbuf)

rbuf := make([]byte, len(wbuf))
r.Read(rbuf)
// rbuf == wbuf
```

