# proc-net-tcp

Library for parsing linux's procfs /proc/net/tcp for system socket information.

```rust
use proc_net_tcp::socket_info;

for socket in socket_info() {
    let socket = socket.unwrap();

    // For an example with more fields see examples/dump_entries.rs
    let addr = socket.local_address;
    let listening = socket.is_listening();
    println!("Socket Address: {addr:?}, Listening: {listening:?}");
}
```
