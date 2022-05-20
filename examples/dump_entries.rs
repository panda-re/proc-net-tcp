use proc_net_tcp::{socket_info, SocketEntry};

fn print_socket(socket: &SocketEntry) {
    let pid = socket
        .owning_pid
        .as_ref()
        .map(u64::to_string)
        .unwrap_or_else(|| String::from("???"));

    let local = socket.local_address;
    let remote = socket.remote_address;
    let server_or_client = if socket.is_listening() {
        "server"
    } else {
        "client"
    };

    println!("PID {pid} bound on {local:?}, remote of {remote:?} (TCP {server_or_client})");
}

fn main() {
    for socket in socket_info() {
        let socket = socket.unwrap();

        print_socket(&socket);
    }

    for socket in socket_info() {
        let socket = socket.unwrap();

        let addr = socket.local_address;
        let listening = socket.is_listening();
        println!("Socket Address: {addr:?}, Listening: {listening:?}");
    }
}
