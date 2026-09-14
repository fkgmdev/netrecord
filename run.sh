cargo build --release && sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/netrecord && ./target/release/netrecord
