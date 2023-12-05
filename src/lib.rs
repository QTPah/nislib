use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::io::Write;
use log::*;

use palserializer::deserialize_be;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

mod tcpserver;
pub mod networking;
pub mod srsa;

use tcpserver::*;
use networking::*;

pub struct Node {
    pub parent_public_key: Arc<RwLock<Option<RsaPublicKey>>>,
    pub children: Arc<RwLock<Vec<RemoteNode>>>,
    pub keypair: Arc<RwLock<(RsaPublicKey, RsaPrivateKey)>>,
    pub server: Arc<RwLock<TcpServer>>,

    pub client: Arc<RwLock<Option<TcpClient>>>,
    fallback_address: Arc<RwLock<String>>,
    next_origin: Arc<RwLock<Option<(RemoteNode, String)>>>,
    listener_address: Arc<String>,
    riddle_cache: Arc<RwLock<Vec<(SocketAddr, [u8; 512], RsaPublicKey)>>>,
    events: Arc<RwLock<NodeEvents>>
}

#[derive(Clone)]
pub struct RemoteNode {
    pub public_key: RsaPublicKey,
    pub address: Option<SocketAddr>,
    pub listener_address: Option<String>
}

#[derive(Clone)]
pub struct NodeEvents {
    pub on_child_connect: Arc<dyn Fn(RemoteNode) + Send + Sync>,
    pub on_child_disconnect: Arc<dyn Fn(RemoteNode) + Send + Sync>,
    pub on_ready: Arc<dyn Fn() + Send + Sync>,
    pub on_disconnect: Arc<dyn Fn() + Send + Sync>,
    pub on_data: Arc<dyn Fn(RemoteNode, &[u8]) + Send + Sync>,
}

pub struct NodeOptions {
    pub connect_to: Option<String>
}

impl Node {
    pub fn new(listen_on: String, profile: (RsaPrivateKey, RsaPublicKey)) -> Node {

        let (private_key, public_key) = profile;

        debug!("Starting server on {}...", listen_on.clone());
        let server = TcpServer::new(listen_on.clone()).unwrap();
            
        Node {
            parent_public_key: Arc::new(RwLock::new(None)),
            children: Arc::new(RwLock::new(vec![])),
            keypair: Arc::new(RwLock::new((public_key, private_key))),
            server: Arc::new(RwLock::new(server)),
            client: Arc::new(RwLock::new(None)),
            fallback_address: Arc::new(RwLock::new(String::new())),
            listener_address: Arc::new(listen_on),
            next_origin: Arc::new(RwLock::new(None)),
            riddle_cache: Arc::new(RwLock::new(vec![])),
            events: Arc::new(RwLock::new(NodeEvents {
                on_child_connect: Arc::new(|_| {}),
                on_child_disconnect: Arc::new(|_| {}),
                on_ready: Arc::new(|| {}),
                on_disconnect: Arc::new(|| {}),
                on_data: Arc::new(|_, _| {}),
            }))
        }
    }

    pub fn connect(&self, events: NodeEvents, options: NodeOptions) {
        *self.events.write().unwrap() = events;

        if let Some(connect_to) = options.connect_to {
            debug!("Connecting to parent {}...", connect_to.clone());
            self.client.write().unwrap().replace(TcpClient::new(connect_to.clone().as_str()).unwrap());

            let client = Arc::clone(&self.client);
            let client2 = Arc::clone(&self.client);
            let client3 = Arc::clone(&self.client);
            let keypair: Arc<RwLock<(RsaPublicKey, RsaPrivateKey)>> = Arc::clone(&self.keypair);
            let keypair2: Arc<RwLock<(RsaPublicKey, RsaPrivateKey)>> = Arc::clone(&self.keypair);
            let parent_public_key = Arc::clone(&self.parent_public_key);
            let server = Arc::clone(&self.server);
            let server3 = Arc::clone(&self.server);

            let events = Arc::clone(&self.events);
            let events3 = Arc::clone(&self.events);

            let fallback_address = Arc::clone(&self.fallback_address);
            let fallback_address3 = Arc::clone(&self.fallback_address);
            let next_origin = Arc::clone(&self.next_origin);
            let children = Arc::clone(&self.children);

            let listener_address = Arc::clone(&self.listener_address);
            let listener_address3 = Arc::clone(&self.listener_address);

            let client_events = ClientEvents {
                data: Arc::new(move |data| {
                    let client: Arc<RwLock<Option<TcpClient>>> = Arc::clone(&client);

                    let packet = Packet::from_bytes(data);
    
                    match packet.packet_type {
                        PacketType::RRequest => {
                            client.write().unwrap().as_mut().unwrap().send(
                                &Packet::new(PacketType::Error,
                                    b"Riddle Request sent to a Client instead of Server".to_vec(),
                                    vec![], vec![]
                                ).to_bytes()
                            ).unwrap();
                            warn!("Parent {} sent Riddle Request to a Client instead of Server",
                                Arc::clone(&client).read().unwrap().as_ref().unwrap().stream.peer_addr().unwrap());
                        },
                        PacketType::RResponse => {
                            client.write().unwrap().as_mut().unwrap().send(
                                &Packet::new(PacketType::CReport,
                                    palserializer::serialize_be(&[
                                        srsa::decrypt(keypair.read().unwrap().1.clone(), packet.payload.to_vec()).unwrap().as_slice(),
                                        listener_address.clone().as_bytes()
                                    ]).unwrap(),
                                    vec![], vec![]
                                ).to_bytes()
                            ).unwrap();
                            debug!("Got Riddle Response from Parent");
                        },
                        PacketType::CReport => {
                            client.write().unwrap().as_mut().unwrap().send(
                                &Packet::new(PacketType::Error,
                                    b"Completion Report sent to a Client instead of Server".to_vec(),
                                    vec![], vec![]
                                ).to_bytes()
                            ).unwrap();
                            warn!("Parent {} sent Completion Report to a Client instead of Server",
                                Arc::clone(&client).read().unwrap().as_ref().unwrap().stream.peer_addr().unwrap());
                        },
                        PacketType::Validation => {
                            parent_public_key.write().as_mut().unwrap().replace(
                                RsaPublicKey::from_pkcs1_der(&packet.payload).unwrap()
                            );
    
                            debug!("Got Validation from Parent {}! Public Key: {}",
                                client.read().unwrap().as_ref().unwrap().stream.peer_addr().unwrap(),
                                srsa::bytes_to_hex(&packet.payload));

                            (events.write().unwrap().on_ready)();

                            // Get fallback address

                            client.write().unwrap().as_mut().unwrap().send(
                                &Packet::new(PacketType::GetFallback,
                                    vec![], vec![], vec![]
                                ).to_bytes()
                            ).unwrap();
                        },
                        PacketType::Error => {
                            error!("{} sent an Error packet: {}",
                                client.read().unwrap().as_ref().unwrap().stream.peer_addr().unwrap(),
                                String::from_utf8(packet.payload).unwrap());
                        },
                        PacketType::GetFallback => {

                            if client.read().unwrap().is_none() {
                                client.write().unwrap().as_mut().unwrap().send(
                                    &Packet::new(PacketType::Error,
                                        b"Validation not received".to_vec(),
                                        vec![], vec![]
                                    ).to_bytes()
                                ).unwrap();
    
                                warn!("{} sent a GetFallback without a Validation",
                                    client.read().unwrap().as_ref().unwrap().stream.peer_addr().unwrap());

                                return;
                            }

                            *fallback_address.write().unwrap() = String::from_utf8(packet.payload).unwrap();

                            debug!("Got Fallback Address from Parent: {}",
                                fallback_address.read().unwrap());
                        },
                        PacketType::Message => {
                            debug!("Got Message from Parent");

                            if parent_public_key.read().unwrap().is_none() {
                                client.write().unwrap().as_mut().unwrap().send(
                                    &Packet::new(PacketType::Error,
                                        b"Validation not received".to_vec(),
                                        vec![], vec![]
                                    ).to_bytes()
                                ).unwrap();
    
                                warn!("{} sent a Message without a Validation",
                                    client.read().unwrap().as_ref().unwrap().stream.peer_addr().unwrap());

                                return;
                            }

                            let destination = RsaPublicKey::from_pkcs1_der(&packet.destination);
                            let source = RsaPublicKey::from_pkcs1_der(&packet.source);

                            if (destination.is_err() && &packet.destination != &vec![1, 1, 1, 1]) || source.is_err() {    
                                warn!("{} sent a Message with a bad src/dst",
                                    client.read().unwrap().as_ref().unwrap().stream.peer_addr().unwrap());

                                return;
                            }

                            let source = source.unwrap();

                            if packet.destination.clone() == vec![1, 1, 1, 1] || destination.clone().unwrap() == keypair.read().unwrap().0.clone() {

                                debug!("Decrypting...");

                                let packet = packet.clone().decrypt(keypair.read().unwrap().1.clone());

                                (events.write().unwrap().on_data)(
                                    RemoteNode {
                                        address: None,
                                        listener_address: None,
                                        public_key: source.clone()
                                    },
                                    &packet.payload
                                );

                            } 
                            if packet.destination.clone() == vec![1, 1, 1, 1] || destination.clone().unwrap() != keypair.read().unwrap().0.clone() {
                                debug!("Forwarding...");

                                server.write().unwrap().connections.write().unwrap().iter_mut().for_each(|x| {
                                    x.write(&packet.to_bytes()).unwrap();
                                });
                            }
                            
                        }
                    }
                }),
                connect: Arc::new(move || {
                
                    // Nislib connection protocol: Riddle Request
    
                    client2.write().unwrap().as_mut().unwrap().send(
                        &Packet::new(PacketType::RRequest,
                            keypair2.read().unwrap().0.clone().to_pkcs1_der().unwrap().to_vec(),
                            vec![], vec![]
                        ).to_bytes()
                    ).unwrap();
    
                    debug!("Sent Riddle Request to Parent {}",
                        client2.read().unwrap().as_ref().unwrap().stream.peer_addr().unwrap());
                    
                }),
                close: Arc::new(move || {

                    if fallback_address3.read().unwrap().as_bytes() == listener_address3.as_bytes() { // If you're next origin
                        debug!("I'm origin now");
                        *client3.write().unwrap() = Option::None;

                        if children.read().unwrap().len() > 0 {
                            next_origin.write().unwrap().replace((children.read().unwrap().first().unwrap().clone(), children.read().unwrap().first().unwrap().clone().listener_address.unwrap()));

                            server3.read().unwrap().connections.write().unwrap().iter_mut().for_each(|x| {
                                x.write(&Packet::new(PacketType::GetFallback,
                                    children.read().unwrap().first().unwrap().clone().listener_address.unwrap().into_bytes(),
                                    vec![], vec![]
                                ).to_bytes()).unwrap();
                            });
                        }

                        
                    } else {
                        match client3.write().unwrap().as_mut().unwrap().reconnect(fallback_address3.read().unwrap().as_str()) {
                            Ok(_) => {
                                info!("Reconnected to fallback address {}", fallback_address3.read().unwrap());
                            },
                            Err(_) => {
                                error!("Failed to reconnect to fallback address {}", fallback_address3.read().unwrap());
                            }
                        }
                    }
    
                    (events3.write().unwrap().on_disconnect)();
                })
            };

            let client = Arc::clone(&self.client);

            client.write().unwrap().as_mut().unwrap().set_events(client_events);
            client.read().unwrap().as_ref().unwrap().listen();
        }

        let client = Arc::clone(&self.client);
        let connections = Arc::clone(&self.server).read().unwrap().connections.clone();
        let keypair: Arc<RwLock<(RsaPublicKey, RsaPrivateKey)>> = Arc::clone(&self.keypair);
        let children = Arc::clone(&self.children);
        let children3 = Arc::clone(&self.children);
        let riddle_cache = Arc::clone(&self.riddle_cache);
        let events = Arc::clone(&self.events);
        let events3 = Arc::clone(&self.events);
        let next_origin = Arc::clone(&self.next_origin);
        let next_origin3 = Arc::clone(&self.next_origin);

        Arc::clone(&self.server).write().unwrap().listen(ServerEvents {
            data: Arc::new(move |data, mut stream| {
                let packet = Packet::from_bytes(data);
    
                match packet.packet_type {
                    PacketType::RRequest => {
                        debug!("Got Riddle Request from {}",
                                stream.peer_addr().unwrap());
    
                        if riddle_cache.write().unwrap().iter().any(|x| x.0 == stream.peer_addr().unwrap()) {
    
                            warn!("{} already has a Riddle Request in the cache",
                                stream.peer_addr().unwrap());
    
                            stream.write(&Packet::new(PacketType::Error,
                                b"Riddle already sent".to_vec(),
                                vec![], vec![]
                            ).to_bytes()).unwrap();
    
                            return;
                        }
    
                        // Generate random riddle
                        let mut riddle = [0; 512];
                        for i in 0..512 {
                            riddle[i] = rand::random::<u8>();
                        }
                        
                        riddle_cache.write().unwrap().push((stream.peer_addr().unwrap(), riddle, RsaPublicKey::from_pkcs1_der(&packet.payload).unwrap()));
    
                        stream.write(&Packet::new(PacketType::RResponse,
                            srsa::encrypt(RsaPublicKey::from_pkcs1_der(&packet.payload).unwrap(), riddle.to_vec()).unwrap().to_vec(),
                            vec![], vec![]
                        ).to_bytes()).unwrap();
    
                        debug!("Sent Riddle Response to {}",
                                stream.peer_addr().unwrap());
                    },
                    PacketType::RResponse => {
                        stream.write(&Packet::new(PacketType::Error,
                            b"Riddle Response sent to a Server instead of Client".to_vec(),
                            vec![], vec![]
                        ).to_bytes()).unwrap();
                        warn!("{} sent Riddle Response to a Server instead of Client",
                                stream.peer_addr().unwrap());
                    },
                    PacketType::CReport => {
                        if !riddle_cache.read().unwrap().iter().any(|x| x.0 == stream.peer_addr().unwrap()) {
    
                            warn!("{} sent a Completion Report without a Riddle Request",
                                stream.peer_addr().unwrap());
    
                            stream.write(&Packet::new(PacketType::Error,
                                b"Riddle Request not sent".to_vec(),
                                vec![], vec![]
                            ).to_bytes()).unwrap();
    
                            return;
                        }
    
                        let cache_register = riddle_cache.read().unwrap().iter().find(|x| x.0 == stream.peer_addr().unwrap()).unwrap().clone();
    
                        // First: Riddle, Second: Server address
                        let deserialized = deserialize_be(packet.payload.as_slice());

                        if deserialized.is_err() {
                            warn!("{} sent a Completion Report with a false Riddle Response",
                                stream.peer_addr().unwrap());
    
                            stream.write(&Packet::new(PacketType::Error,
                                b"Riddle Response false".to_vec(),
                                vec![], vec![]
                            ).to_bytes()).unwrap();
    
                            riddle_cache.write().unwrap().retain(|x| x.0 != stream.peer_addr().unwrap());
    
                            return;
                        }

                        if &cache_register.1 != deserialized.clone().unwrap()[0].as_slice() {
    
                            warn!("{} sent a Completion Report with an incorrect Riddle Response",
                                stream.peer_addr().unwrap());
    
                            stream.write(&Packet::new(PacketType::Error,
                                b"Riddle Response incorrect".to_vec(),
                                vec![], vec![]
                            ).to_bytes()).unwrap();
    
                            riddle_cache.write().unwrap().retain(|x| x.0 != stream.peer_addr().unwrap());
    
                            return;
                        }
    
                        debug!("{} sent a Completion Report with a correct Riddle Response",
                                stream.peer_addr().unwrap());
    
                        children.write().unwrap().push(RemoteNode {
                            address: Some(stream.peer_addr().unwrap()),
                            listener_address: Some(String::from_utf8(deserialized.clone().unwrap()[1].clone()).unwrap()),
                            public_key: cache_register.2.clone()
                        });

                        debug!("-1");
    
                        riddle_cache.write().unwrap().retain(|x| x.0 != stream.peer_addr().unwrap());
    
                        debug!("0");

                        (events.write().unwrap().on_child_connect)(RemoteNode {
                            address: Some(stream.peer_addr().unwrap()),
                            listener_address: Some(String::from_utf8(deserialized.clone().unwrap()[1].clone()).unwrap()),
                            public_key: cache_register.2.clone()
                        });

                        debug!("1");

                        if client.read().unwrap().is_none() && next_origin.read().unwrap().is_none() {
                            debug!("{}/{} is future origin",
                                stream.peer_addr().unwrap(), String::from_utf8(deserialized.clone().unwrap()[1].clone()).unwrap());
                            next_origin.write().unwrap().replace((RemoteNode {
                                address: None,
                                listener_address: None,
                                public_key: cache_register.2.clone()
                            }, String::from_utf8(deserialized.unwrap()[1].clone()).unwrap()));
                        }

                        stream.write(&Packet::new(PacketType::Validation,
                            keypair.read().unwrap().0.to_pkcs1_der().unwrap().to_vec(),
                            vec![], vec![]
                        ).to_bytes()).unwrap();
                    },
                    PacketType::Validation => {
                        stream.write(&Packet::new(PacketType::Error,
                            b"Validation sent to a Server instead of Client".to_vec(),
                            vec![], vec![]
                        ).to_bytes()).unwrap();
                        warn!("{} sent Validation to a Server instead of Client",
                                stream.peer_addr().unwrap());
                    },
                    PacketType::Error => {
                        error!("{} sent an Error packet: {}",
                                stream.peer_addr().unwrap(),
                                String::from_utf8(packet.payload).unwrap());
                    },
                    PacketType::GetFallback => {
                        if !children.read().unwrap().iter().any(|x| x.address == Some(stream.peer_addr().unwrap())) {
    
                            warn!("{} sent a Message without a Validation",
                                stream.peer_addr().unwrap());
    
                            stream.write(&Packet::new(PacketType::Error,
                                b"Validation not sent".to_vec(),
                                vec![], vec![]
                            ).to_bytes()).unwrap();
    
                            return;
                        }


                        // If you're not origin, respond with your parent
                        if client.read().unwrap().is_some() {
                            stream.write(&Packet::new(PacketType::GetFallback, 
                                client.read().unwrap().as_ref().unwrap().stream.peer_addr().unwrap().to_string().into_bytes(),
                                vec![], vec![]
                            ).to_bytes()).unwrap();
                        } else { // If you ARE origin, respond with next_origin
                            stream.write(&Packet::new(PacketType::GetFallback,
                                next_origin.read().unwrap().as_ref().unwrap().1.clone().into_bytes(),
                                vec![], vec![]
                            ).to_bytes()).unwrap();
                        }

                    },
                    PacketType::Message => {
                        debug!("Got Message from {}", stream.peer_addr().unwrap());

                        if !children.read().unwrap().iter().any(|x| x.address == Some(stream.peer_addr().unwrap())) {
    
                            warn!("{} sent a Message without a Validation",
                                stream.peer_addr().unwrap());
    
                            stream.write(&Packet::new(PacketType::Error,
                                b"Validation not sent".to_vec(),
                                vec![], vec![]
                            ).to_bytes()).unwrap();
    
                            return;
                        }

                        let destination = RsaPublicKey::from_pkcs1_der(&packet.destination);
                        let source = RsaPublicKey::from_pkcs1_der(&packet.source);

                        if (destination.is_err() && &packet.destination != &vec![1, 1, 1, 1]) || source.is_err() {
                            warn!("{} sent a Message with a bad src/dst",
                                stream.peer_addr().unwrap());

                            return;
                        }
    
                        if &packet.destination == &vec![1, 1, 1, 1] || &destination.clone().unwrap() == &keypair.read().unwrap().0 {
                            debug!("Decrypting...");

                            let packet = packet.clone().decrypt(keypair.read().unwrap().1.clone());

                            (events.write().unwrap().on_data)(
                                children.read().unwrap().iter().find(|x| x.address == Some(stream.peer_addr().unwrap())).unwrap().clone(),
                                &packet.payload
                            );

                        } 
                        if &packet.destination == &vec![1, 1, 1, 1] || &destination.unwrap() != &keypair.read().unwrap().0 {
                            debug!("Forwarding...");

                            connections.write().unwrap().iter_mut().for_each(|x| {
                                if x.peer_addr().unwrap() != stream.peer_addr().unwrap() {
                                    x.write(&packet.to_bytes()).unwrap();
                                }
                            });

                            if client.read().unwrap().is_some() {
                                client.write().unwrap().as_mut().unwrap().send(&packet.to_bytes()).unwrap();
                            }
                        }
                    }
                }
    
            }),
            connect: Arc::new(move |stream| {
                debug!("Client connected: {}", stream.peer_addr().unwrap());
            }),
            close: Arc::new(move |stream| {
                
                let child = children3.read().unwrap().iter().find(|x| x.address == Some(stream.peer_addr().unwrap())).unwrap().clone();

                children3.write().unwrap().retain(|x| x.address != Some(stream.peer_addr().unwrap()));

                if &child.public_key == &next_origin3.read().unwrap().as_ref().unwrap().0.public_key {
                    debug!("Indended next origin disconnected");
                    
                    *next_origin3.write().unwrap() = Option::None;
                }

                (events3.write().unwrap().on_child_disconnect)(child);
            }),
        });

        if Arc::clone(&self.client).read().unwrap().is_none() {
            (Arc::clone(&self.events).write().unwrap().on_ready)();
        }
    }

    pub fn broadcast(&self, data: Vec<u8>) {
        self.send(vec![1, 1, 1, 1], data);
    }

    pub fn send(&self, to: Vec<u8>, data: Vec<u8>) {
        self.send_packet(Packet::new(PacketType::Message,
            data.clone(),
            self.keypair.read().unwrap().0.to_pkcs1_der().unwrap().to_vec(), to.clone()
        ));
    }

    pub fn send_packet(&self, packet: Packet) {
        self.server.write().unwrap().connections.write().unwrap().iter_mut().filter(|x| {
            self.children.read().unwrap().iter().any(|y| Some(x.peer_addr().unwrap()) == y.address)
        }).for_each(|x| {
            x.write(&packet.to_bytes()).unwrap();
        });

        if self.client.read().unwrap().is_some() {
            self.client.write().unwrap().as_mut().unwrap().send(
                &packet.to_bytes()
            ).unwrap();
        }
    }
}