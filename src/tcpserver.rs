use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::io::{Read, Write};

pub struct ServerEvents {
    pub data: Arc<dyn Fn(&[u8], &TcpStream) + Send + Sync>,
    pub connect: Arc<dyn Fn(&TcpStream) + Send + Sync>,
    pub close: Arc<dyn Fn(&TcpStream) + Send + Sync>,
}

pub struct ClientEvents {
    pub data: Arc<dyn Fn(&[u8]) + Send + Sync>,
    pub connect: Arc<dyn Fn() + Send + Sync>,
    pub close: Arc<dyn Fn() + Send + Sync>,
}

pub struct TcpServer {
    pub listener: Arc<RwLock<TcpListener>>,
    pub connections: Arc<RwLock<Vec<TcpStream>>>,
}

pub struct TcpClient {
    pub stream: TcpStream,
    events: ClientEvents,
}

impl TcpServer {
    pub fn new(address: String) -> Result<TcpServer, std::io::Error> {
        Ok(TcpServer {
            listener: Arc::new(RwLock::new(TcpListener::bind(address)?)),
            connections: Arc::new(RwLock::new(vec![])),
        })
    }

    pub fn listen(&mut self, events: ServerEvents) {
        let connections_clone = self.connections.clone();
        let events = Arc::new(events);
        let listener = self.listener.clone();

        std::thread::spawn(move || {
            for stream in listener.write().unwrap().incoming() {
                match stream {
                    Ok(stream) => {
                        let mut connections = connections_clone.write().unwrap();
                        connections.push(stream.try_clone().unwrap());
                        let data = events.data.clone();
                        let connect = events.connect.clone();
                        let close = events.close.clone();

                        connect(&stream);

                        let connections_clone = Arc::clone(&connections_clone);
                        std::thread::spawn(move || {
                            let mut stream = stream;
                            let mut buf = [0; 1024];
                            loop {
                                match stream.read(&mut buf) {
                                    Ok(size) => {
                                        if size == 0 {
                                            close(&stream);
                                            connections_clone.write().unwrap().retain(|x| x.peer_addr().unwrap() != stream.peer_addr().unwrap());
                                            break;
                                        }
                                        data(&buf[0..size], &stream);
                                    }
                                    Err(_) => {
                                        close(&stream);
                                        connections_clone.write().unwrap().retain(|x| x.peer_addr().unwrap() != stream.peer_addr().unwrap());
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        });
    }
}

impl TcpClient {
    pub fn new(address: &str) -> Result<TcpClient, std::io::Error> {
        let stream = TcpStream::connect(address)?;

        Ok(TcpClient {
            stream,
            events: ClientEvents {
                data: Arc::new(|_| {}),
                connect: Arc::new(|| {}),
                close: Arc::new(|| {}),
            },
        })
    }

    pub fn reconnect(&mut self, address: &str) -> Result<(), std::io::Error> {
        self.stream = TcpStream::connect(address)?;
        self.listen();
        Ok(())
    }

    pub fn set_events(&mut self, events: ClientEvents) {
        self.events = events;
    }

    pub fn listen(&self) {

        let data = Arc::clone(&self.events.data);
        let connect = Arc::clone(&self.events.connect.clone());
        let close = Arc::clone(&self.events.close.clone());

        let mut stream = self.stream.try_clone().unwrap();

        std::thread::spawn(move || {
            connect();
            let mut buf = [0; 1024];
            loop {
                match stream.read(&mut buf) {
                    Ok(size) => {
                        if size == 0 {
                            close();
                            break;
                        }
                        data(&buf[0..size]);
                    }
                    Err(_) => {
                        close();
                        break;
                    }
                }
            }
        });

    }

    pub fn send(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        self.stream.write(data)?;
        Ok(())
    }
}