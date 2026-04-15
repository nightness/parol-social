//! Browser WebSocket transport via web-sys.
//!
//! Provides `WasmWebSocket` — a Rust wrapper around the browser's WebSocket API
//! for use in WASM. Uses JS callbacks to feed received messages into an
//! `mpsc`-style channel (implemented via `Rc<RefCell<VecDeque>>` since we're
//! single-threaded in WASM).
//!
//! This does NOT implement the native `Connection` trait (which requires
//! tokio/async_trait). Instead it provides a WASM-specific interface that
//! the future WASM circuit builder will use.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use js_sys::{ArrayBuffer, Uint8Array};
use thiserror::Error;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{BinaryType, CloseEvent, ErrorEvent, MessageEvent, WebSocket};

/// Errors from the WASM WebSocket transport.
#[derive(Debug, Error)]
pub enum WasmWebSocketError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("connection closed")]
    ConnectionClosed,
    #[error("invalid state: {0}")]
    InvalidState(String),
}

impl From<JsValue> for WasmWebSocketError {
    fn from(val: JsValue) -> Self {
        let msg = val.as_string().unwrap_or_else(|| format!("{val:?}"));
        WasmWebSocketError::ConnectionFailed(msg)
    }
}

/// Browser WebSocket wrapper.
///
/// Holds the `web_sys::WebSocket` and receives data via JS callbacks
/// into internal queues. All operations are non-blocking except
/// [`wait_open`](Self::wait_open).
pub struct WasmWebSocket {
    ws: WebSocket,
    recv_queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
    error_queue: Rc<RefCell<VecDeque<String>>>,
    opened: Rc<RefCell<bool>>,
    closed: Rc<RefCell<bool>>,
    // Store closures to prevent them from being dropped.
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_error: Closure<dyn FnMut(ErrorEvent)>,
    _on_close: Closure<dyn FnMut(CloseEvent)>,
    _on_open: Closure<dyn FnMut(JsValue)>,
}

impl WasmWebSocket {
    /// Create a new WebSocket connection to `url`.
    ///
    /// The WebSocket connects asynchronously — use [`wait_open`](Self::wait_open)
    /// to await the OPEN state before sending.
    pub fn connect(url: &str) -> Result<Self, WasmWebSocketError> {
        let ws = WebSocket::new(url).map_err(WasmWebSocketError::from)?;
        ws.set_binary_type(BinaryType::Arraybuffer);

        let recv_queue: Rc<RefCell<VecDeque<Vec<u8>>>> = Rc::default();
        let error_queue: Rc<RefCell<VecDeque<String>>> = Rc::default();
        let opened = Rc::new(RefCell::new(false));
        let closed = Rc::new(RefCell::new(false));

        // onmessage
        let rq = recv_queue.clone();
        let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
            let data = e.data();
            if let Some(buf) = data.dyn_ref::<ArrayBuffer>() {
                let arr = Uint8Array::new(buf);
                rq.borrow_mut().push_back(arr.to_vec());
            }
            // Blob handling is omitted — we set binary_type to ArrayBuffer so
            // the browser will always deliver ArrayBuffer payloads.
        });
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        // onerror
        let eq = error_queue.clone();
        let on_error = Closure::<dyn FnMut(ErrorEvent)>::new(move |e: ErrorEvent| {
            eq.borrow_mut().push_back(e.message());
        });
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        // onclose
        let cf = closed.clone();
        let on_close = Closure::<dyn FnMut(CloseEvent)>::new(move |_: CloseEvent| {
            *cf.borrow_mut() = true;
        });
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        // onopen
        let of = opened.clone();
        let on_open = Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| {
            *of.borrow_mut() = true;
        });
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        Ok(Self {
            ws,
            recv_queue,
            error_queue,
            opened,
            closed,
            _on_message: on_message,
            _on_error: on_error,
            _on_close: on_close,
            _on_open: on_open,
        })
    }

    /// Send binary data over the WebSocket.
    pub fn send(&self, data: &[u8]) -> Result<(), WasmWebSocketError> {
        if self.ws.ready_state() != WebSocket::OPEN {
            return Err(WasmWebSocketError::InvalidState(
                "WebSocket is not open".into(),
            ));
        }
        self.ws
            .send_with_u8_array(data)
            .map_err(|e| WasmWebSocketError::SendFailed(format!("{e:?}")))
    }

    /// Non-blocking receive. Returns the next queued message, or `None`.
    pub fn recv(&self) -> Result<Option<Vec<u8>>, WasmWebSocketError> {
        if let Some(err) = self.error_queue.borrow_mut().pop_front() {
            return Err(WasmWebSocketError::ConnectionFailed(err));
        }
        Ok(self.recv_queue.borrow_mut().pop_front())
    }

    /// Close the WebSocket connection.
    pub fn close(&self) -> Result<(), WasmWebSocketError> {
        self.ws
            .close()
            .map_err(|e| WasmWebSocketError::SendFailed(format!("{e:?}")))
    }

    /// Returns `true` if the WebSocket is in the OPEN state.
    pub fn is_open(&self) -> bool {
        self.ws.ready_state() == WebSocket::OPEN
    }

    /// Returns `true` if the onclose callback has fired.
    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    /// Number of messages buffered in the receive queue.
    pub fn buffered_count(&self) -> usize {
        self.recv_queue.borrow().len()
    }

    /// Access the underlying `web_sys::WebSocket` handle (for async proxying).
    pub fn ws_handle(&self) -> &WebSocket {
        &self.ws
    }

    /// Access the receive queue (for async proxying across await points).
    pub fn recv_queue_handle(&self) -> &Rc<RefCell<VecDeque<Vec<u8>>>> {
        &self.recv_queue
    }

    /// Access the error queue (for async proxying across await points).
    pub fn error_queue_handle(&self) -> &Rc<RefCell<VecDeque<String>>> {
        &self.error_queue
    }

    /// Access the opened flag (for async proxying across await points).
    pub fn opened_handle(&self) -> &Rc<RefCell<bool>> {
        &self.opened
    }

    /// Access the closed flag (for async proxying across await points).
    pub fn closed_handle(&self) -> &Rc<RefCell<bool>> {
        &self.closed
    }

    /// Wait until the WebSocket reaches the OPEN state.
    ///
    /// Yields to the browser event loop between polls so callbacks can fire.
    pub async fn wait_open(&self) -> Result<(), WasmWebSocketError> {
        loop {
            if *self.opened.borrow() {
                return Ok(());
            }
            if *self.closed.borrow() || self.ws.ready_state() >= WebSocket::CLOSING {
                return Err(WasmWebSocketError::ConnectionClosed);
            }
            // Yield to the browser event loop.
            wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&JsValue::NULL))
                .await
                .ok();
        }
    }
}

// ---------------------------------------------------------------------------
// JS-facing thin wrapper (opaque ID into a thread-local map)
// ---------------------------------------------------------------------------

thread_local! {
    pub static SOCKETS: RefCell<HashMap<u32, WasmWebSocket>> = RefCell::new(HashMap::new());
    static NEXT_ID: RefCell<u32> = const { RefCell::new(0) };
}

fn with_socket<T>(
    id: u32,
    f: impl FnOnce(&WasmWebSocket) -> Result<T, WasmWebSocketError>,
) -> Result<T, JsValue> {
    SOCKETS.with(|sockets| {
        let map = sockets.borrow();
        let ws = map
            .get(&id)
            .ok_or_else(|| JsValue::from_str("invalid socket id"))?;
        f(ws).map_err(|e| JsValue::from_str(&e.to_string()))
    })
}

/// Open a WebSocket connection. Returns an opaque handle ID.
#[wasm_bindgen]
pub fn ws_connect(url: &str) -> Result<u32, JsValue> {
    let ws = WasmWebSocket::connect(url).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let id = NEXT_ID.with(|n| {
        let mut n = n.borrow_mut();
        let id = *n;
        *n = n.wrapping_add(1);
        id
    });
    SOCKETS.with(|sockets| sockets.borrow_mut().insert(id, ws));
    Ok(id)
}

/// Wait for the WebSocket to reach the OPEN state.
#[wasm_bindgen]
pub async fn ws_wait_open(id: u32) -> Result<(), JsValue> {
    // We need to borrow the socket only briefly to start the future,
    // but wait_open borrows &self for the duration. Since we're single-threaded
    // in WASM we can safely work with the Rc internals directly.
    let (opened, closed, ws_raw) = SOCKETS.with(|sockets| {
        let map = sockets.borrow();
        let ws = map
            .get(&id)
            .ok_or_else(|| JsValue::from_str("invalid socket id"))?;
        Ok::<_, JsValue>((ws.opened.clone(), ws.closed.clone(), ws.ws.clone()))
    })?;

    loop {
        if *opened.borrow() {
            return Ok(());
        }
        if *closed.borrow() || ws_raw.ready_state() >= WebSocket::CLOSING {
            return Err(JsValue::from_str("WebSocket closed before opening"));
        }
        wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&JsValue::NULL))
            .await
            .ok();
    }
}

/// Send binary data on a WebSocket.
#[wasm_bindgen]
pub fn ws_send(id: u32, data: &[u8]) -> Result<(), JsValue> {
    with_socket(id, |ws| ws.send(data))
}

/// Non-blocking receive. Returns a `Uint8Array` or `null`.
#[wasm_bindgen]
pub fn ws_recv(id: u32) -> Result<JsValue, JsValue> {
    with_socket(id, |ws| {
        ws.recv().map(|opt| match opt {
            Some(bytes) => {
                let arr = Uint8Array::new_with_length(bytes.len() as u32);
                arr.copy_from(&bytes);
                arr.into()
            }
            None => JsValue::NULL,
        })
    })
}

/// Close a WebSocket.
#[wasm_bindgen]
pub fn ws_close(id: u32) -> Result<(), JsValue> {
    with_socket(id, |ws| ws.close())
}

/// Check whether a WebSocket is in the OPEN state.
#[wasm_bindgen]
pub fn ws_is_open(id: u32) -> bool {
    with_socket(id, |ws| Ok(ws.is_open())).unwrap_or(false)
}
