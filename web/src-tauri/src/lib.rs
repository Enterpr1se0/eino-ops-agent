use serde::Deserialize;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tauri::{Manager, RunEvent};
use tauri_plugin_shell::{ShellExt, process::CommandEvent};

const READY_PREFIX: &str = "OPSPILOT_DESKTOP_READY=";

#[derive(Default)]
struct SidecarState(Mutex<Option<tauri_plugin_shell::process::CommandChild>>);

#[derive(Debug, Deserialize, PartialEq)]
struct DesktopReady {
    url: String,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_shell::init())
        .manage(SidecarState::default())
        .setup(start_sidecar)
        .build(tauri::generate_context!())
        .expect("failed to build OpsPilot desktop application");

    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(child) = handle.state::<SidecarState>().0.lock().unwrap().take() {
                let _ = child.kill();
            }
        }
    });
}

fn start_sidecar(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&data_dir)?;

    let command = app
        .shell()
        .sidecar("ops-agent")?
        .env("OPS_AGENT_HOME", &data_dir)
        .env("OPS_AGENT_DESKTOP", "true")
        .env("OPS_AGENT_LISTEN", "127.0.0.1:0")
        .current_dir(&data_dir);
    let (mut events, child) = command.spawn()?;
    app.state::<SidecarState>().0.lock().unwrap().replace(child);

    let handle = app.handle().clone();
    let ready = Arc::new(AtomicBool::new(false));
    let event_ready = Arc::clone(&ready);
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                CommandEvent::Stdout(bytes) => {
                    let line = String::from_utf8_lossy(&bytes);
                    match parse_ready(&line) {
                        Ok(Some(response)) => {
                            event_ready.store(true, Ordering::Release);
                            open_application(&handle, response);
                        }
                        Ok(None) => {}
                        Err(error) => show_startup_error(
                            &handle,
                            format!("Invalid backend startup response: {error}"),
                        ),
                    }
                }
                CommandEvent::Error(error) => show_startup_error(&handle, error),
                CommandEvent::Terminated(status) if !event_ready.load(Ordering::Acquire) => {
                    show_startup_error(
                        &handle,
                        format!(
                            "Backend stopped before the application was ready ({:?}).",
                            status.code
                        ),
                    );
                }
                _ => {}
            }
        }
    });

    let timeout_handle = app.handle().clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(90));
        if !ready.load(Ordering::Acquire) {
            if let Some(child) = timeout_handle
                .state::<SidecarState>()
                .0
                .lock()
                .unwrap()
                .take()
            {
                let _ = child.kill();
            }
            show_startup_error(
                &timeout_handle,
                "Backend startup timed out after 90 seconds.".into(),
            );
        }
    });
    Ok(())
}

fn open_application(app: &tauri::AppHandle, ready: DesktopReady) {
    let destination = match application_url(&ready) {
        Ok(url) => url,
        Err(error) => {
            show_startup_error(app, format!("Invalid backend URL: {error}"));
            return;
        }
    };
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.navigate(destination);
    }
}

fn parse_ready(line: &str) -> Result<Option<DesktopReady>, serde_json::Error> {
    let Some(payload) = line.trim().strip_prefix(READY_PREFIX) else {
        return Ok(None);
    };
    serde_json::from_str(payload).map(Some)
}

fn application_url(ready: &DesktopReady) -> Result<tauri::Url, String> {
    let destination = ready
        .url
        .parse::<tauri::Url>()
        .map_err(|error| error.to_string())?;
    if destination.scheme() != "http"
        || destination.host_str() != Some("127.0.0.1")
        || destination.port().is_none()
        || !destination.username().is_empty()
        || destination.password().is_some()
    {
        return Err("backend URL must use an explicit 127.0.0.1 HTTP port".into());
    }
    Ok(destination)
}

fn show_startup_error(app: &tauri::AppHandle, message: String) {
    if let Some(window) = app.get_webview_window("main") {
        let localized = format!("本地服务启动失败 / Local service failed to start: {message}");
        let argument =
            serde_json::to_string(&localized).unwrap_or_else(|_| "\"Startup failed\"".into());
        let _ = window.eval(&format!("window.desktopStartupError({argument})"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_desktop_ready_event() {
        assert_eq!(parse_ready("ordinary log line").unwrap(), None);
        let ready = parse_ready(
            r#"OPSPILOT_DESKTOP_READY={"url":"http://127.0.0.1:49152"}"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            ready,
            DesktopReady {
                url: "http://127.0.0.1:49152".into(),
            }
        );
    }

    #[test]
    fn uses_backend_url_without_credentials() {
        let ready = DesktopReady {
            url: "http://127.0.0.1:49152".into(),
        };
        let url = application_url(&ready).unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:49152/");
    }

    #[test]
    fn rejects_non_loopback_backend_url() {
        let ready = DesktopReady {
            url: "https://example.com/".into(),
        };
        assert!(application_url(&ready).is_err());
    }
}
