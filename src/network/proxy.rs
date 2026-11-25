use std::ptr::null;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use url::Url;
use windows_sys::Win32::Foundation::GlobalFree;
use windows_sys::Win32::Networking::WinHttp::*;
use windows_sys::core::w;

use super::Destination;

pub async fn connect(destination: Destination) -> Result<TcpStream> {
    let host = destination.hostname();
    tokio::time::timeout(Duration::from_secs(15), async {
        let proxy = tokio::task::spawn_blocking(move || proxy_for(host)).await??;
        let Some(proxy) = proxy else {
            return Ok(TcpStream::connect((host, 443)).await?);
        };
        let url = Url::parse(&proxy).context("invalid CONNECT proxy URL")?;
        ensure!(
            url.scheme() == "http" && url.username().is_empty() && url.password().is_none(),
            "the APDU relay requires an unauthenticated HTTP CONNECT proxy"
        );
        let mut stream = TcpStream::connect((
            url.host_str().context("missing proxy host")?,
            url.port_or_known_default().context("missing proxy port")?,
        ))
        .await?;
        stream
            .write_all(
                format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            ensure!(headers.len() < 8192, "CONNECT response headers too large");
            headers.push(stream.read_u8().await?);
        }
        let status = headers.split(|&byte| byte == b' ').nth(1);
        ensure!(status == Some(b"200"), "CONNECT proxy refused the tunnel");
        Ok(stream)
    })
    .await
    .context("APDU socket or proxy connection timed out")?
}

fn proxy_for(host: &str) -> Result<Option<String>> {
    if let Ok(bypass) = std::env::var("NO_PROXY")
        && bypass.split(',').any(|entry| matches_host(host, entry))
    {
        return Ok(None);
    }
    if let Some(proxy) = ["HTTPS_PROXY", "ALL_PROXY"]
        .into_iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|value| !value.trim().is_empty())
    {
        return Ok(Some(proxy_url(proxy.trim())));
    }
    let mut config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
    if unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut config) } == 0 {
        return Ok(None);
    }
    let static_proxy = unsafe { copy_wide(config.lpszProxy) };
    let static_bypass = unsafe { copy_wide(config.lpszProxyBypass) };
    let script = unsafe { copy_wide(config.lpszAutoConfigUrl) };
    let autodetect = config.fAutoDetect != 0;
    if let Some(bypass) = static_bypass
        && bypass
            .split([';', ' '])
            .any(|entry| matches_host(host, entry))
    {
        return Ok(None);
    }
    if script.is_some() || (autodetect && static_proxy.is_none()) {
        let address: Vec<u16> = format!("https://{host}/")
            .encode_utf16()
            .chain([0])
            .collect();
        let script_wide = script
            .as_deref()
            .map(|script| script.encode_utf16().chain([0]).collect::<Vec<_>>());
        let mut options = WINHTTP_AUTOPROXY_OPTIONS {
            dwFlags: match (autodetect, script_wide.is_some()) {
                (true, true) => WINHTTP_AUTOPROXY_AUTO_DETECT | WINHTTP_AUTOPROXY_CONFIG_URL,
                (true, false) => WINHTTP_AUTOPROXY_AUTO_DETECT,
                _ => WINHTTP_AUTOPROXY_CONFIG_URL,
            },
            dwAutoDetectFlags: WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A,
            lpszAutoConfigUrl: script_wide.as_ref().map_or(null(), Vec::as_ptr),
            ..Default::default()
        };
        let session = unsafe {
            WinHttpOpen(
                w!("Codex APDU"),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                null(),
                null(),
                0,
            )
        };
        if !session.is_null() {
            unsafe { WinHttpSetTimeouts(session, 4000, 4000, 4000, 4000) };
            let mut result = WINHTTP_PROXY_INFO::default();
            let resolved = unsafe {
                WinHttpGetProxyForUrl(session, address.as_ptr(), &mut options, &mut result)
            };
            unsafe { WinHttpCloseHandle(session) };
            let proxy = unsafe { copy_wide(result.lpszProxy) };
            let _ = unsafe { copy_wide(result.lpszProxyBypass) };
            if resolved != 0 {
                return Ok(proxy.as_deref().and_then(select_https));
            }
        }
        ensure!(
            script.is_none() || static_proxy.is_some(),
            "Windows proxy script could not be resolved"
        );
    }
    Ok(static_proxy.as_deref().and_then(select_https))
}

fn matches_host(host: &str, entry: &str) -> bool {
    let entry = entry.trim().trim_end_matches(":443");
    if entry == "*" {
        return true;
    }
    if let Some(suffix) = entry.strip_prefix("*.") {
        return host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'));
    }
    let entry = entry.trim_start_matches('.');
    host.eq_ignore_ascii_case(entry)
        || host
            .strip_suffix(entry)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn select_https(value: &str) -> Option<String> {
    let items = || value.split([';', ' ']).map(str::trim);
    items()
        .find_map(|entry| entry.strip_prefix("https=").map(proxy_url))
        .or_else(|| {
            items()
                .find(|entry| {
                    !entry.is_empty()
                        && !entry.contains('=')
                        && !entry.eq_ignore_ascii_case("PROXY")
                        && !entry.eq_ignore_ascii_case("DIRECT")
                })
                .map(proxy_url)
        })
}

fn proxy_url(proxy: &str) -> String {
    if proxy.contains("://") {
        proxy.to_owned()
    } else {
        format!("http://{proxy}")
    }
}

unsafe fn copy_wide(pointer: windows_sys::core::PWSTR) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut len = 0;
    while unsafe { *pointer.add(len) } != 0 {
        len += 1;
    }
    let result = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, len) });
    unsafe { GlobalFree(pointer.cast()) };
    Some(result)
}
