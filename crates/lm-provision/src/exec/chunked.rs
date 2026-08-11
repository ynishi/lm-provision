//! Parallel range downloads — the file cut into pieces, each fetched by
//! its own request to the URL the profile named.
//!
//! # The one rule that makes this work
//!
//! **Every chunk requests the original URL and follows its own
//! redirect.** It never reuses a resolved location for a second range.
//!
//! That is not a stylistic choice. HuggingFace serves large files
//! through a signed URL that authorises *a specific byte range*:
//!
//! > The signed `url` authorizes exactly the byte ranges in its
//! > `X-Xet-Signed-Range` set; a `Range` header requesting bytes outside
//! > that set returns an authorization failure. These are short-lived;
//! > **do not cache or rewrite them.**
//! >
//! > — [Xet download protocol](https://huggingface.co/docs/xet/en/download-protocol)
//!
//! Resolve once and reuse, and every range after the first is refused.
//! Resolve per chunk and each one arrives correctly scoped: three
//! disjoint ranges of a 4.27 GB weight, each fetched this way, all
//! answered `206` [実測: 2026-08-11, `huggingface.co/.../resolve/main/`].
//!
//! **This is what a resolve-once downloader cannot do.** An `aria2c`
//! route lived here before this one and posted exactly `split - 1`
//! refusals against HuggingFace, collapsing to a single connection
//! mid-transfer, because it resolves the redirect once and splits
//! against the result. `hf_transfer` has the same shape — one probe
//! `Range: bytes=0-0`, then every chunk reuses `redirected_url`
//! [`hf_transfer/src/lib.rs`] — and HuggingFace has deprecated it now
//! that Xet is the storage backend.
//!
//! # Where re-resolving is unnecessary, it is still cheap
//!
//! Range-scoped signing is not universal. CivitAI's presigned URL covers
//! only the host (`X-Amz-SignedHeaders=host`), so one resolved location
//! serves any range for its 24-hour life, and a downloader that resolves
//! once works perfectly against it [実測: 2026-08-11, three disjoint
//! ranges of a 2.13 GB model on one resolved URL, all `206`].
//!
//! This route re-resolves there too, and pays a redirect per chunk for
//! it. That is deliberate: the alternative is a rule about which hosts
//! may be trusted to serve a second range, which is a list to maintain
//! and to be wrong about. The cost was measured rather than assumed —
//! thirty rapid re-resolutions at eight concurrent against CivitAI, all
//! `206`, no rate limiting [実測: same day] — and a redirect against a
//! 10 MiB chunk is not the expensive part of a download.
//!
//! It is not merely affordable, it is faster than the alternative even
//! where the alternative works: a 2.13 GB CivitAI model fetched six
//! times on one pod, alternating between this route and `aria2c -c -x16
//! -s16 -k 10M --file-allocation=none` (the flags the predecessor
//! implementation used), **22 / 23 / 26 s here against 35 / 36 / 50 s
//! there** — 90 MB/s against 53 MB/s, the two spreads not overlapping,
//! and both routes producing a file whose digest matches the one
//! CivitAI publishes [実測: 2026-08-11].
//!
//! Alternating rather than one-then-the-other because these transfers
//! have a wide run-to-run spread: seven runs of one 4.27 GB file at
//! fixed settings landed anywhere between 64 s and 148 s. An earlier
//! comparison of this kind was drawn from one sample per arm and had to
//! be withdrawn when repeating it reversed the result.
//!
//! # The numbers are HuggingFace's own
//!
//! [`CONCURRENCY`] and [`CHUNK_SIZE`] are not tuned here and are not
//! guesses; they are what HuggingFace's own client uses.
//!
//! There is **no documented limit on concurrent connections** to the Hub
//! — the published quotas are request *counts* per five-minute window
//! against `/resolve/` paths, and nothing states whether CDN range GETs
//! are counted at all [[Hub rate limits](https://huggingface.co/docs/hub/rate-limits)].
//! Nothing in HuggingFace's documentation discourages multi-connection
//! downloaders either. So the reason to bound concurrency is not a rule
//! being obeyed; it is that an unbounded fan-out over a large file is a
//! way to be rude to a host for no measured gain.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::effects::{ProgressSink, TransferProgress};
use super::ExecError;

/// Bytes per range request.
///
/// 10 MiB is `huggingface_hub`'s `DOWNLOAD_CHUNK_SIZE`
/// [`huggingface_hub/constants.py`], which is the size its own transfers
/// ask for.
pub const CHUNK_SIZE: u64 = 10 * 1024 * 1024;

/// Range requests in flight at once.
///
/// 16 is the default of `HF_XET_NUM_CONCURRENT_RANGE_GETS`, the same
/// quantity in HuggingFace's current client (which scales adaptively up
/// to 64 from there)
/// [[environment variables](https://huggingface.co/docs/huggingface_hub/en/package_reference/environment_variables)].
///
/// It is **not** the `MAX_CONCURRENT_STEPS` of `crate::apply`, which
/// counts files moving at once. Four files at sixteen ranges each is 64
/// requests in flight, and that was measured rather than assumed: four
/// 2.13 GB weights to one pod took **27-34 s** fetched together against
/// **229-242 s** one at a time, with no rate limiting, no failed chunk
/// and no retry on either shape [実測: 2026-08-11].
///
/// The two axes **compound**. Each individual file finished faster with
/// three others competing than with the link to itself, which says the
/// limit on one file is the supplier's per-connection rate rather than
/// anything the pod is short of.
pub const CONCURRENCY: usize = 16;

/// Below this a file is fetched in one request.
///
/// Two chunks is the least that can be called parallel, and under it the
/// extra round trip costs more than it saves.
pub const MIN_TOTAL: u64 = 2 * CHUNK_SIZE;

/// Attempts per chunk before the transfer gives up.
///
/// **Not optional.** Sixteen connections held open across a multi-gigabyte
/// transfer will have one of them dropped, and without a retry that one
/// drop discards every other chunk's work. Measured the hard way: the
/// first run of this route against HuggingFace fetched 32 chunks and
/// died on `range 31457280-41943039: reading the body`, having already
/// spent two minutes [実測: 2026-08-11].
///
/// 5 is `huggingface_hub`'s `max_retries` for its own chunked downloads
/// [`file_download.py`], which also passes `parallel_failures=3`.
const MAX_ATTEMPTS: u32 = 5;

/// First backoff, doubling each attempt up to [`MAX_BACKOFF`].
///
/// Both bounds are `hf_transfer`'s `BASE_WAIT_TIME` / `MAX_WAIT_TIME`
/// [`hf_transfer/src/lib.rs`].
const BASE_BACKOFF: Duration = Duration::from_millis(300);

/// Ceiling for the backoff. A supplier that needs longer than this to
/// recover is not going to be waited out chunk by chunk.
const MAX_BACKOFF: Duration = Duration::from_secs(10);

/// The file's full length, read from a `206`'s `Content-Range`.
///
/// `None` when the header is missing or names an unknown total (`*`),
/// which is a supplier that answered a range without saying how much
/// there is — and without that number there is nothing to divide.
pub fn total_of(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)?
        .to_str()
        .ok()?
        // `bytes 0-10485759/4265146304` — the length follows the slash.
        .rsplit('/')
        .next()?
        .trim()
        .parse()
        .ok()
}

/// Fetch `url` into an already-created `file` of length `total`, in
/// [`CHUNK_SIZE`] pieces, [`CONCURRENCY`] at a time.
///
/// `first` is the response to the opening range, already in hand — the
/// caller asked for it to find out whether this route applies at all, so
/// its body is chunk zero and re-requesting it would throw away a chunk
/// that is already arriving.
///
/// Reports the running total to `progress` as pieces land. The count is
/// **bytes written across all chunks**, so it rises smoothly even though
/// no single chunk is contiguous with the file's start — which is what
/// makes the transcript read the same as the single-stream route's.
///
/// The first failure ends the transfer: a weight with a hole in it is
/// worse than one that is missing, because the hole is only found by
/// whatever loads it later.
pub async fn download(
    client: &reqwest::Client,
    url: &str,
    file: Arc<std::fs::File>,
    total: u64,
    first: reqwest::Response,
    progress: ProgressSink<'_>,
) -> Result<u64, ExecError> {
    let written = Arc::new(AtomicU64::new(0));
    // Chunk zero is `first`; the parallel ones start after it.
    let mut ranges = (CHUNK_SIZE..total).step_by(CHUNK_SIZE as usize);
    let mut running = tokio::task::JoinSet::new();

    {
        let client = client.clone();
        let url = url.to_string();
        let file = Arc::clone(&file);
        let written = Arc::clone(&written);
        let end = (CHUNK_SIZE - 1).min(total - 1);
        running.spawn(async move {
            // The response is already open, so the first attempt is a
            // drain rather than a request. If it breaks, the range is
            // retried like any other — from the original URL, which is
            // the only way to get a fresh signing anyway.
            match drain(first, 0, end, Arc::clone(&file), Arc::clone(&written)).await {
                Ok(()) => Ok(()),
                Err((_, partial)) => {
                    written.fetch_sub(partial, Ordering::Relaxed);
                    chunk(client, url, 0, end, file, written).await
                }
            }
        });
    }

    // Reported from here rather than from inside the chunks: sixteen
    // writers each announcing their own arrival would produce a count
    // that jumps around, and the transcript's job is to be readable.
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let spawn = |running: &mut tokio::task::JoinSet<Result<(), String>>, start: u64| {
        let end = (start + CHUNK_SIZE - 1).min(total - 1);
        let client = client.clone();
        let url = url.to_string();
        let file = Arc::clone(&file);
        let written = Arc::clone(&written);
        running.spawn(async move { chunk(client, url, start, end, file, written).await });
    };

    // One seat is already taken by chunk zero.
    for _ in 1..CONCURRENCY {
        match ranges.next() {
            Some(start) => spawn(&mut running, start),
            None => break,
        }
    }

    loop {
        tokio::select! {
            _ = tick.tick() => {
                progress(TransferProgress {
                    written: written.load(Ordering::Relaxed),
                    total: Some(total),
                    finished: false,
                });
            }
            joined = running.join_next() => match joined {
                None => break,
                Some(Err(err)) => {
                    running.abort_all();
                    return Err(failed(format!("a range download panicked: {err}")));
                }
                Some(Ok(Err(err))) => {
                    running.abort_all();
                    return Err(failed(err));
                }
                Some(Ok(Ok(()))) => {
                    if let Some(start) = ranges.next() {
                        spawn(&mut running, start);
                    }
                }
            }
        }
    }

    let written = written.load(Ordering::Relaxed);
    if written != total {
        return Err(failed(format!(
            "the supplier declared {total} bytes and delivered {written}"
        )));
    }
    Ok(written)
}

/// One range, from its own request to the original URL.
///
/// **The request goes to `url`, never to a location resolved earlier.**
/// That is the whole reason this route exists: a supplier may sign the
/// redirect target for the range that was asked for, and reusing it for
/// a second range is refused (module doc).
async fn chunk(
    client: reqwest::Client,
    url: String,
    start: u64,
    end: u64,
    file: Arc<std::fs::File>,
    written: Arc<AtomicU64>,
) -> Result<(), String> {
    let mut backoff = BASE_BACKOFF;
    let mut last = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        if attempt > 1 {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
        match attempt_chunk(&client, &url, start, end, &file, &written).await {
            Ok(()) => return Ok(()),
            Err((message, partial)) => {
                // Whatever this attempt managed is discarded, so the
                // running total has to give it back — otherwise a
                // retried chunk is counted twice and the transfer
                // reports more bytes than the file holds.
                written.fetch_sub(partial, Ordering::Relaxed);
                last = message;
            }
        }
    }
    Err(format!("{last} (after {MAX_ATTEMPTS} attempts)"))
}

/// One try at one range. Returns what it wrote alongside the failure, so
/// the caller can undo it before trying again.
///
/// **The request goes to `url`, never to a location resolved earlier** —
/// which is also why a retry is safe against a supplier whose signed
/// URLs expire: the retry signs afresh.
async fn attempt_chunk(
    client: &reqwest::Client,
    url: &str,
    start: u64,
    end: u64,
    file: &Arc<std::fs::File>,
    written: &Arc<AtomicU64>,
) -> Result<(), (String, u64)> {
    let response = client
        .get(url)
        .header(reqwest::header::RANGE, format!("bytes={start}-{end}"))
        .send()
        .await
        .map_err(|err| (format!("range {start}-{end}: {err}"), 0))?;

    // A `200` here is the supplier deciding to send the whole file for a
    // range request, which would have every chunk writing the whole file
    // over every other one. The opening range said it serves ranges;
    // this is the check that it still does.
    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        return Err((
            format!(
                "range {start}-{end}: expected 206, got {}",
                response.status().as_u16()
            ),
            0,
        ));
    }

    drain(response, start, end, Arc::clone(file), Arc::clone(written)).await
}

/// Write one range's body into `file` at its own offset.
///
/// Split from [`chunk`] so that the opening range — whose response the
/// caller already holds — lands the same way every other one does.
async fn drain(
    mut response: reqwest::Response,
    start: u64,
    end: u64,
    file: Arc<std::fs::File>,
    written: Arc<AtomicU64>,
) -> Result<(), (String, u64)> {
    let mut at = start;
    while let Some(piece) = match response.chunk().await {
        Ok(piece) => piece,
        Err(err) => {
            return Err((
                format!("range {start}-{end}: reading the body: {err}"),
                at - start,
            ))
        }
    } {
        let file = Arc::clone(&file);
        let offset = at;
        let len = piece.len() as u64;
        // `write_all_at` is a positioned write: it does not move a
        // shared cursor, so sixteen of these can be in flight against
        // one handle without a lock between them. It is blocking, hence
        // the hop off the runtime — a 64 KiB write is short, and
        // sixteen tasks each doing one inline would still be sixteen
        // stalls of a worker thread.
        let landed = tokio::task::spawn_blocking(move || {
            use std::os::unix::fs::FileExt;
            file.write_all_at(&piece, offset)
        })
        .await;
        match landed {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                return Err((
                    format!("range {start}-{end}: writing at {offset}: {err}"),
                    at - start,
                ))
            }
            Err(err) => return Err((format!("range {start}-{end}: writing: {err}"), at - start)),
        }
        at += len;
        written.fetch_add(len, Ordering::Relaxed);
    }

    let expected = end - start + 1;
    let got = at - start;
    if got != expected {
        return Err((
            format!("range {start}-{end}: asked for {expected} bytes and received {got}"),
            got,
        ));
    }
    Ok(())
}

/// This route's errors carry the transfer's op, since the caller asked
/// for a transfer and did not ask how it would be cut up.
fn failed(message: String) -> ExecError {
    ExecError::EffectFailed {
        op: "net_transfer".to_string(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_cut_into_whole_chunks_with_a_short_last_one() {
        let total = CHUNK_SIZE * 3 + 1234;
        let ends: Vec<(u64, u64)> = (0..total)
            .step_by(CHUNK_SIZE as usize)
            .map(|start| (start, (start + CHUNK_SIZE - 1).min(total - 1)))
            .collect();
        assert_eq!(ends.len(), 4);
        assert_eq!(ends[0], (0, CHUNK_SIZE - 1));
        assert_eq!(ends[3], (CHUNK_SIZE * 3, total - 1));
        // Every byte exactly once: no gap to leave a hole and no overlap
        // to write one chunk over another.
        let covered: u64 = ends.iter().map(|(start, end)| end - start + 1).sum();
        assert_eq!(covered, total);
    }

    #[test]
    fn a_file_of_exactly_one_chunk_is_one_range() {
        let ends: Vec<u64> = (0..CHUNK_SIZE).step_by(CHUNK_SIZE as usize).collect();
        assert_eq!(ends, vec![0]);
    }

    #[test]
    fn the_threshold_leaves_room_for_two_chunks() {
        // Below this the route would spend a probe to discover it has
        // one range to fetch, which is the single-stream route with an
        // extra round trip.
        assert_eq!(MIN_TOTAL, CHUNK_SIZE * 2);
    }

    #[test]
    fn the_concurrency_is_huggingfaces_own_default() {
        // HF_XET_NUM_CONCURRENT_RANGE_GETS. Stated so that changing it
        // is a decision about departing from the supplier's client
        // rather than an edit.
        assert_eq!(CONCURRENCY, 16);
        assert_eq!(CHUNK_SIZE, 10 * 1024 * 1024);
    }
}
