//! Control-prioritized FIFO queue for outbound and inbound protocol frames.

use std::collections::VecDeque;

use crate::{Frame, Lane};

/// Two-lane FIFO frame queue that always drains `Lane::Control` ahead of `Lane::Data`.
///
/// Urgent control frames (`ExecCancel`, `ExecExit`, `CopyInStart`, `CopyOutStart`, `CopyError`,
/// `StreamCredit`, `Ping`, `Pong`, `Shutdown`) preempt bulk `Lane::Data` traffic, while
/// `CopyDone` shares `Lane::Data` with `StreamData` so copy-out completion never overtakes
/// queued tar chunks. Senders must only enqueue `ExecExit` after all `StreamData` chunks for
/// that `StreamId` have drained.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PriorityFrameQueue {
    control: VecDeque<Frame>,
    data: VecDeque<Frame>,
}

impl PriorityFrameQueue {
    /// Creates an empty prioritized frame queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueues `frame` at the back of its declared priority lane.
    pub fn push(&mut self, frame: Frame) {
        match frame.header.lane {
            Lane::Control => self.control.push_back(frame),
            Lane::Data => self.data.push_back(frame),
        }
    }

    /// Dequeues the oldest `Control` frame if present, otherwise the oldest `Data` frame.
    pub fn pop(&mut self) -> Option<Frame> {
        self.control.pop_front().or_else(|| self.data.pop_front())
    }

    /// Returns `true` when both `Control` and `Data` lanes are empty.
    pub fn is_empty(&self) -> bool {
        self.control.is_empty() && self.data.is_empty()
    }

    /// Returns total queued frames across both lanes.
    pub fn len(&self) -> usize {
        self.control.len() + self.data.len()
    }

    /// Returns queued frames waiting in `Lane::Control`.
    pub fn control_len(&self) -> usize {
        self.control.len()
    }

    /// Returns queued frames waiting in `Lane::Data`.
    pub fn data_len(&self) -> usize {
        self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Message, StreamChannel, StreamId};

    #[test]
    fn control_frames_always_dequeue_ahead_of_data_with_intra_lane_fifo() {
        let mut queue = PriorityFrameQueue::new();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.pop(), None);

        let d1 = Frame::from_message(
            StreamId(1),
            &Message::StreamData {
                channel: StreamChannel::Stdout,
                eof: false,
                data: b"chunk1".to_vec(),
            },
        )
        .unwrap();
        let d2 = Frame::from_message(
            StreamId(1),
            &Message::StreamData {
                channel: StreamChannel::Stdout,
                eof: true,
                data: b"chunk2".to_vec(),
            },
        )
        .unwrap();
        let c1 = Frame::from_message(StreamId(1), &Message::ExecCancel).unwrap();
        let c2 = Frame::from_message(StreamId(0), &Message::Ping { seq: 7 }).unwrap();

        queue.push(d1.clone());
        queue.push(d2.clone());
        queue.push(c1.clone());
        queue.push(c2.clone());

        assert!(!queue.is_empty());
        assert_eq!(queue.len(), 4);
        assert_eq!(queue.control_len(), 2);
        assert_eq!(queue.data_len(), 2);

        assert_eq!(queue.pop(), Some(c1));
        assert_eq!(queue.pop(), Some(c2));
        assert_eq!(queue.control_len(), 0);
        assert_eq!(queue.data_len(), 2);

        assert_eq!(queue.pop(), Some(d1));
        assert_eq!(queue.pop(), Some(d2));
        assert!(queue.is_empty());
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn copy_done_preserves_fifo_after_stream_data_while_control_frames_preempt() {
        let mut queue = PriorityFrameQueue::new();

        let copy_start = Frame::from_message(
            StreamId(2),
            &Message::CopyOutStart {
                src_guest: "/workspace/out".to_owned(),
                max_bytes: 1024 * 1024,
            },
        )
        .unwrap();
        let chunk1 = Frame::from_message(
            StreamId(2),
            &Message::StreamData {
                channel: StreamChannel::Stdout,
                eof: false,
                data: b"tar-part-1".to_vec(),
            },
        )
        .unwrap();
        let chunk2 = Frame::from_message(
            StreamId(2),
            &Message::StreamData {
                channel: StreamChannel::Stdout,
                eof: true,
                data: b"tar-part-2".to_vec(),
            },
        )
        .unwrap();
        let copy_done = Frame::from_message(
            StreamId(2),
            &Message::CopyDone {
                bytes_transferred: 20,
            },
        )
        .unwrap();
        let credit = Frame::from_message(
            StreamId(2),
            &Message::StreamCredit {
                channel: StreamChannel::Stdout,
                bytes: 4096,
            },
        )
        .unwrap();
        let copy_err = Frame::from_message(
            StreamId(3),
            &Message::CopyError {
                message: "permission denied".to_owned(),
            },
        )
        .unwrap();
        let copy_in = Frame::from_message(
            StreamId(4),
            &Message::CopyInStart {
                dst_guest: "/workspace/in".to_owned(),
                max_bytes: 8192,
            },
        )
        .unwrap();
        let exec_exit = Frame::from_message(
            StreamId(5),
            &Message::ExecExit {
                code: Some(0),
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            },
        )
        .unwrap();

        // Simulate concurrent enqueue: data chunks + CopyDone first, then urgent control frames.
        queue.push(copy_start.clone());
        queue.push(chunk1.clone());
        queue.push(chunk2.clone());
        queue.push(copy_done.clone());
        queue.push(credit.clone());
        queue.push(copy_err.clone());
        queue.push(copy_in.clone());
        queue.push(exec_exit.clone());

        assert_eq!(queue.control_len(), 5);
        assert_eq!(queue.data_len(), 3);

        // All control frames drain strictly FIFO ahead of Data lane.
        assert_eq!(queue.pop(), Some(copy_start));
        assert_eq!(queue.pop(), Some(credit));
        assert_eq!(queue.pop(), Some(copy_err));
        assert_eq!(queue.pop(), Some(copy_in));
        assert_eq!(queue.pop(), Some(exec_exit));

        // CopyDone stays strictly ordered behind both StreamData chunks on the Data lane.
        assert_eq!(queue.pop(), Some(chunk1));
        assert_eq!(queue.pop(), Some(chunk2));
        assert_eq!(queue.pop(), Some(copy_done));
        assert!(queue.is_empty());
    }
}
