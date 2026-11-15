//! Control-prioritized FIFO queue for outbound and inbound protocol frames.

use std::collections::VecDeque;

use crate::{Frame, Lane};

/// Two-lane FIFO frame queue that always drains `Lane::Control` ahead of `Lane::Data`.
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
}
