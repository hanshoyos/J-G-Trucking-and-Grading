package alerts

import (
    "context"
    "encoding/json"
    "sync"
    "time"

    "github.com/segmentio/kafka-go"
    "go.uber.org/zap"
)

type Alert struct {
    Raw json.RawMessage
}

type Store struct {
    mu          sync.RWMutex
    buf         []json.RawMessage // ring buffer, cap 200
    subscribers map[chan json.RawMessage]struct{}
    log         *zap.Logger
}

func NewStore(log *zap.Logger) *Store {
    return &Store{
        buf:         make([]json.RawMessage, 0, 200),
        subscribers: make(map[chan json.RawMessage]struct{}),
        log:         log,
    }
}

func (s *Store) Subscribe() chan json.RawMessage {
    ch := make(chan json.RawMessage, 64)
    s.mu.Lock()
    s.subscribers[ch] = struct{}{}
    s.mu.Unlock()
    return ch
}

func (s *Store) Unsubscribe(ch chan json.RawMessage) {
    s.mu.Lock()
    delete(s.subscribers, ch)
    s.mu.Unlock()
}

func (s *Store) Recent() []json.RawMessage {
    s.mu.RLock()
    defer s.mu.RUnlock()
    out := make([]json.RawMessage, len(s.buf))
    copy(out, s.buf)
    return out
}

func (s *Store) push(msg json.RawMessage) {
    s.mu.Lock()
    if len(s.buf) >= 200 {
        s.buf = s.buf[1:]
    }
    s.buf = append(s.buf, msg)
    subs := make([]chan json.RawMessage, 0, len(s.subscribers))
    for ch := range s.subscribers {
        subs = append(subs, ch)
    }
    s.mu.Unlock()
    for _, ch := range subs {
        select {
        case ch <- msg:
        default:
        }
    }
}

// ConsumeLoop runs in background; exits when ctx is cancelled.
func (s *Store) ConsumeLoop(ctx context.Context, brokers, topic string) {
    r := kafka.NewReader(kafka.ReaderConfig{
        Brokers:        []string{brokers},
        Topic:          topic,
        GroupID:        "ace-gateway",
        MinBytes:       1,
        MaxBytes:       1 << 20,
        CommitInterval: time.Second,
        StartOffset:    kafka.LastOffset,
    })
    defer r.Close()
    s.log.Info("kafka alert consumer started", zap.String("topic", topic))
    for {
        m, err := r.ReadMessage(ctx)
        if err != nil {
            if ctx.Err() != nil {
                return
            }
            s.log.Warn("kafka read error", zap.Error(err))
            time.Sleep(2 * time.Second)
            continue
        }
        s.push(json.RawMessage(m.Value))
    }
}
