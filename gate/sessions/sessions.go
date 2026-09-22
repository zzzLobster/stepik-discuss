package sessions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	BucketSessions     = []byte("sessions")
	BucketUserVersions = []byte("user_versions")
	BucketTeacherToken = []byte("teacher_token")
	BucketMeta         = []byte("meta")
	BucketPushSubs     = []byte("push_subs")
	BucketPushMeta     = []byte("push_meta")

	KeyTeacherCurrent = []byte("current")
	KeyGlobalEpoch    = []byte("global_epoch")
	KeySchemaVersion  = []byte("schema_version")
	SchemaVersion     = []byte("2")
)

var ErrCorrupt = errors.New("session corrupt")

const (
	CookieSID    = "__Host-sid"
	CookieBinder = "__Host-oa"
	CookieCSRF   = "__Host-csrf"

	SIDMaxAgeSeconds    = 2592000
	BinderMaxAgeSeconds = 600
	CSRFMaxAgeSeconds   = SIDMaxAgeSeconds
)

type SessionRecord struct {
	StepikUserID    int64             `json:"stepik_user_id"`
	FIO             string            `json:"fio"`
	AvatarURL       string            `json:"avatar_url"`
	AllowedClassIDs []int64           `json:"allowed_class_ids"`
	ClassTitles     map[string]string `json:"class_titles"`
	IsTeacher       bool              `json:"is_teacher"`
	CreatedAt       time.Time         `json:"created_at"`
	LastVerifiedAt  time.Time         `json:"last_verified_at"`
	NextRetryAt     time.Time         `json:"next_retry_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	LastSeenAt      time.Time         `json:"last_seen_at"`
	UserVersion     uint64            `json:"user_version"`
	GlobalEpoch     uint64            `json:"global_epoch"`
	TokenCiphertext []byte            `json:"token_ciphertext"`
	TokenNonce      []byte            `json:"token_nonce"`
	TokenObtainedAt time.Time         `json:"token_obtained_at"`
	TokenExpiresAt  time.Time         `json:"token_expires_at"`
	// CSRFToken is the double-submit cookie value for this session. It is
	// additive: pre-feature rows unmarshal with an empty value and are
	// backfilled when next used by an HTML route.
	CSRFToken string `json:"csrf_token,omitempty"`
	// Refresh fields are additive: pre-feature rows unmarshal with nil/zero
	// values and follow the legacy no-renewal path. Same AES-GCM key as the
	// access token, separate nonces. No refresh-expiry field is stored.
	RefreshCiphertext []byte    `json:"refresh_ciphertext,omitempty"`
	RefreshNonce      []byte    `json:"refresh_nonce,omitempty"`
	RefreshObtainedAt time.Time `json:"refresh_obtained_at,omitempty"`
}

type TeacherToken struct {
	Ciphertext []byte    `json:"ciphertext"`
	Nonce      []byte    `json:"nonce"`
	ObtainedAt time.Time `json:"obtained_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	ExpiresIn  int       `json:"expires_in"`
	OwnerUID   int64     `json:"owner_uid"`
	// Same additive refresh storage as SessionRecord (see above).
	RefreshCiphertext []byte    `json:"refresh_ciphertext,omitempty"`
	RefreshNonce      []byte    `json:"refresh_nonce,omitempty"`
	RefreshObtainedAt time.Time `json:"refresh_obtained_at,omitempty"`
}

type Store struct {
	db  *bolt.DB
	key [32]byte
}

func Open(path string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("token key must be 32 bytes")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	copy(s.key[:], key)
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{BucketSessions, BucketUserVersions, BucketTeacherToken, BucketMeta, BucketPushSubs, BucketPushMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		meta := tx.Bucket(BucketMeta)
		ver := meta.Get(KeySchemaVersion)
		if ver == nil {
			if err := meta.Put(KeySchemaVersion, SchemaVersion); err != nil {
				return err
			}
		} else if string(ver) == "1" {
			if err := meta.Put(KeySchemaVersion, SchemaVersion); err != nil {
				return err
			}
		} else if string(ver) != "2" {
			return errors.New("unsupported schema version " + string(ver))
		}
		if meta.Get(KeyGlobalEpoch) == nil {
			if err := meta.Put(KeyGlobalEpoch, []byte("0")); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Ping() error {
	return s.db.View(func(tx *bolt.Tx) error {
		ver := tx.Bucket(BucketMeta).Get(KeySchemaVersion)
		if ver == nil {
			return errNoSchema()
		}
		if string(ver) != "2" {
			return errors.New("unsupported schema version " + string(ver))
		}
		return nil
	})
}

func errNoSchema() error {
	return errors.New("schema version missing")
}

func (s *Store) EncryptToken(plain string) (ct, nonce []byte, err error) {
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, []byte(plain), nil), nonce, nil
}

func (s *Store) DecryptToken(ct, nonce []byte) (string, error) {
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func NewSID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func NewBinder() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func SetSID(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieSID,
		Value:    sid,
		Path:     "/",
		MaxAge:   SIDMaxAgeSeconds,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearSID(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieSID,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func SetBinder(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieBinder,
		Value:    v,
		Path:     "/",
		MaxAge:   BinderMaxAgeSeconds,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearBinder(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieBinder,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func NewCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func SetCSRF(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieCSRF,
		Value:    v,
		Path:     "/",
		MaxAge:   CSRFMaxAgeSeconds,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearCSRF(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieCSRF,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func csrfCookie(r *http.Request) string {
	c, err := r.Cookie(CookieCSRF)
	if err != nil {
		return ""
	}
	return c.Value
}

func verifyCSRF(r *http.Request, got string) bool {
	want := csrfCookie(r)
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// VerifyFormCSRF checks that the request's csrf_token form field matches the
// __Host-csrf cookie using a constant-time comparison. The token is read only
// from the POST body, never from the URL query string, to avoid leaking it via
// Referer headers or browser history.
func VerifyFormCSRF(r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}
	return verifyCSRF(r, r.PostFormValue("csrf_token"))
}

// VerifyHeaderCSRF checks that the request's X-CSRF-Token header matches the
// __Host-csrf cookie using a constant-time comparison.
func VerifyHeaderCSRF(r *http.Request) bool {
	return verifyCSRF(r, r.Header.Get("X-CSRF-Token"))
}

func (s *Store) TeacherTokenPlain(teacherID int64) (string, bool) {
	tok, err := s.GetTeacherToken()
	if err != nil {
		return "", false
	}
	if tok == nil {
		return "", false
	}
	if tok.OwnerUID != teacherID {
		return "", false
	}
	if time.Now().After(tok.ExpiresAt.Add(-60 * time.Second)) {
		return "", false
	}
	plain, err := s.DecryptToken(tok.Ciphertext, tok.Nonce)
	if err != nil {
		return "", false
	}
	return plain, true
}

func (s *Store) GetSession(sid string) (*SessionRecord, error) {
	var rec *SessionRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(BucketSessions).Get([]byte(sid))
		if raw == nil {
			return nil
		}
		var r SessionRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return ErrCorrupt
		}
		rec = &r
		return nil
	})
	return rec, err
}

func (s *Store) PutSession(sid string, rec *SessionRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(BucketSessions).Put([]byte(sid), raw)
	})
}

func (s *Store) DeleteSession(sid string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(BucketSessions).Delete([]byte(sid))
	})
}

func (s *Store) GetUserVersion(uid int64) (uint64, error) {
	var v uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(BucketUserVersions).Get([]byte(strconv.FormatInt(uid, 10)))
		if raw == nil {
			return nil
		}
		n, err := strconv.ParseUint(string(raw), 10, 64)
		if err != nil {
			return err
		}
		v = n
		return nil
	})
	return v, err
}

func (s *Store) BumpUserVersion(uid int64) (uint64, error) {
	var v uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketUserVersions)
		k := []byte(strconv.FormatInt(uid, 10))
		var cur uint64
		if raw := b.Get(k); raw != nil {
			n, err := strconv.ParseUint(string(raw), 10, 64)
			if err != nil {
				return err
			}
			cur = n
		}
		cur++
		v = cur
		return b.Put(k, []byte(strconv.FormatUint(cur, 10)))
	})
	return v, err
}

func (s *Store) GetGlobalEpoch() (uint64, error) {
	var v uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(BucketMeta).Get(KeyGlobalEpoch)
		if raw == nil {
			return nil
		}
		n, err := strconv.ParseUint(string(raw), 10, 64)
		if err != nil {
			return err
		}
		v = n
		return nil
	})
	return v, err
}

func (s *Store) BumpGlobalEpoch() (uint64, error) {
	var v uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketMeta)
		var cur uint64
		if raw := b.Get(KeyGlobalEpoch); raw != nil {
			n, err := strconv.ParseUint(string(raw), 10, 64)
			if err != nil {
				return err
			}
			cur = n
		}
		cur++
		v = cur
		return b.Put(KeyGlobalEpoch, []byte(strconv.FormatUint(cur, 10)))
	})
	return v, err
}

func (s *Store) GetTeacherToken() (*TeacherToken, error) {
	var tok *TeacherToken
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(BucketTeacherToken).Get(KeyTeacherCurrent)
		if raw == nil {
			return nil
		}
		var t TeacherToken
		if err := json.Unmarshal(raw, &t); err != nil {
			return err
		}
		tok = &t
		return nil
	})
	return tok, err
}

func (s *Store) PutTeacherToken(tok *TeacherToken) error {
	raw, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(BucketTeacherToken).Put(KeyTeacherCurrent, raw)
	})
}

// HasTeacherSessionFresherThan reports whether any teacher session holds
// tokens obtained after since. The background teacher loop uses it to avoid
// parking on a stale shared record after a demand dual-write failure left a
// fresher rotated chain in a session (see auth.teacherBackgroundRenew).
func (s *Store) HasTeacherSessionFresherThan(since time.Time) (bool, error) {
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(BucketSessions).Cursor()
		for k, raw := c.First(); k != nil; k, raw = c.Next() {
			var r SessionRecord
			if err := json.Unmarshal(raw, &r); err != nil {
				continue
			}
			if !r.IsTeacher {
				continue
			}
			if r.TokenObtainedAt.After(since) {
				found = true
				return nil
			}
		}
		return nil
	})
	return found, err
}

func (s *Store) StripClass(uid, cid int64) (int, error) {
	changed := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketSessions)
		c := b.Cursor()
		for k, raw := c.First(); k != nil; k, raw = c.Next() {
			var r SessionRecord
			if err := json.Unmarshal(raw, &r); err != nil {
				continue
			}
			if r.StepikUserID != uid {
				continue
			}
			kept := r.AllowedClassIDs[:0]
			for _, id := range r.AllowedClassIDs {
				if id != cid {
					kept = append(kept, id)
				}
			}
			if len(kept) == len(r.AllowedClassIDs) {
				continue
			}
			r.AllowedClassIDs = kept
			if r.ClassTitles != nil {
				delete(r.ClassTitles, strconv.FormatInt(cid, 10))
			}
			next, err := json.Marshal(&r)
			if err != nil {
				return err
			}
			if err := b.Put(k, next); err != nil {
				return err
			}
			changed++
		}
		return nil
	})
	return changed, err
}

// PushSub is a Web Push subscription row stored in push_subs[hex(sha256(endpoint))].
type PushSub struct {
	UID        int64     `json:"uid"`
	SID        string    `json:"sid"`
	Endpoint   string    `json:"endpoint"`
	P256dh     string    `json:"p256dh"`
	Auth       string    `json:"auth"`
	Cids       []int64   `json:"cids,omitempty"`
	All        bool      `json:"all"`
	UA         string    `json:"ua,omitempty"`
	KeyVersion string    `json:"key_version"`
	CreatedAt  time.Time `json:"created_at"`
	LastOkAt   time.Time `json:"last_ok_at"`
	FailCount  int       `json:"fail_count"`
}

// PushKey returns hex(sha256(endpoint)) bucket key.
func PushKey(endpoint string) []byte {
	sum := sha256.Sum256([]byte(endpoint))
	dst := make([]byte, 64)
	hex.Encode(dst, sum[:])
	return dst
}

func (s *Store) PutPushSub(sub *PushSub) error {
	raw, err := json.Marshal(sub)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(BucketPushSubs).Put(PushKey(sub.Endpoint), raw)
	})
}

func (s *Store) GetPushSub(endpoint string) (*PushSub, error) {
	var sub *PushSub
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(BucketPushSubs).Get(PushKey(endpoint))
		if raw == nil {
			return nil
		}
		var p PushSub
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		sub = &p
		return nil
	})
	return sub, err
}

func (s *Store) DeletePushSub(endpoint string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(BucketPushSubs).Delete(PushKey(endpoint))
	})
}

func (s *Store) SnapshotPushSubs() ([]PushSub, error) {
	var out []PushSub
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(BucketPushSubs).Cursor()
		for _, raw := c.First(); raw != nil; _, raw = c.Next() {
			var p PushSub
			if err := json.Unmarshal(raw, &p); err != nil {
				continue
			}
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

func (s *Store) PushSubsCount() (int, error) {
	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(BucketPushSubs).Stats().KeyN
		return nil
	})
	return n, err
}

// SessionWithSID pairs a session record with its sid.
type SessionWithSID struct {
	SID string
	Rec *SessionRecord
}

func (s *Store) SessionsForUID(uid int64) ([]SessionWithSID, error) {
	var out []SessionWithSID
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(BucketSessions).Cursor()
		for k, raw := c.First(); k != nil; k, raw = c.Next() {
			var r SessionRecord
			if err := json.Unmarshal(raw, &r); err != nil {
				continue
			}
			if r.StepikUserID != uid {
				continue
			}
			cp := r
			out = append(out, SessionWithSID{SID: string(k), Rec: &cp})
		}
		return nil
	})
	return out, err
}

// BestSessionForUID returns freshest live session for uid in one View snapshot.
// Freshness is VerifyTTL+15m upper bound (UTC), plus ExpiresAt, UserVersion, GlobalEpoch.
// IsTeacher does not bypass expiry.
func (s *Store) BestSessionForUID(uid int64, verifyTTL time.Duration) (*SessionRecord, string) {
	var best *SessionRecord
	var bestSID string
	now := time.Now().UTC()
	_ = s.db.View(func(tx *bolt.Tx) error {
		var curVer uint64
		if raw := tx.Bucket(BucketUserVersions).Get([]byte(strconv.FormatInt(uid, 10))); raw != nil {
			if n, err := strconv.ParseUint(string(raw), 10, 64); err == nil {
				curVer = n
			}
		}
		var curEpoch uint64
		if raw := tx.Bucket(BucketMeta).Get(KeyGlobalEpoch); raw != nil {
			if n, err := strconv.ParseUint(string(raw), 10, 64); err == nil {
				curEpoch = n
			}
		}
		c := tx.Bucket(BucketSessions).Cursor()
		for k, raw := c.First(); k != nil; k, raw = c.Next() {
			var r SessionRecord
			if err := json.Unmarshal(raw, &r); err != nil {
				continue
			}
			if r.StepikUserID != uid {
				continue
			}
			if !r.ExpiresAt.After(now) {
				continue
			}
			if time.Since(r.LastVerifiedAt.UTC()) > verifyTTL+15*time.Minute {
				continue
			}
			if r.UserVersion != curVer {
				continue
			}
			if r.GlobalEpoch != curEpoch {
				continue
			}
			if best == nil || r.LastVerifiedAt.After(best.LastVerifiedAt) {
				cp := r
				best = &cp
				bestSID = string(k)
			}
		}
		return nil
	})
	if best == nil {
		return nil, ""
	}
	return best, bestSID
}

// DeleteSessionAndPushSubs deletes session sid + push rows where row.sid==sid in single Update.
func (s *Store) DeleteSessionAndPushSubs(sid string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(BucketSessions).Delete([]byte(sid)); err != nil {
			return err
		}
		pb := tx.Bucket(BucketPushSubs)
		c := pb.Cursor()
		for k, raw := c.First(); k != nil; k, raw = c.Next() {
			var p PushSub
			if err := json.Unmarshal(raw, &p); err != nil {
				continue
			}
			if p.SID == sid {
				if err := pb.Delete(k); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// StripClassAndPrunePush rewrites sessions AllowedClassIDs + prunes push rows in single Update.
// Never bumps UserVersion for class revoke.
func (s *Store) StripClassAndPrunePush(uid, cid int64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		sb := tx.Bucket(BucketSessions)
		sc := sb.Cursor()
		for k, raw := sc.First(); k != nil; k, raw = sc.Next() {
			var r SessionRecord
			if err := json.Unmarshal(raw, &r); err != nil {
				continue
			}
			if r.StepikUserID != uid {
				continue
			}
			kept := r.AllowedClassIDs[:0]
			for _, id := range r.AllowedClassIDs {
				if id != cid {
					kept = append(kept, id)
				}
			}
			if len(kept) == len(r.AllowedClassIDs) {
				continue
			}
			r.AllowedClassIDs = kept
			if r.ClassTitles != nil {
				delete(r.ClassTitles, strconv.FormatInt(cid, 10))
			}
			next, err := json.Marshal(&r)
			if err != nil {
				return err
			}
			if err := sb.Put(k, next); err != nil {
				return err
			}
		}
		pb := tx.Bucket(BucketPushSubs)
		pc := pb.Cursor()
		for k, raw := pc.First(); k != nil; k, raw = pc.Next() {
			var p PushSub
			if err := json.Unmarshal(raw, &p); err != nil {
				continue
			}
			if p.UID != uid {
				continue
			}
			if p.All {
				if err := pb.Delete(k); err != nil {
					return err
				}
				continue
			}
			found := false
			for _, id := range p.Cids {
				if id == cid {
					found = true
					break
				}
			}
			if !found {
				continue
			}
			if len(p.Cids) == 1 {
				if err := pb.Delete(k); err != nil {
					return err
				}
				continue
			}
			kept := p.Cids[:0]
			for _, id := range p.Cids {
				if id != cid {
					kept = append(kept, id)
				}
			}
			p.Cids = kept
			next, err := json.Marshal(&p)
			if err != nil {
				return err
			}
			if err := pb.Put(k, next); err != nil {
				return err
			}
		}
		return nil
	})
}

// BumpVersionAndPrunePush bumps user version + deletes rows for uid in single Update.
func (s *Store) BumpVersionAndPrunePush(uid int64) (uint64, error) {
	var v uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		ub := tx.Bucket(BucketUserVersions)
		k := []byte(strconv.FormatInt(uid, 10))
		var cur uint64
		if raw := ub.Get(k); raw != nil {
			n, err := strconv.ParseUint(string(raw), 10, 64)
			if err != nil {
				return err
			}
			cur = n
		}
		cur++
		v = cur
		if err := ub.Put(k, []byte(strconv.FormatUint(cur, 10))); err != nil {
			return err
		}
		pb := tx.Bucket(BucketPushSubs)
		c := pb.Cursor()
		for pk, raw := c.First(); pk != nil; pk, raw = c.Next() {
			var p PushSub
			if err := json.Unmarshal(raw, &p); err != nil {
				continue
			}
			if p.UID == uid {
				if err := pb.Delete(pk); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return v, err
}

// DeletePushSubsForUID deletes all push rows for uid in single Update.
func (s *Store) DeletePushSubsForUID(uid int64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		pb := tx.Bucket(BucketPushSubs)
		c := pb.Cursor()
		for k, raw := c.First(); k != nil; k, raw = c.Next() {
			var p PushSub
			if err := json.Unmarshal(raw, &p); err != nil {
				continue
			}
			if p.UID == uid {
				if err := pb.Delete(k); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// BumpEpochAndClearPush bumps global epoch + deletes all push_subs in single Update.
func (s *Store) BumpEpochAndClearPush() (uint64, error) {
	var v uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		mb := tx.Bucket(BucketMeta)
		var cur uint64
		if raw := mb.Get(KeyGlobalEpoch); raw != nil {
			n, err := strconv.ParseUint(string(raw), 10, 64)
			if err != nil {
				return err
			}
			cur = n
		}
		cur++
		v = cur
		if err := mb.Put(KeyGlobalEpoch, []byte(strconv.FormatUint(cur, 10))); err != nil {
			return err
		}
		pb := tx.Bucket(BucketPushSubs)
		c := pb.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if err := pb.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	return v, err
}

func (s *Store) StartSweeper(stop <-chan struct{}) {
	t := time.NewTicker(time.Hour)
	go func() {
		defer t.Stop()
		_ = s.sweep()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				_ = s.sweep()
			}
		}
	}()
}

func (s *Store) sweep() error {
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketSessions)
		c := b.Cursor()
		for k, raw := c.First(); k != nil; k, raw = c.Next() {
			var r SessionRecord
			if err := json.Unmarshal(raw, &r); err != nil {
				if err := c.Delete(); err != nil {
					return err
				}
				continue
			}
			if r.ExpiresAt.Before(cutoff) {
				if err := c.Delete(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
