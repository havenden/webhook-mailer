package main

import (
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

const maxBodyBytes = 1024 * 1024

type app struct {
	db                                                                *sql.DB
	adminUser, adminPassword, adminToken, smtpPassword, publicBaseURL string
	cookieSecure                                                      bool
	sessions                                                          map[string]time.Time
	mu                                                                sync.Mutex
}
type webhook struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Token        string    `json:"-"`
	Enabled      bool      `json:"enabled"`
	RecipientIDs []int64   `json:"recipient_ids"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
type recipient struct {
	ID      int64     `json:"id"`
	Email   string    `json:"email"`
	Enabled bool      `json:"enabled"`
	AddedAt time.Time `json:"added_at"`
}
type smtpSettings struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	FromEmail string `json:"from_email"`
}

func main() {
	a, err := newApp()
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", a.health)
	mux.HandleFunc("GET /", serveLogin)
	mux.HandleFunc("GET /admin", serveAdmin)
	mux.HandleFunc("GET /static/app.js", serveJS)
	mux.HandleFunc("GET /static/style.css", serveCSS)
	mux.HandleFunc("POST /api/auth/login", a.login)
	mux.HandleFunc("POST /api/auth/logout", a.logout)
	mux.HandleFunc("/push/", a.receive)
	mux.Handle("/api/v1/", a.requireAdmin(http.HandlerFunc(a.api)))
	addr := env("LISTEN_ADDR", ":8080")
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, logging(mux)))
}
func newApp() (*app, error) {
	if err := loadEnvFile(env("ENV_FILE", ".env")); err != nil {
		return nil, err
	}
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		return nil, fmt.Errorf("MYSQL_DSN must be configured")
	}
	if os.Getenv("ADMIN_USERNAME") == "" || os.Getenv("ADMIN_PASSWORD") == "" {
		return nil, fmt.Errorf("ADMIN_USERNAME and ADMIN_PASSWORD must be configured")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	a := &app{db: db, adminUser: os.Getenv("ADMIN_USERNAME"), adminPassword: os.Getenv("ADMIN_PASSWORD"), adminToken: os.Getenv("ADMIN_TOKEN"), smtpPassword: os.Getenv("SMTP_PASSWORD"), publicBaseURL: strings.TrimRight(os.Getenv("PUBLIC_BASE_URL"), "/"), cookieSecure: envBool("COOKIE_SECURE", true), sessions: map[string]time.Time{}}
	if err = a.migrate(); err != nil {
		return nil, err
	}
	return a, nil
}
func (a *app) migrate() error {
	for _, q := range []string{`CREATE TABLE IF NOT EXISTS webhooks (id BIGINT AUTO_INCREMENT PRIMARY KEY,name VARCHAR(120) NOT NULL,token CHAR(48) NOT NULL UNIQUE,enabled BOOLEAN NOT NULL DEFAULT TRUE,recipient_ids JSON NOT NULL,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, `CREATE TABLE IF NOT EXISTS recipients (id BIGINT AUTO_INCREMENT PRIMARY KEY,email VARCHAR(254) NOT NULL UNIQUE,enabled BOOLEAN NOT NULL DEFAULT TRUE,added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, `CREATE TABLE IF NOT EXISTS smtp_settings (id TINYINT PRIMARY KEY,host VARCHAR(255) NOT NULL,port INT NOT NULL,username VARCHAR(254) NOT NULL,from_email VARCHAR(254) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`} {
		if _, err := a.db.Exec(q); err != nil {
			return err
		}
	}
	_, err := a.db.Exec(`INSERT IGNORE INTO smtp_settings(id,host,port,username,from_email) VALUES(1,?,?,?,?)`, env("SMTP_HOST", "smtp.qq.com"), envInt("SMTP_PORT", 465), os.Getenv("SMTP_USERNAME"), os.Getenv("FROM_EMAIL"))
	return err
}
func (a *app) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Username != a.adminUser || in.Password != a.adminPassword {
		writeError(w, 401, "账号或密码错误")
		return
	}
	token, _ := randomID(32)
	a.mu.Lock()
	a.sessions[token] = time.Now().Add(12 * time.Hour)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "wm_session", Value: token, Path: "/", HttpOnly: true, Secure: a.cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 43200})
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("wm_session"); e == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "wm_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.cookieSecure})
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (a *app) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.isAdmin(r) {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, 401, "请先登录")
	})
}
func (a *app) isAdmin(r *http.Request) bool {
	t := r.Header.Get("X-Admin-Token")
	if t == "" {
		t = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if a.adminToken != "" && t == a.adminToken {
		return true
	}
	c, e := r.Cookie("wm_session")
	if e != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[c.Value]
	if !ok || time.Now().After(exp) {
		delete(a.sessions, c.Value)
		return false
	}
	return true
}
func (a *app) api(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	switch {
	case p == "webhooks" && r.Method == "GET":
		a.listHooks(w)
	case p == "webhooks" && r.Method == "POST":
		a.createHook(w, r)
	case strings.HasPrefix(p, "webhooks/") && r.Method == "PUT":
		a.updateHook(w, r, strings.TrimPrefix(p, "webhooks/"))
	case p == "recipients" && r.Method == "GET":
		a.listRecipients(w)
	case p == "recipients" && r.Method == "POST":
		a.createRecipient(w, r)
	case strings.HasPrefix(p, "recipients/") && r.Method == "PUT":
		a.updateRecipient(w, r, strings.TrimPrefix(p, "recipients/"))
	case p == "smtp" && r.Method == "GET":
		a.getSMTP(w)
	case p == "smtp" && r.Method == "PUT":
		a.updateSMTP(w, r)
	default:
		writeError(w, 404, "接口不存在")
	}
}
func (a *app) listHooks(w http.ResponseWriter) {
	rows, e := a.db.Query(`SELECT id,name,token,enabled,recipient_ids,created_at,updated_at FROM webhooks ORDER BY id DESC`)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		h, e := scanHook(rows)
		if e != nil {
			writeError(w, 500, e.Error())
			return
		}
		out = append(out, a.hookJSON(h))
	}
	writeJSON(w, 200, out)
}

type hookScanner interface{ Scan(...any) error }

func scanHook(s hookScanner) (webhook, error) {
	var h webhook
	var ids []byte
	e := s.Scan(&h.ID, &h.Name, &h.Token, &h.Enabled, &ids, &h.CreatedAt, &h.UpdatedAt)
	if e == nil {
		e = json.Unmarshal(ids, &h.RecipientIDs)
	}
	return h, e
}
func (a *app) hookJSON(h webhook) map[string]any {
	return map[string]any{"id": h.ID, "name": h.Name, "enabled": h.Enabled, "recipient_ids": h.RecipientIDs, "created_at": h.CreatedAt, "updated_at": h.UpdatedAt, "url": a.publicBaseURL + "/push/" + h.Token}
}
func (a *app) createHook(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name         string  `json:"name"`
		RecipientIDs []int64 `json:"recipient_ids"`
		Enabled      *bool   `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		writeError(w, 400, "请输入接口名称")
		return
	}
	token, _ := randomID(24)
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	ids, _ := json.Marshal(in.RecipientIDs)
	res, e := a.db.Exec(`INSERT INTO webhooks(name,token,enabled,recipient_ids) VALUES(?,?,?,?)`, in.Name, token, enabled, ids)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	id, _ := res.LastInsertId()
	writeJSON(w, 201, a.hookJSON(webhook{ID: id, Name: in.Name, Token: token, Enabled: enabled, RecipientIDs: in.RecipientIDs, CreatedAt: time.Now(), UpdatedAt: time.Now()}))
}
func (a *app) updateHook(w http.ResponseWriter, r *http.Request, idText string) {
	id, e := strconv.ParseInt(idText, 10, 64)
	if e != nil {
		writeError(w, 400, "无效 ID")
		return
	}
	var in struct {
		Name         *string  `json:"name"`
		RecipientIDs *[]int64 `json:"recipient_ids"`
		Enabled      *bool    `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	row := a.db.QueryRow(`SELECT id,name,token,enabled,recipient_ids,created_at,updated_at FROM webhooks WHERE id=?`, id)
	h, e := scanHook(row)
	if e == sql.ErrNoRows {
		writeError(w, 404, "接口不存在")
		return
	}
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	if in.Name != nil {
		h.Name = strings.TrimSpace(*in.Name)
		if h.Name == "" {
			writeError(w, 400, "名称不能为空")
			return
		}
	}
	if in.Enabled != nil {
		h.Enabled = *in.Enabled
	}
	if in.RecipientIDs != nil {
		h.RecipientIDs = *in.RecipientIDs
	}
	ids, _ := json.Marshal(h.RecipientIDs)
	_, e = a.db.Exec(`UPDATE webhooks SET name=?,enabled=?,recipient_ids=? WHERE id=?`, h.Name, h.Enabled, ids, id)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	h.UpdatedAt = time.Now()
	writeJSON(w, 200, a.hookJSON(h))
}
func (a *app) listRecipients(w http.ResponseWriter) {
	rows, e := a.db.Query(`SELECT id,email,enabled,added_at FROM recipients ORDER BY id DESC`)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	defer rows.Close()
	var out []recipient
	for rows.Next() {
		var x recipient
		if e = rows.Scan(&x.ID, &x.Email, &x.Enabled, &x.AddedAt); e != nil {
			writeError(w, 500, e.Error())
			return
		}
		out = append(out, x)
	}
	writeJSON(w, 200, out)
}
func (a *app) createRecipient(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email   string `json:"email"`
		Enabled *bool  `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	email := strings.TrimSpace(in.Email)
	if _, e := mail.ParseAddress(email); e != nil {
		writeError(w, 400, "请输入有效邮箱")
		return
	}
	on := true
	if in.Enabled != nil {
		on = *in.Enabled
	}
	res, e := a.db.Exec(`INSERT INTO recipients(email,enabled) VALUES(?,?)`, email, on)
	if e != nil {
		writeError(w, 400, "邮箱已存在")
		return
	}
	id, _ := res.LastInsertId()
	writeJSON(w, 201, recipient{ID: id, Email: email, Enabled: on, AddedAt: time.Now()})
}
func (a *app) updateRecipient(w http.ResponseWriter, r *http.Request, idText string) {
	id, e := strconv.ParseInt(idText, 10, 64)
	if e != nil {
		writeError(w, 400, "无效 ID")
		return
	}
	var in struct {
		Email   *string `json:"email"`
		Enabled *bool   `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	var x recipient
	e = a.db.QueryRow(`SELECT id,email,enabled,added_at FROM recipients WHERE id=?`, id).Scan(&x.ID, &x.Email, &x.Enabled, &x.AddedAt)
	if e == sql.ErrNoRows {
		writeError(w, 404, "邮箱不存在")
		return
	}
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	if in.Email != nil {
		if _, e := mail.ParseAddress(*in.Email); e != nil {
			writeError(w, 400, "邮箱不正确")
			return
		}
		x.Email = strings.TrimSpace(*in.Email)
	}
	if in.Enabled != nil {
		x.Enabled = *in.Enabled
	}
	_, e = a.db.Exec(`UPDATE recipients SET email=?,enabled=? WHERE id=?`, x.Email, x.Enabled, id)
	if e != nil {
		writeError(w, 400, "邮箱已存在")
		return
	}
	writeJSON(w, 200, x)
}
func (a *app) getSMTP(w http.ResponseWriter) {
	s, e := a.smtp()
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, s)
}
func (a *app) smtp() (smtpSettings, error) {
	var s smtpSettings
	e := a.db.QueryRow(`SELECT host,port,username,from_email FROM smtp_settings WHERE id=1`).Scan(&s.Host, &s.Port, &s.Username, &s.FromEmail)
	return s, e
}
func (a *app) updateSMTP(w http.ResponseWriter, r *http.Request) {
	var s smtpSettings
	if !decodeJSON(w, r, &s) {
		return
	}
	if s.Host == "" || s.Port < 1 || s.Port > 65535 {
		writeError(w, 400, "SMTP 配置不正确")
		return
	}
	if _, e := mail.ParseAddress(s.FromEmail); e != nil {
		writeError(w, 400, "发件邮箱不正确")
		return
	}
	_, e := a.db.Exec(`UPDATE smtp_settings SET host=?,port=?,username=?,from_email=? WHERE id=1`, s.Host, s.Port, s.Username, s.FromEmail)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, s)
}
func (a *app) receive(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "POST" {
		writeError(w, 405, "仅支持 GET 和 POST")
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/push/")
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if e != nil {
		writeError(w, 413, "请求超过 1MiB")
		return
	}
	h, e := scanHook(a.db.QueryRow(`SELECT id,name,token,enabled,recipient_ids,created_at,updated_at FROM webhooks WHERE token=?`, token))
	if e != nil || !h.Enabled {
		writeError(w, 404, "接口不存在")
		return
	}
	rows, e := a.db.Query(`SELECT email FROM recipients WHERE enabled=TRUE`)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	var to []string
	chosen := map[int64]bool{}
	for _, id := range h.RecipientIDs {
		chosen[id] = true
	}
	for rows.Next() {
		var email string
		rows.Scan(&email)
		if len(chosen) == 0 {
			to = append(to, email)
			continue
		}
		var id int64
		a.db.QueryRow(`SELECT id FROM recipients WHERE email=?`, email).Scan(&id)
		if chosen[id] {
			to = append(to, email)
		}
	}
	rows.Close()
	if len(to) == 0 {
		writeError(w, 409, "没有启用的收件邮箱")
		return
	}
	s, e := a.smtp()
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	if e = sendMail(s, a.smtpPassword, to, h.Name, r, body); e != nil {
		writeError(w, 502, "邮件投递失败")
		return
	}
	writeJSON(w, 202, map[string]any{"status": "accepted", "recipients": len(to)})
}
func sendMail(s smtpSettings, p string, to []string, name string, r *http.Request, b []byte) error {
	if s.Username == "" || p == "" {
		return fmt.Errorf("SMTP credentials missing")
	}
	conn, e := tls.Dial("tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)), &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12})
	if e != nil {
		return e
	}
	defer conn.Close()
	c, e := smtp.NewClient(conn, s.Host)
	if e != nil {
		return e
	}
	defer c.Quit()
	if e = c.Auth(smtp.PlainAuth("", s.Username, p, s.Host)); e != nil {
		return e
	}
	if e = c.Mail(s.FromEmail); e != nil {
		return e
	}
	for _, v := range to {
		if e = c.Rcpt(v); e != nil {
			return e
		}
	}
	d, e := c.Data()
	if e != nil {
		return e
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: Webhook: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nMethod: %s\nURL: %s\nQuery: %s\n\n%s", s.FromEmail, strings.Join(to, ","), name, r.Method, r.URL.String(), r.URL.Query().Encode(), b)
	_, e = d.Write([]byte(msg))
	if x := d.Close(); e == nil {
		e = x
	}
	return e
}
func randomID(n int) (string, error) {
	b := make([]byte, n)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		writeError(w, 400, "无效 JSON")
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, s int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(s)
	json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, s int, m string) {
	writeJSON(w, s, map[string]string{"error": m})
}
func env(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}
func envInt(k string, f int) int {
	v, e := strconv.Atoi(os.Getenv(k))
	if e == nil && v > 0 {
		return v
	}
	return f
}
func envBool(k string, f bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return f
	}
	return v == "1" || strings.EqualFold(v, "true")
}
func loadEnvFile(path string) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return fmt.Errorf("invalid .env line: %q", line)
		}
		key, value = strings.TrimSpace(key), strings.Trim(strings.TrimSpace(value), `"'`)
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, value)
		}
	}
	return nil
}
func logging(n http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.ServeHTTP(w, r) })
}
