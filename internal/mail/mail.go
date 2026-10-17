// Package mail submits transactional mail to a trusted internal relay. It never authenticates.
package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	stdmail "net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type Settings struct {
	Enabled   bool   `json:"enabled"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	FromName  string `json:"from_name"`
	FromEmail string `json:"from_email"`
	StartTLS  bool   `json:"starttls"`
}

func Address(s string) bool {
	a, e := stdmail.ParseAddress(s)
	return e == nil && a.Address == s && !strings.ContainsAny(s, "\r\n")
}
func (s Settings) Validate() error {
	if strings.ContainsAny(s.FromName, "\r\n") || len(s.FromName) > 200 {
		return errors.New("invalid sender name")
	}
	if !s.Enabled {
		return nil
	}
	if s.Host == "" || strings.ContainsAny(s.Host, " /\r\n\t") || s.Port < 1 || s.Port > 65535 || !Address(s.FromEmail) {
		return errors.New("invalid SMTP settings")
	}
	return nil
}

type Message struct{ To, Subject, TextBody string }
type Mailer interface {
	Send(context.Context, Message) error
}
type SMTPMailer struct{ Settings Settings }

func (m SMTPMailer) Send(ctx context.Context, msg Message) error {
	s := m.Settings
	if err := s.Validate(); err != nil {
		return err
	}
	if !s.Enabled {
		return errors.New("email disabled")
	}
	if !Address(msg.To) || strings.ContainsAny(msg.Subject, "\r\n") || len(msg.TextBody) > 256*1024 {
		return errors.New("invalid message")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return err
	}
	defer c.Close()
	if s.StartTLS {
		if err = c.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if err = c.Mail(s.FromEmail); err != nil {
		return err
	}
	if err = c.Rcpt(msg.To); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	from := (&stdmail.Address{Name: s.FromName, Address: s.FromEmail}).String()
	body := strings.ReplaceAll(strings.ReplaceAll(msg.TextBody, "\r\n", "\n"), "\n", "\r\n")
	_, err = fmt.Fprintf(w, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nAuto-Submitted: auto-generated\r\nX-Auto-Response-Suppress: All\r\n\r\n%s\r\n", from, msg.To, mime.QEncoding.Encode("utf-8", msg.Subject), time.Now().Format(time.RFC1123Z), body)
	if err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
