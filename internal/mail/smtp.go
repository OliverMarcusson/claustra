package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	mailaddr "net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/olivermarcusson/claustra/internal/config"
)

type Sender interface {
	Send(context.Context, string, string, string) error
}

type SMTP struct{ Config config.SMTP }

func (s SMTP) Send(ctx context.Context, to, subject, body string) error {
	if s.Config.Host == "" || s.Config.From == "" {
		return errors.New("SMTP is not configured")
	}
	from, err := mailaddr.ParseAddress(s.Config.From)
	if err != nil {
		return fmt.Errorf("invalid SMTP from address: %w", err)
	}
	recipient, err := mailaddr.ParseAddress(to)
	if err != nil {
		return errors.New("invalid recipient")
	}
	addr := net.JoinHostPort(s.Config.Host, fmt.Sprint(s.Config.Port))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	c, err := smtp.NewClient(conn, s.Config.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if s.Config.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("SMTP server does not offer STARTTLS")
		}
		if err = c.StartTLS(&tls.Config{ServerName: s.Config.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if s.Config.Username != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("SMTP server does not offer AUTH")
		}
		if err = c.Auth(smtp.PlainAuth("", s.Config.Username, s.Config.Password, s.Config.Host)); err != nil {
			return err
		}
	}
	if err = c.Mail(from.Address); err != nil {
		return err
	}
	if err = c.Rcpt(recipient.Address); err != nil {
		return err
	}
	writer, err := c.Data()
	if err != nil {
		return err
	}
	message := "From: " + from.String() + "\r\nTo: " + recipient.String() + "\r\nSubject: " + strings.ReplaceAll(strings.ReplaceAll(subject, "\r", ""), "\n", "") + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + strings.ReplaceAll(body, "\n", "\r\n")
	if _, err = writer.Write([]byte(message)); err != nil {
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	return c.Quit()
}
