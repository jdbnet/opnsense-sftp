package sftpsrv

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/keys"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/store"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

type Server struct {
	listen     string
	backupsDir string
	db         *store.DB
	keys       *keys.Manager
	listener   net.Listener
	wg         sync.WaitGroup
	done       chan struct{}
}

func New(listen, backupsDir string, db *store.DB, keysMgr *keys.Manager) *Server {
	return &Server{
		listen:     listen,
		backupsDir: backupsDir,
		db:         db,
		keys:       keysMgr,
		done:       make(chan struct{}),
	}
}

func (s *Server) Start() error {
	if err := os.MkdirAll(s.backupsDir, 0o755); err != nil {
		return err
	}
	hostKey, err := s.keys.HostKey()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	s.listener = ln
	slog.Info("sftp listening", "addr", s.listen)
	s.wg.Add(1)
	go s.acceptLoop(hostKey)
	return nil
}

func (s *Server) Stop() {
	close(s.done)
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.wg.Wait()
}

func (s *Server) acceptLoop(hostKey gossh.Signer) {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				slog.Error("sftp accept", "err", err)
				continue
			}
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c, hostKey)
		}(conn)
	}
}

func (s *Server) handleConn(conn net.Conn, hostKey gossh.Signer) {
	defer conn.Close()
	var currentInstance *store.Instance
	sshConfig := &gossh.ServerConfig{
		PublicKeyCallback: func(meta gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			inst, err := s.db.GetInstanceByIdentifier(meta.User())
			if err != nil {
				return nil, fmt.Errorf("permission denied")
			}
			sshKey, err := s.db.GetSSHKeyByKeyID(inst.SSHKeyID)
			if err != nil {
				return nil, fmt.Errorf("permission denied")
			}
			stored, err := keys.ParseAuthorizedKey(sshKey.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("permission denied")
			}
			if string(key.Marshal()) != string(stored.Marshal()) {
				return nil, fmt.Errorf("permission denied")
			}
			currentInstance = inst
			slog.Info("sftp auth ok", "user", meta.User())
			return nil, nil
		},
	}
	sshConfig.AddHostKey(hostKey)
	transport, chans, reqs, err := gossh.NewServerConn(conn, sshConfig)
	if err != nil {
		slog.Debug("sftp handshake", "err", err)
		return
	}
	defer transport.Close()
	go gossh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(gossh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		if currentInstance == nil {
			_ = channel.Close()
			continue
		}
		inst := currentInstance
		go func(ch gossh.Channel, in <-chan *gossh.Request) {
			defer ch.Close()
			for req := range in {
				if req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
					_ = req.Reply(true, nil)
					h := &handler{server: s, instance: inst}
					server := sftp.NewRequestServer(ch, sftp.Handlers{
						FileGet:  h,
						FilePut:  h,
						FileCmd:  h,
						FileList: h,
					})
					if err := server.Serve(); err != nil && err != io.EOF {
						slog.Debug("sftp serve", "err", err)
					}
					_ = server.Close()
					return
				}
				_ = req.Reply(false, nil)
			}
		}(channel, requests)
	}
}

type handler struct {
	server   *Server
	instance *store.Instance
}

func (h *handler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	path, err := h.canonicalize(r.Filepath)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (h *handler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	path, err := h.canonicalize(r.Filepath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	return &recordingWriter{
		File:   f,
		path:   path,
		server: h.server,
		inst:   h.instance,
	}, nil
}

func (h *handler) Filecmd(r *sftp.Request) error {
	path, err := h.canonicalize(r.Filepath)
	if err != nil {
		return err
	}
	switch r.Method {
	case "Remove":
		return os.Remove(path)
	case "Mkdir":
		return os.MkdirAll(path, 0o755)
	case "Rmdir":
		return os.Remove(path)
	case "Rename":
		dst, err := h.canonicalize(r.Target)
		if err != nil {
			return err
		}
		return os.Rename(path, dst)
	case "Setstat":
		return nil
	default:
		return os.ErrInvalid
	}
}

func (h *handler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	if r.Method == "Stat" || r.Method == "Lstat" {
		return h.statPath(r)
	}
	path, err := h.canonicalize(r.Filepath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var infos []os.FileInfo
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		infos = append(infos, info)
	}
	return listerAt(infos), nil
}

func (h *handler) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	return h.statPath(r)
}

func (h *handler) RealPath(p string) (string, error) {
	path, err := h.canonicalize(p)
	if err != nil {
		return "", err
	}
	instanceDir, err := h.instanceDir()
	if err != nil {
		return "", err
	}
	if path == instanceDir {
		if err := os.MkdirAll(instanceDir, 0o755); err != nil {
			return "", err
		}
	} else if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return h.clientPath(p), nil
}

func (h *handler) statPath(r *sftp.Request) (sftp.ListerAt, error) {
	path, err := h.canonicalize(r.Filepath)
	if err != nil {
		return nil, err
	}
	instanceDir, err := h.instanceDir()
	if err != nil {
		return nil, err
	}
	if path == instanceDir {
		if err := os.MkdirAll(instanceDir, 0o755); err != nil {
			return nil, err
		}
	}
	var info os.FileInfo
	if r.Method == "Lstat" {
		info, err = os.Lstat(path)
	} else {
		info, err = os.Stat(path)
	}
	if err != nil {
		return nil, err
	}
	return listerAt{info}, nil
}

func (h *handler) instanceDir() (string, error) {
	return filepath.Abs(filepath.Join(h.server.backupsDir, h.instance.Identifier))
}

func (h *handler) clientPath(requestPath string) string {
	p := strings.Trim(strings.TrimPrefix(requestPath, "/"), "/")
	inst := h.instance.Identifier
	if p == "" || p == inst {
		return "/" + inst
	}
	if strings.HasPrefix(p, inst+"/") {
		return "/" + p
	}
	return "/" + inst + "/" + p
}

type listerAt []os.FileInfo

func (l listerAt) ListAt(f []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(f, l[offset:])
	if int(offset)+n >= len(l) {
		return n, io.EOF
	}
	return n, nil
}

type recordingWriter struct {
	*os.File
	path   string
	server *Server
	inst   *store.Instance
}

func (w *recordingWriter) Close() error {
	err := w.File.Close()
	info, statErr := os.Stat(w.path)
	var size int64
	if statErr == nil {
		size = info.Size()
	}
	filename := filepath.Base(w.path)
	if recErr := w.server.db.RecordBackup(w.inst.ID, filename, w.path, size); recErr != nil {
		slog.Error("record backup", "err", recErr)
	} else {
		slog.Info("backup recorded", "file", filename, "instance", w.inst.Identifier, "size", size)
	}
	return err
}

func (h *handler) canonicalize(path string) (string, error) {
	path = strings.TrimPrefix(path, "/")
	inst := h.instance
	if inst == nil {
		return "", os.ErrPermission
	}
	if path == inst.Identifier {
		path = ""
	}
	prefix := inst.Identifier + "/"
	if strings.HasPrefix(path, prefix) {
		path = strings.TrimPrefix(path, prefix)
	}
	instanceDir, err := filepath.Abs(filepath.Join(h.server.backupsDir, inst.Identifier))
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(instanceDir, 0o755); err != nil {
		return "", err
	}
	var fullPath string
	if path == "" {
		fullPath = instanceDir
	} else {
		fullPath = filepath.Join(instanceDir, path)
	}
	fullPath, err = filepath.Abs(fullPath)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(fullPath, instanceDir+string(os.PathSeparator)) && fullPath != instanceDir {
		return "", os.ErrPermission
	}
	return fullPath, nil
}