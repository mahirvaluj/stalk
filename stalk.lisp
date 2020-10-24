(in-package :stalk)

;; (ql:quickload '(:ironclad :usocket :spack :alexandria :bordeaux-threads :cl-leb128))

(defparameter *default-identity-location* `(,"~/.stalk/id_pub" 
                                             ,"~/.stalk/id_priv"))
(defvar *default-identity* (load-identity-from-files (car *default-identity-location*) (cadr *default-identity-location*)))

(defvar *id*)

(defvar *connection-threads* nil)

(defvar *codes*
  `((100 :handshake-hello) (101 :handshake-ack) (102 :handshake-ack-fin)
    (400 :bad-request) (401 :handshake-auth-fail) (500 :crash)))
(defun get-stat-code (keyword)
  (car (find-if #'(lambda (i) (eql keyword (cadr i))) *codes*)))
(defun get-keyword (stat-code)
  (cadr (find-if #'(lambda (i) (eql stat-code (car i))) *codes*)))

(defclass stalk-connection()
  ((host
    :accessor host
    :initarg :host)
   (port
    :accessor port
    :initarg :port)
   (peer-identity
    :accessor peer-identity
    :initarg :peer-identity)
   (identity
    :accessor identity
    :initarg :identity)
   (socket
    :reader socket
    :initarg :socket)
   (spack-handler
    :reader spack-handler
    :initarg :spack-handler)
   (cipher
    :accessor cipher
    :initarg :cipher)))

(defmethod register-spack-handler ((conn stalk-connection) (f function))
  )

(defun make-connection (sock peer-identity cipher identity)
  (make-instance 'stalk-connection
                 :host (usocket:get-peer-address sock)
                 :port (usocket:get-peer-port sock)
                 :peer-identity peer-identity
                 :identity identity
                 :cipher cipher
                 :socket sock))

(defun listener (host port connection-handler &key (identity *default-identity*))
  (let ((socket (usocket:socket-listen host port :element-type '(unsigned-byte 8))))
    (loop do 
         (let ((sock (usocket:socket-accept socket)))
           (format t "~A~%" sock)
           (let ((connection (server-handshake sock identity)))
             (return-from listener connection)
             ;; (push (bt:make-thread

             ;;            (when (peer-identity connection)
             ;;              (funcall connection-handler connection))))
             ;;       *connection-threads*)
             )))))

(defun server-handshake (sock identity)
  "Attempt to do a handshake, assuming proper formatting coming down
the socket. This entire function throwing an error will throw an error
back at the authenticator"
  (let ((client-id) (cipher) (sym-server-pubkey) (sym-server-privkey))
    (spack:destructuring-elements (code client-id-pubkey client-id-modulus sym-peer-pubkey-raw init-vec signature)
        (spack:parse (usocket:socket-stream sock))
      (assert (= code 100))
      (setf client-id (make-instance 'stalk-identity
                                     :pubkey (ironclad:make-public-key :rsa :e client-id-pubkey :n client-id-modulus)))
      (unless (ironclad:verify-signature (pubkey client-id) (to-simple-bytearray sym-peer-pubkey-raw) (to-simple-bytearray signature))
        (error "signature of public key failed"))
      (multiple-value-setq (sym-server-privkey sym-server-pubkey)
        (ironclad:generate-key-pair :curve25519 :compatible-with-key
                                    (ironclad:make-public-key :curve25519 :y sym-peer-pubkey-raw)))
      (setf cipher (ironclad:make-cipher
                    :aes :mode :ctr :initialization-vector (to-simple-bytearray init-vec)
                    :key (ironclad:diffie-hellman sym-server-privkey
                                                  (ironclad:make-public-key :curve25519 :y (to-simple-bytearray sym-peer-pubkey-raw))))))
    (format t "Got hello from client~%")
    (loop for i across (spack:out (spack:make-and-push
                                   (101 :integer)
                                   ((cadr (ironclad:destructure-public-key sym-server-pubkey))
                                    :byte-array)
                                   ((ironclad:sign-message (privkey identity)
                                                           (cadr (ironclad:destructure-public-key sym-server-pubkey)))
                                    :byte-array)))
       do
         (write-byte i (usocket:socket-stream sock)))
    (force-output (usocket:socket-stream sock))
    (usocket:wait-for-input sock)
    (spack:destructuring-elements (msg) (spack:parse (usocket:socket-stream sock))
      (setf msg (to-simple-bytearray msg))
      (let ((plaintext (make-array (length msg) :element-type '(unsigned-byte 8))))
        (multiple-value-bind (a b) (ironclad:decrypt-in-place cipher msg) (format t "A ~D  B ~D~%" a b))
        (return-from server-handshake msg)
        (spack:destructuring-elements (code) (spack:parse plaintext)
          (unless (= code 102) (error "bad code in confirmation"))
          (make-instance 'stalk-connection
                         :cipher cipher
                         :socket sock
                         :identity identity
                         :peer-identity client-id
                         :port (usocket:get-peer-port sock)
                         :host (usocket:get-peer-name sock)))))))

(defun to-simple-bytearray (a)
  (let ((b (make-array (length a) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below (length a) do (setf (aref b i) (aref a i)))
    b))

(defun send-error (sock error-keyword)
  (let ((sp (make-instance 'spack)))
    (spack:spush (get-stat-code error-keyword) :integer sp)
    (loop for i across (spack:out sp) do
         (write-byte i sock))
    (force-output sock)
    (usocket:socket-close sock)))

(defun connect (host port &key (identity *default-identity*) server-identity)
  "If server-identity is nil, then do unauthenticated handshake"
  (let ((sock (usocket:socket-connect host port :element-type '(unsigned-byte 8))))
    (when (null sock) (error "failed to connect to server"))
    (let ((connection (client-handshake sock identity server-identity)))
      connection)))

(defun client-handshake (sock identity server-identity)
  (let ((sym-client-privkey) (sym-client-pubkey) (j 0) (cipher)
        (init-vec (make-array 16 :element-type '(unsigned-byte 8)
                              :initial-contents (loop for i from 0 below 16 collect (random 256)))))
    (loop for i across
         (destructuring-bind (_e client-pubkey _n modulus) (ironclad:destructure-public-key (pubkey identity))
           (declare (ignore _e _n))
           (multiple-value-setq (sym-client-privkey sym-client-pubkey) (ironclad:generate-key-pair :curve25519 :num-bits 256))
           (spack:out (spack:make-and-push
                       (100 :integer)
                       (client-pubkey :integer)
                       (modulus :integer)
                       ((cadr (ironclad:destructure-public-key sym-client-pubkey)) :byte-array)
                       (init-vec :byte-array)
                       ((ironclad:sign-message (privkey identity)
                                               (cadr (ironclad:destructure-public-key sym-client-pubkey)))
                        :byte-array))))
       do (progn (write-byte i (usocket:socket-stream sock)) (setf j (+ 1 j))
                 ;;(format t "~D " i)
                 ))
    (force-output (usocket:socket-stream sock))
    (usocket:wait-for-input sock)
    (spack:destructuring-elements (code sym-server-pubkey-raw signature)
        (spack:parse (usocket:socket-stream sock))
      (assert (= code 101))
      (unless (ironclad:verify-signature (pubkey server-identity) sym-server-pubkey-raw signature)
        (error "FAIL: Server identity check failed. Double check the public key."))
      (setf cipher (ironclad:make-cipher :aes :mode :ctr :initialization-vector init-vec
                                         :key (ironclad:diffie-hellman
                                               sym-client-privkey
                                               (ironclad:make-public-key :curve25519
                                                                         :y sym-server-pubkey-raw)))))
    (let* ((buf (spack:out (spack:make-and-push (102 :integer))))
           (ciphertext (make-array (* 128 (ceiling (/ (length buf) 128))) :element-type '(unsigned-byte 8))))
      (ironclad:encrypt-in-place cipher buf)
      (let ((outbuf (spack:out (spack:make-and-push (ciphertext :byte-array)))))
        (loop for i across outbuf
           do
             (write-byte i (usocket:socket-stream sock)))
        (force-output (usocket:socket-stream sock))
        (return-from client-handshake (list buf outbuf ciphertext)))
      (make-instance 'stalk-connection
                     :cipher cipher
                     :socket sock
                     :identity identity
                     :peer-identity server-identity
                     :port (usocket:get-peer-port sock)
                     :host (usocket:get-peer-name sock)))))


(defun send (spack connection))

(defun flush (connection))

