(in-package :stalk)

;; (ql:quickload '(:ironclad :usocket :spack :alexandria :bordeaux-threads :cl-leb128))

(defparameter *default-identity-location* `(,"~/.stalk/id_pub" 
                                             ,"~/.stalk/id_priv"))
(defvar *default-identity* (load-identity-from-files (car *default-identity-location*) (cadr *default-identity-location*)))

(defvar *id*)
(defvar *port* 6434)
(defvar *codes*
  `((100 :enc-hello) (101 :dec-hello) (400 :bad-request) (401 :bad-handshake) (500 :crash)))
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
   (cryptosystem
    :accessor cryptosystem
    :initarg :cryptosystem)))


(defmethod register-spack-handler ((conn stalk-connection) (f function))
  )

(defun make-connection (sock peer-identity cryptosystem identity)
  (make-instance 'stalk-connection
                 :host (usocket:get-peer-address sock)
                 :port (usocket:get-peer-port sock)
                 :peer-identity peer-identity
                 :identity identity
                 :cryptosystem cryptosystem
                 :socket sock))

(defun listener (host port connection-handler &key (identity *default-identity*))
  (loop do 
       (let ((socket (usocket:socket-listen host port)))
         (usocket:wait-for-input socket)
         (bt:make-thread
          #'(lambda ()
              (multiple-value-bind (peer-identity cryptosystem)
                  (unwind-protect
                       (handshake (usocket:socket-accept socket) identity)
                    (progn (send-error socket :bad-handshake) (return nil)))
                (when peer-identity
                  (funcall connection-handler
                           (make-connection socket peer-identity cryptosystem identity)))))))))

(defun handshake (sock identity)
  "Attempt to do a handshake, assuming proper formatting coming down
the socket. This entire function throwing an error will throw an error
back at the authenticator"
  (let ((state nil) (curr (spack:parse sock)) (connection (make-instance 'stalk-connection)))
    (cond ((eql (val (car (spack:elements curr))) 100)
           (let* ((enc-buf (val (cadr (spack:elements curr))))
                  (dec-buf (ironclad:decrypt-message (privkey identity) enc-buf :oaep t))
                  (dec-spack (spack:parse dec-buf))
                  (cryptosystem))
             (destructuring-bind
                   (peer-pubkey modulus algo keylen sym-pubkey) (map 'list #'(lambda (x) (spack:val x)) (spack:elements dec-spack))
               (case algo
                 ("curve25519" (multiple-value-bind (conn-privkey conn-pubkey)
                                   (ironclad:generate-key-pair :curve25519 :num-bits keylen)
                                 (ironclad:encrypt-message
                                  (ironclad:make-public-key :rsa :e peer-pubkey :n modulus)
                                  (setf cipher (ironclad:make-cipher :rsa :key (ironclad:diffie-hellman conn-privkey sym-pubkey)))
                                  (destructuring-bind (_x raw-peer-pubkey) (ironclad:destructure-public-key conn-pubkey)
                                    (declare (ignore _x))
                                    (loop for i across
                                         (spack:out
                                          (spack:make-and-push
                                           ((ironclad:encrypt-message (ironclad:make-public-key :rsa :e peer-pubkey :n modulus)
                                                                      (spack:out
                                                                       (spack:make-and-push
                                                                        (conn-pubkey :byte-array)
                                                                        ((length conn-pubkey) :integer))))
                                            :byte-array)))
                                       do (write-byte i (usocket:socket-stream sock)))
                                    (force-output (socket-stream sock))
                                   ;; Then, wait for acknowledgement
                                   ;; of handshake, then we're done
                                   ;; and can hand off the
                                   ;; implementation
                                    ))))
                 (t (error "unsupported algo"))))))
          ((eql (val (car (spack:elements))) 101)
           ())
          (t (error "bad hello")))))

(defun send-error (sock error-keyword)
  (let ((sp (make-instance 'spack)))
    (spack:spush (get-stat-code error-keyword) :integer sp)
    (loop for i across (spack:out sp) do
         (write-byte i sock))
    (force-output sock)
    (usocket:socket-close sock)))

(defun connect (host port &optional identity &key handler))

(defun send (spack connection))

(defun flush (connection))

